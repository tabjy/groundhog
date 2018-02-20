package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"crypto/rsa"

	"github.com/tabjy/groundhog/common"
	"github.com/tabjy/groundhog/common/crypto"
	"github.com/tabjy/groundhog/common/protocol"
	"github.com/tabjy/yagl"
)

// Client implements common.Dialer support all exported fields of net.Dialer.
// Zero-value for Client is a valid configuration
type Client struct {
	net.Dialer

	Host string // Groundhog server hostname/IP to connect to. If nil, connect to localhost would be attempted
	Port uint16 // a opening port of a Groundhog server. If nil, 1081 would be attempted

	RSAKey       *rsa.PrivateKey // 4096-bit RSA private key for encryption. If nil, a key pair would be generated
	CipherMethod byte            // desired cipher method. If nil, plaintext would be used. (NOT RECOMMENDED!)

	// Logger specifies an optional logger
	// If nil, logging goes to os.Stderr via a yagl standard logger.
	Logger yagl.Logger
}

func (c *Client) Prepare() error {
	if c.Port == 0 {
		c.Port = 1081
	}

	if c.Logger == nil {
		c.Logger = yagl.StdLogger()
	}

	if c.RSAKey == nil {
		if keyPair, err := rsa.GenerateKey(rand.Reader, 4096); err != nil {
			c.Logger.Errorf("failed to generate RSA key pair: %s", err)
			return err
		} else {
			c.RSAKey = keyPair
		}
	}

	return nil
}

func (c *Client) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := c.Prepare(); err != nil {
		return nil, err
	}

	addr, err := protocol.NewAddrFromString(address)
	if err != nil {
		return nil, err
	}

	p := &proxyConn{
		host:      c.Host,
		port:      c.Port,
		cipher:    c.CipherMethod,
		clientKey: c.RSAKey,
		dst:       addr,
		dialer:    &c.Dialer,
		logger:    c.Logger,
	}

	target, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	return target, nil
}

type proxyConn struct {
	host string
	port uint16

	cipher byte

	clientKey  *rsa.PrivateKey
	serverKey  *rsa.PublicKey
	sessionKey []byte

	dst *protocol.Addr

	dialer common.Dialer
	logger yagl.Logger

	target net.Conn
	req    io.Writer
	res    io.Reader
}

func (c *proxyConn) connect(ctx context.Context) (net.Conn, error) {
	if target, err := c.dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.host, strconv.Itoa(int(c.port)))); err != nil {
		return nil, err
	} else {
		c.target = target
	}

	// watchdog to close connections if context cancelled
	go func() {
		<-ctx.Done() // this doesn't block forever, Server call cancel after ServeTCP returns

		if c.target != nil {
			c.target.Close()
		}
	}()

	c.target.(*net.TCPConn).SetKeepAlive(true)
	c.req = c.target
	c.res = bufio.NewReader(c.target)

	if err := c.writePubKey(); err != nil {
		c.logger.Errorf("failed to write public key: %s", err.Error())
		return nil, err
	}

	if err := c.readPubKey(); err != nil {
		c.logger.Errorf("failed to read public key: %s", err.Error())
		return nil, err
	}

	if err := c.sendRequest(); err != nil {
		c.logger.Errorf("failed to send request: %s", err.Error())
		return nil, err
	}

	if err := c.readReply(); err != nil {
		c.logger.Errorf("failed to read reply: %s", err.Error())
		return nil, err
	}

	var cipherTarget net.Conn
	ed := crypto.StreamEncryptDecrypter{
		EncryptKey: c.sessionKey,
		DecryptKey: c.sessionKey,
	}

	switch c.cipher {
	case protocol.CipherPlaintext:
		cipherTarget = c.target
	case protocol.CipherAES128OFB, protocol.CipherAES192OFB, protocol.CipherAES256OFB:
		ed.StreamEncrypter = cipher.NewOFB
		ed.StreamDecrypter = cipher.NewOFB

	case protocol.CipherAES128CTR, protocol.CipherAES192CTR, protocol.CipherAES256CTR:
		ed.StreamEncrypter = cipher.NewCTR
		ed.StreamDecrypter = cipher.NewCTR

	case protocol.CipherAES128CFB, protocol.CipherAES192CFB, protocol.CipherAES256CFB:
		ed.StreamEncrypter = cipher.NewCFBEncrypter
		ed.StreamDecrypter = cipher.NewCFBDecrypter

	default:
		err := fmt.Errorf("unsupported cipher method %#x", c.cipher)
		c.logger.Error(err)
		return nil, err
	}

	if c.cipher != protocol.CipherPlaintext {
		encryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
			err = fmt.Errorf("failed to generate encryption IV: %s", err)
			c.logger.Error(err)
			return nil, err
		}
		if _, err := c.req.Write(encryptIV); err != nil {
			err = fmt.Errorf("failed to write encryption IV: %s", err)
			c.logger.Error(err)
			return nil, err
		}

		decryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadAtLeast(c.res, decryptIV, aes.BlockSize); err != nil {
			err = fmt.Errorf("failed to read decryption IV: %s", err)
			c.logger.Error(err)
			return nil, err
		}

		ed.EncryptIV = encryptIV
		ed.DecryptIV = decryptIV

		var err error
		cipherTarget, err = ed.Plaintext(c.target)
		if err != nil {
			err = fmt.Errorf("failed to create cipher for target connection: %s", err)
			c.logger.Error(err)
			return nil, err
		}
	}

	return cipherTarget, nil
}

func (c *proxyConn) writePubKey() error {
	pub, err := x509.MarshalPKIXPublicKey(&c.clientKey.PublicKey)
	if err != nil {
		return err
	}

	if _, err := c.req.Write(pub); err != nil {
		return err
	}

	return nil
}

func (c *proxyConn) readPubKey() error {
	buf := make([]byte, 550) // 550 bytes: length of a PKIX formatted 4096-bit RSA public key

	if _, err := io.ReadAtLeast(c.res, buf, 550); err != nil {
		return err
	}

	pub, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return err
	}

	if rsaPub, ok := pub.(*rsa.PublicKey); !ok {
		return errors.New("invalid RSA public key")
	} else {
		c.serverKey = rsaPub
		return nil
	}
}

func (c *proxyConn) sendRequest() error {
	// max payload size of RSA 4096 OAEP with SHA256: 446
	// 4096 / 8 - 2 * 256 / 8 - 2 = 446
	// max hostname length in POSIX: 255
	addrBuf, err := c.dst.Marshal()
	if err != nil {
		return err
	}

	plaintext := append(addrBuf, c.cipher)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.serverKey, plaintext, nil)
	if err != nil {
		return err
	}

	if _, err := c.req.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

func (c *proxyConn) readReply() error {
	ciphertext := make([]byte, 512)
	if _, err := io.ReadAtLeast(c.res, ciphertext, 512); err != nil {
		return err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, c.clientKey, ciphertext, nil)
	if err != nil {
		return err
	}

	resRd := bytes.NewReader(plaintext)

	rep, err := resRd.ReadByte()
	if err != nil {
		return err
	}

	if err := protocol.RepToErr(rep); err != nil {
		return err
	}

	// read AES session key
	sessionKeyLen := 0
	switch c.cipher {
	case protocol.CipherAES128CFB, protocol.CipherAES128CTR, protocol.CipherAES128OFB:
		sessionKeyLen = 16
	case protocol.CipherAES192CFB, protocol.CipherAES192CTR, protocol.CipherAES192OFB:
		sessionKeyLen = 24
	case protocol.CipherAES256CFB, protocol.CipherAES256CTR, protocol.CipherAES256OFB:
		sessionKeyLen = 32
	case protocol.CipherPlaintext:
		return nil
	default:
		return fmt.Errorf("unsupported cihper: %xs#", c.cipher)
	}

	c.sessionKey = make([]byte, sessionKeyLen)
	if _, err := io.ReadAtLeast(resRd, c.sessionKey, sessionKeyLen); err != nil {
		return err
	}

	return nil
}
