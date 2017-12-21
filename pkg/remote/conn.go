package remote

import (
	"net"
	"io"
	"crypto/x509"
	"crypto/rsa"
	"fmt"
	"crypto/sha256"
	"bytes"
	"crypto/rand"

	"github.com/tabjy/groundhog/pkg/util"
	"github.com/tabjy/groundhog/pkg/crypto"
)

type proxyConn struct {
	conn   net.Conn
	target net.Conn

	config       *Config
	destAddr     *util.Addr
	cipherMethod byte
	sessionKey   []byte
	clientPubKey *rsa.PublicKey
}

func newProxyConn(conn net.Conn, config *Config) *proxyConn {
	return &proxyConn{
		conn:   conn,
		config: config,
	}
}

func (c *proxyConn) serve() error {
	defer c.conn.Close()

	var err error

	if err := c.readPubKey(); err != nil {
		return err
	}

	if err := c.writePubKey(); err != nil {
		return err
	}

	if err := c.readReq(); err != nil {
		return err
	}

	rep := util.REP_SUCCEEDED
	target, netErr := net.Dial("tcp", c.destAddr.String())
	if netErr != nil {
		rep = util.ConnErrToRep(err)
		err = netErr
	} else {
		c.target = target
		defer target.Close()
	}

	if err := c.writeRes(rep); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	// TODO: more cipher implementation
	var plainSide, cipherSide net.Conn
	errCh := make(chan error)

	switch c.cipherMethod {
	case util.CIPHER_PLAINTEXT:
		go util.IOCopy(target, c.conn, errCh)
		go util.IOCopy(c.conn, target, errCh)

		// Wait
		for i := 0; i < 2; i++ {
			e := <-errCh
			if e != nil {
				// return from this function closes target (and conn).
				return e
			}
		}
	case util.CIPHER_AES_128_OFB, util.CIPHER_AES_192_OFB, util.CIPHER_AES_256_OFB:
		plainSide, cipherSide, err = crypto.CreateAESOFBPipe(c.sessionKey, errCh)
	case util.CIPHER_AES_128_CTR, util.CIPHER_AES_192_CTR, util.CIPHER_AES_256_CTR:
		plainSide, cipherSide, err = crypto.CreateAESCTRPipe(c.sessionKey, errCh)
	case util.CIPHER_AES_128_CFB, util.CIPHER_AES_192_CFB, util.CIPHER_AES_256_CFB:
		plainSide, cipherSide, err = crypto.CreateAESOFBPipe(c.sessionKey, errCh)
	default:
		return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.cipherMethod)
	}

	if err != nil {
		return err
	}

	go util.IOCopy(target, plainSide, errCh)
	go util.IOCopy(plainSide, target, errCh)

	go util.IOCopy(cipherSide, c.conn, errCh)
	go util.IOCopy(c.conn, cipherSide, errCh)

	// shut down connection on error
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *proxyConn) readPubKey() error {
	pubBuf := make([]byte, 550)
	_, err := io.ReadAtLeast(c.conn, pubBuf, 550)
	if err != nil {
		return err
	}

	pub, err := x509.ParsePKIXPublicKey(pubBuf)
	if err != nil {
		return err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	// fmt.Println("remote pub got:", rsaPub)
	if !ok {
		return fmt.Errorf(util.ERR_TPL_INVALID_RSA_PUB_KEY)
	}
	c.clientPubKey = rsaPub

	return nil
}

func (c *proxyConn) writePubKey() error {
	// RSA key-pairs are guaranteed to be 4096 bit
	// TODO: investigate: is encoded public key always 550 byte long
	// fmt.Println("remote pub send:", &c.config.PrivateKey.PublicKey)
	pub, err := x509.MarshalPKIXPublicKey(&c.config.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(pub); err != nil {
		return err
	}

	return nil
}

func (c *proxyConn) readReq() error {
	ciphertext := make([]byte, 512)
	if _, err := io.ReadAtLeast(c.conn, ciphertext, 512); err != nil {
		return err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, c.config.PrivateKey, ciphertext, nil)
	if err != nil {
		return err
	}

	reqReader := bytes.NewReader(plaintext)

	addr, err := util.NewAddr().Parse(reqReader)
	if err != nil {
		return err
	}
	c.destAddr = addr

	cipherMethod, err := reqReader.ReadByte()
	if err != nil {
		return err
	}
	c.cipherMethod = cipherMethod

	for i, v := range c.config.SupportedCipherMethods {
		if c.cipherMethod == v {
			break
		} else if i == len(c.config.SupportedCipherMethods) - 1 {
			return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.cipherMethod)
		}
	}

	return nil
}

func (c *proxyConn) writeRes(rep byte) error {
	plaintext := []byte{0x00}

	if rep != util.REP_SUCCEEDED {
		plaintext[0] = rep
	} else {
		sessionKeyLen := 0
		switch c.cipherMethod {
		case util.CIPHER_AES_128_CFB, util.CIPHER_AES_128_CTR, util.CIPHER_AES_128_OFB:
			sessionKeyLen = 16
		case util.CIPHER_AES_192_CFB, util.CIPHER_AES_192_CTR, util.CIPHER_AES_192_OFB:
			sessionKeyLen = 24
		case util.CIPHER_AES_256_CFB, util.CIPHER_AES_256_CTR, util.CIPHER_AES_256_OFB:
			sessionKeyLen = 32
		case util.CIPHER_PLAINTEXT:
			sessionKeyLen = 0
		default:
			return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.cipherMethod)
		}

		if sessionKeyLen != 0 {
			c.sessionKey = make([]byte, sessionKeyLen)

			if _, err := io.ReadFull(rand.Reader, c.sessionKey); err != nil {
				return err
			}

			plaintext = append(plaintext, c.sessionKey...)
		}

	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.clientPubKey, plaintext, nil)
	if err != nil {
		return err
	}

	c.conn.Write(ciphertext)

	return nil
}
