package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/tabjy/groundhog/common"
	"github.com/tabjy/groundhog/common/crypto"
	"github.com/tabjy/groundhog/common/protocol"
	"github.com/tabjy/groundhog/common/tcp"
	"github.com/tabjy/groundhog/common/util"
	"github.com/tabjy/yagl"
)

// Config defines optional configurations for a Groundhog server. The zero value
// for Config is a valid configuration.
type Config struct {
	Host string // IP address or hostname to listen on. Leave empty for an unspecified address.
	Port uint16 // Port to listen on. A port number is automatically chosen if left empty or 0.

	RSAKey        *rsa.PrivateKey // 4096-bit RSA private key for encryption. If nil, a key pair would be generated.
	CipherMethods []byte          // Acceptable methods. If nil, all implemented methods would be accepted.

	Dialer common.Dialer // Dialer implementation. If nil, net.Dialer would be used.

	// Logger specifies an optional logger
	// If nil, logging goes to os.Stderr via a yagl standard logger.
	Logger yagl.Logger
}

// NewServer takes a Groundhog Config and return a tcp.Server. The returned server
// has to be manually started by calling srv.Listen and srv.Server (or just
// srv.ListenAndServer).
func NewServer(config *Config) (*tcp.Server, error) {
	var logger yagl.Logger
	if config.Logger != nil {
		logger = config.Logger
	} else {
		logger = yagl.StdLogger()
	}

	var dialer common.Dialer
	if config.Dialer != nil {
		dialer = config.Dialer
	} else {
		dialer = &net.Dialer{}
	}

	var keyPair *rsa.PrivateKey
	if config.RSAKey != nil {
		keyPair = config.RSAKey
	} else {
		var err error
		keyPair, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
	}

	var methods []byte
	if config.CipherMethods == nil || len(config.CipherMethods) == 0 {
		methods = []byte{
			protocol.CipherPlaintext,
			protocol.CipherAES128CFB,
			protocol.CipherAES192CFB,
			protocol.CipherAES256CFB,
			protocol.CipherAES128CTR,
			protocol.CipherAES192CTR,
			protocol.CipherAES256CTR,
			protocol.CipherAES128OFB,
			protocol.CipherAES192OFB,
			protocol.CipherAES256OFB,
		}
	} else {
		methods = config.CipherMethods
	}

	return &tcp.Server{
		Host: config.Host,
		Port: config.Port,
		Handler: &handler{
			dialer:        dialer,
			logger:        logger,
			rsaKey:        keyPair,
			cipherMethods: methods,
		},
		Logger: logger,
	}, nil
}

type handler struct {
	dialer        common.Dialer
	logger        yagl.Logger
	rsaKey        *rsa.PrivateKey
	cipherMethods []byte
}

func (h *handler) ServeTCP(ctx context.Context, conn net.Conn) {
	g := gndhog{
		dialer:            h.dialer,
		logger:            h.logger,
		serverKey:         h.rsaKey,
		acceptableCiphers: h.cipherMethods,
	}

	g.init(ctx, conn)
}

type gndhog struct {
	dialer common.Dialer
	logger yagl.Logger

	acceptableCiphers []byte
	clientCipher      byte

	client net.Conn
	target net.Conn

	req io.Reader
	res io.Writer

	serverKey  *rsa.PrivateKey
	clientKey  *rsa.PublicKey
	sessionKey []byte

	dst   *protocol.Addr
	src   *protocol.Addr
	local *protocol.Addr
}

func (g *gndhog) init(ctx context.Context, conn net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// watchdog to close connections if context cancelled
	go func() {
		<-ctx.Done() // this doesn't block forever, Server call cancel after ServeTCP returns

		if g.client != nil {
			g.client.Close()
		}

		if g.target != nil {
			g.target.Close()
		}
	}()

	conn.(*net.TCPConn).SetKeepAlive(true)
	g.logger.Tracef("new connection from %v, now passed to Groundhog server", conn.RemoteAddr())

	g.client = conn
	g.req = bufio.NewReader(conn)
	g.res = conn
	g.local = &protocol.Addr{
		IP:   conn.LocalAddr().(*net.TCPAddr).IP,
		Port: uint16(conn.LocalAddr().(*net.TCPAddr).Port),
	}
	g.src = &protocol.Addr{
		IP:   conn.RemoteAddr().(*net.TCPAddr).IP,
		Port: uint16(conn.RemoteAddr().(*net.TCPAddr).Port),
	}

	if err := g.readPubKey(); err != nil {
		g.logger.Errorf("failed to read public key: %s", err.Error())
		return
	}
	g.logger.Tracef("client public key read")

	if err := g.writePubKey(); err != nil {
		g.logger.Errorf("failed to write public key: %s", err.Error())
		return
	}
	g.logger.Tracef("server public key written")

	if err := g.parseRequest(); err != nil {
		g.logger.Errorf("failed to parse request: %s", err.Error())
		return
	}
	g.logger.Tracef("request parsed")

	var dialErr error
	g.target, dialErr = g.dialer.DialContext(ctx, "tcp", g.dst.String())
	if err := g.reply(dialErr); err != nil {
		g.logger.Error(err)
		return
	}

	if dialErr != nil {
		g.logger.Errorf("failed to dial target server: %v", dialErr.Error())
		return
	}
	defer g.target.Close()

	g.logger.Tracef("request from %s to %s", g.client.RemoteAddr(), g.dst.String())

	var cipherTarget net.Conn
	ed := crypto.StreamEncryptDecrypter{
		EncryptKey: g.sessionKey,
		DecryptKey: g.sessionKey,
	}

	switch g.clientCipher {
	case protocol.CipherPlaintext:
		cipherTarget = g.target
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
		g.logger.Errorf("unsupported cipher method %#x", g.clientCipher)
		return
	}

	if g.clientCipher != protocol.CipherPlaintext {
		encryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
			g.logger.Errorf("failed to generate encryption IV: %s", err)
			return
		}
		if _, err := g.res.Write(encryptIV); err != nil {
			g.logger.Errorf("failed to write encryption IV: %s", err)
			return
		}

		decryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadAtLeast(g.req, decryptIV, aes.BlockSize); err != nil {
			g.logger.Errorf("failed to read decryption IV: %s", err)
			return
		}

		ed.EncryptIV = encryptIV
		ed.DecryptIV = decryptIV

		var err error
		cipherTarget, err = ed.Ciphertext(g.target)
		if err != nil {
			g.logger.Errorf("failed to create cipher for target connection: %s", err)
			return
		}
	}

	if _, _, err := util.Proxy(cipherTarget, g.client); err != nil {
		g.logger.Errorf("failed to proxy connections: %s", err)
		return
	}

	return
}

func (g *gndhog) readPubKey() error {
	buf := make([]byte, 550) // 550 bytes: length of a PKIX formatted 4096-bit RSA public key

	if _, err := io.ReadAtLeast(g.req, buf, 550); err != nil {
		return err
	}

	pub, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return err
	}

	if rsaPub, ok := pub.(*rsa.PublicKey); !ok {
		return errors.New("invalid RSA public key")
	} else {
		g.clientKey = rsaPub
		return nil
	}
}

func (g *gndhog) writePubKey() error {
	buf, err := x509.MarshalPKIXPublicKey(&g.serverKey.PublicKey)

	if err != nil {
		return err
	}

	if _, err := g.res.Write(buf); err != nil {
		return err
	}

	return nil
}

func (g *gndhog) parseRequest() error {
	ciphertext := make([]byte, 512)
	if _, err := io.ReadAtLeast(g.req, ciphertext, 512); err != nil {
		return err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, g.serverKey, ciphertext, nil)
	if err != nil {
		return err
	}

	reqRd := bytes.NewReader(plaintext)
	if addr, err := protocol.NewAddrFromReader(reqRd); err != nil {
		return err
	} else {
		g.dst = addr
	}

	if method, err := reqRd.ReadByte(); err != nil {
		return err
	} else {
		g.clientCipher = method
	}

	for _, v := range g.acceptableCiphers {
		if g.clientCipher == v {
			return nil
		}
	}

	return fmt.Errorf("unsupported cipher method %#x", g.clientCipher)
}

func (g *gndhog) reply(err error) error {
	rep := protocol.ErrToRep(err)
	plaintext := []byte{0x00}

	if rep != protocol.RepSucceeded {
		plaintext[0] = rep
	} else {
		keyLen := 0
		switch g.clientCipher {
		case protocol.CipherPlaintext:
			keyLen = 0
		case protocol.CipherAES128CFB, protocol.CipherAES128CTR, protocol.CipherAES128OFB:
			keyLen = 16 // 128/8
		case protocol.CipherAES192CFB, protocol.CipherAES192CTR, protocol.CipherAES192OFB:
			keyLen = 24 // 192/8
		case protocol.CipherAES256CFB, protocol.CipherAES256CTR, protocol.CipherAES256OFB:
			keyLen = 32 // 192/8
		default:
			fmt.Errorf("unsupported cipher method %#x", g.clientCipher)
		}

		if keyLen > 0 {
			g.sessionKey = make([]byte, keyLen)

			if _, err := io.ReadFull(rand.Reader, g.sessionKey); err != nil {
				return err
			}

			plaintext = append(plaintext, g.sessionKey...)
		}
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, g.clientKey, plaintext, nil)
	if err != nil {
		return err
	}

	g.res.Write(ciphertext)
	return nil
}
