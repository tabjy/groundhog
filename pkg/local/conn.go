package local

import (
	"net"
	"gitlab.com/tabjy/groundhog/pkg/util"
	"strconv"
	"crypto/x509"
	"crypto/rsa"
	"io"
	"fmt"
	"crypto/sha256"
	"bytes"
	"crypto/rand"
)

type proxyConn struct {
	conn       net.Conn
	destAddr   *util.Addr
	config     *Config
	srvPubKey  *rsa.PublicKey
	rep        byte
	sessionKey []byte
}

func newProxyConn(addr *util.Addr, config *Config) *proxyConn {
	return &proxyConn{
		destAddr: addr,
		config:   config,
	}
}

func (c *proxyConn) connect() (net.Conn, error) {
	conn, err := net.Dial("tcp", net.JoinHostPort(c.config.Host, strconv.Itoa(c.config.Port)))
	if err != nil {
		return nil, err
	}
	c.conn = conn

	if err := c.writePubKey(); err != nil {
		return nil, err
	}

	if err := c.readPubKey(); err != nil {
		return nil, err
	}

	if err := c.writeReq(); err != nil {
		return nil, err
	}

	if err := c.readRes(); err != nil {
		return nil, err
	}

	// var plainSide, cipherSide net.Conn
	// var err error

	// errCh := make(chan error)

	// TODO: cipher implementation
	switch c.config.CipherMethod {
	case util.CIPHER_PLAINTEXT:
		return c.conn, nil
	default:
		return nil, fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.config.CipherMethod)
	}

	return nil, nil
}

func (c *proxyConn) writePubKey() error {
	// RSA key-pairs are guaranteed to be 4096 bit
	// TODO: investigate: is encoded public key always 550 byte long
	fmt.Println("client pub send:", &c.config.PrivateKey.PublicKey)
	pub, err := x509.MarshalPKIXPublicKey(&c.config.PrivateKey.PublicKey)
	if err != nil {
		return err
	}

	if _, err := c.conn.Write(pub); err != nil {
		return err
	}

	return nil
}

func (c *proxyConn) readPubKey() error {
	fmt.Println("reading srv pub")
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
	fmt.Println("remote pub got:", rsaPub)
	if !ok {
		return fmt.Errorf(util.ERR_TPL_INVALID_RSA_PUB_KEY)
	}
	c.srvPubKey = rsaPub

	return nil
}

func (c *proxyConn) writeReq() error {
	// max payload size of RSA 4096 OAEP with SHA256: 446
	// 4096 / 8 - 2 * 256 / 8 - 2 = 446
	// max hostname length in POSIX: 255
	addr, err := c.destAddr.Build()
	if err != nil {
		return err
	}

	plaintext := append(addr, c.config.CipherMethod)
	fmt.Println("encrypt req", plaintext, len(plaintext))
	fmt.Println("encrypt req", c.srvPubKey)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.srvPubKey, plaintext, nil)
	if err != nil {
		return err
	}

	if _, err := c.conn.Write(ciphertext); err != nil {
		return err
	}

	fmt.Println("request sent")

	return nil
}

func (c *proxyConn) readRes() error {
	// TODO: investigate: is cipher text always 512 byte long
	ciphertext := make([]byte, 512)
	if _, err := io.ReadAtLeast(c.conn, ciphertext, 512); err != nil {
		return err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, c.config.PrivateKey, ciphertext, nil)
	if err != nil {
		return err
	}

	resReader := bytes.NewReader(plaintext)
	rep, err := resReader.ReadByte()

	if err != nil {
		return err
	}

	c.rep = rep
	if c.rep == util.REP_CIPHER_NOT_SUPPORTED {
		return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.config.CipherMethod)
	}

	// read AES session key
	sessionKeyLen := 0
	switch c.config.CipherMethod {
	case util.CIPHER_AES_128_CBF, util.CIPHER_AES_128_CTR, util.CIPHER_AES_128_OFB:
		sessionKeyLen = 16
	case util.CIPHER_AES_192_CBF, util.CIPHER_AES_192_CTR, util.CIPHER_AES_192_OFB:
		sessionKeyLen = 24
	case util.CIPHER_AES_256_CBF, util.CIPHER_AES_256_CTR, util.CIPHER_AES_256_OFB:
		sessionKeyLen = 32
	case util.CIPHER_PLAINTEXT:
		return nil
	default:
		return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.config.CipherMethod)
	}

	c.sessionKey = make([]byte, sessionKeyLen)
	if _, err := io.ReadAtLeast(resReader, c.sessionKey, sessionKeyLen); err != nil {
		return err
	}

	return nil
}
