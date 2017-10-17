package server

import (
	"net"
	"io"
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"bytes"

	"gitlab.com/tabjy/groundhog/pkg/util"
	"fmt"
	"gitlab.com/tabjy/groundhog/pkg/crypto"
	"strings"
	"crypto/rand"
	"crypto/cipher"
)

const (
	repSucceeded               byte = 0x00
	repGeneralFailure          byte = 0x01
	repNotAllowByRuleset       byte = 0x02
	repNetworkUnreachable      byte = 0x03
	repHostUnreachable         byte = 0x04
	repConnectionRefused       byte = 0x05
	repTtlExpired              byte = 0x06
	repCommamdNotSupported     byte = 0x07
	repAddressTypeNotSupported byte = 0x08
)

var (
	errUnsupportedCiphermethod = fmt.Errorf("unsupported cipher method")
)

type proxyConn struct {
	conn         net.Conn
	req          io.Reader
	res          io.Writer
	destAddr     *util.Addr
	config       *Config
	publicKey    *rsa.PublicKey
	cipherMethod byte
	cipherBlock  cipher.Block
}

func newProxyConn(conn net.Conn, config *Config) *proxyConn {
	writer, _ := conn.(io.Writer)
	return &proxyConn{
		conn:   conn,
		req:    bufio.NewReader(conn),
		res:    writer,
		config: config,
	}
}

// any connection-level fatal error should be returned for logging
func (c *proxyConn) serve() error {
	defer c.conn.Close()

	// parse client's public key
	if err := c.readPubKey(); err != nil {
		return err
	}

	// send server's public key
	if err := c.writePubKey(); err != nil {
		return err
	}

	if err := c.readRequest(); err != nil {
		return err
	}

	target, err := net.Dial("tcp", c.destAddr.String())
	defer target.Close()
	if err != nil {
		fmt.Println(c.destAddr.String()+":", err)
		errMsg := err.Error()
		// TODO: differentiate more error types
		switch {
		case strings.Contains(errMsg, "no such host"):
			c.sendReply(repHostUnreachable, util.NewAddr(), nil)
		case strings.Contains(errMsg, "connection refused"):
			c.sendReply(repConnectionRefused, util.NewAddr(), nil)
		case strings.Contains(errMsg, "connection timed out"):
			c.sendReply(repTtlExpired, util.NewAddr(), nil)
		default:
			c.sendReply(repGeneralFailure, util.NewAddr(), nil)
		}

		return err
	}

	// TODO: support other key size
	// AES256 key len: 32 bytes
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return err
	}
	if err := c.sendReply(repSucceeded, c.destAddr, aesKey); err != nil {
		return err
	}

}

func (c *proxyConn) readPubKey() error {
	// TODO: support RSA size other than 4096
	// is RSA-4096 public key always 550 bytes long after PKIX encoded?
	pkixBuf := make([]byte, 550)
	if _, err := io.ReadAtLeast(c.req, pkixBuf, 550); err != nil {
		return err
	}

	pub, err := x509.ParsePKIXPublicKey(pkixBuf)
	if err != nil {
		return err
	}

	rsaPub, _ := pub.(rsa.PublicKey)

	c.publicKey = &rsaPub
	return nil
}

func (c *proxyConn) writePubKey() error {
	pkixBuf, err := x509.MarshalPKIXPublicKey(&c.config.PrivateKey.PublicKey)
	if err != nil {
		return err
	}

	if _, err := c.res.Write(pkixBuf); err != nil {
		return err
	}
	return nil
}

func (c *proxyConn) readRequest() error {
	// 4096 / 8 - 2 * 256 / 8 - 2 = 446
	// max payload size of RSA 4096 OAEP with SHA256: 446
	// max hostname length in POSIX: 255
	ciphertext := make([]byte, 512)
	if _, err := io.ReadAtLeast(c.req, ciphertext, 512); err != nil {
		return err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, &c.config.PrivateKey, ciphertext, nil)
	if err != nil {
		return err
	}

	plaintextReader := bytes.NewReader(plaintext)

	addr, err := util.NewAddr().Parse(plaintextReader)
	if err != nil {
		// TODO: handel unsupported address type response
		return err
	}
	c.destAddr = addr

	cipherMethod, err := plaintextReader.ReadByte()
	if err != nil {
		return err
	}

	switch cipherMethod {
	case crypto.Method_PLAINTEXT, crypto.Method_AES_128_CBF, crypto.Method_AES_192_CBF, crypto.Method_AES_256_CBF:
		c.cipherMethod = cipherMethod
	default:
		return errUnsupportedCiphermethod
	}

	return nil
}

func (c *proxyConn) sendReply(rep byte, addr *util.Addr, aesKey []byte) error {
	addrBuf, err := addr.Build()
	if err != nil {
		return err
	}
	// TODO: support other key size
	// AES256 key len: 32 bytes
	// replyBuf := make([]byte, 1+len(addrBuf)+32)
	replyBuf := []byte{rep}
	replyBuf = append(replyBuf, addrBuf...)
	replyBuf = append(replyBuf, aesKey...)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.publicKey, replyBuf, nil)
	if err != nil {
		return err
	}
	if _, err := c.res.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
