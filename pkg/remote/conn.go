package remote

import (
	"net"
	"gitlab.com/tabjy/groundhog/pkg/util"
	"io"
	"crypto/x509"
	"crypto/rsa"
	"fmt"
	"crypto/sha256"
	"bytes"
	"crypto/rand"
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

	// TODO: cipher implementation
	switch c.config.CipherMethod {
	case util.CIPHER_PLAINTEXT:
		errCh := make(chan error, 2)
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
	default:
		return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.config.CipherMethod)
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
	fmt.Println("remote pub got:", rsaPub)
	if !ok {
		return fmt.Errorf(util.ERR_TPL_INVALID_RSA_PUB_KEY)
	}
	c.clientPubKey = rsaPub

	return nil
}

func (c *proxyConn) writePubKey() error {
	// RSA key-pairs are guaranteed to be 4096 bit
	// TODO: investigate: is encoded public key always 550 byte long
	fmt.Println("remote pub send:", &c.config.PrivateKey.PublicKey)
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

	return nil
}

func (c *proxyConn) writeRes(rep byte) error {
	plaintext := []byte{0x00}

	if rep != util.REP_SUCCEEDED {
		plaintext[0] = rep
	} else {
		sessionKeyLen := 0
		switch c.config.CipherMethod {
		case util.CIPHER_AES_128_CBF, util.CIPHER_AES_128_CTR, util.CIPHER_AES_128_OFB:
			sessionKeyLen = 16
		case util.CIPHER_AES_192_CBF, util.CIPHER_AES_192_CTR, util.CIPHER_AES_192_OFB:
			sessionKeyLen = 24
		case util.CIPHER_AES_256_CBF, util.CIPHER_AES_256_CTR, util.CIPHER_AES_256_OFB:
			sessionKeyLen = 32
		case util.CIPHER_PLAINTEXT:
			sessionKeyLen = 0
		default:
			return fmt.Errorf(util.ERR_TPL_GROUNDHOG_CIPHER_NOT_SUPPORTED, c.config.CipherMethod)
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
