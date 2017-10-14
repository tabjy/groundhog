package socks5

import (
	"net"
	"bufio"
	"io"
	"fmt"
	"strings"

	"gitlab.com/tabjy/groundhog/pkg/util"
)

const (
	cmdConnect      byte = 0x01
	cmdBind         byte = 0x02
	cmdUdpAssociate byte = 0x03
)

const (
	authMethodNoAuth       byte = 0x00
	authMethodGSSAPI       byte = 0x01
	authMethodUserPass     byte = 0x02
	authMethodNoAcceptable byte = 0xff
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
	errUnsupportedSocksVer    = fmt.Errorf("unsupoorted SOCKS version")
	errNoAcceptableAuthMethod = fmt.Errorf("no supported authentication method")
	errUnsupportedCmd         = fmt.Errorf("unsupported socks command")
	errIllegalReservedField   = fmt.Errorf("illegal reserved field")
)

type socksConn struct {
	conn        net.Conn
	req         io.Reader
	res         io.Writer
	authMethods []byte
	cmd         byte
	destAddr    *util.Addr
}

func newSocksConn(conn net.Conn) *socksConn {
	writer, _ := conn.(io.Writer)
	return &socksConn{
		conn: conn,
		req:  bufio.NewReader(conn),
		res:  writer,
	}
}

// any connection-level fatal error should be returned for logging
func (c *socksConn) serve() error {
	defer c.conn.Close()

	// first request: authentication
	if err := c.checkSocksVer(); err != nil {
		return err
	}

	if err := c.auth(); err != nil {
		return err
	}

	if err := c.checkSocksVer(); err != nil {
		return err
	}

	if err := c.readCmd(); err != nil {
		return err
	}

	// check RSV byte, which MUST be 0x00
	rsv := []byte{0}
	if _, err := c.req.Read(rsv); err != nil {
		return err
	}
	if rsv[0] != 0x00 {
		return errIllegalReservedField
	}

	if err := c.readDestAddr(); err != nil {
		return err
	}

	c.exec()

	return nil
}

func (c *socksConn) checkSocksVer() error {
	ver := []byte{0}
	if _, err := c.req.Read(ver); err != nil {
		return err
	}

	// supports SOCKS5 only
	if ver[0] != byte(0x05) {
		return errUnsupportedSocksVer
	}

	return nil
}

// support "NO AUTHENTICATION REQUIRED" only. others no needed.
func (c *socksConn) auth() error {
	methodLen := []byte{0}
	if _, err := c.req.Read(methodLen); err != nil {
		return err
	}

	c.authMethods = make([]byte, int(methodLen[0]))
	if _, err := io.ReadAtLeast(c.req, c.authMethods, int(methodLen[0])); err != nil {
		return err
	}

	for method := range c.authMethods {
		if method == 0x00 {
			c.res.Write([]byte{0x05, authMethodNoAuth})
			return nil
		}
	}

	c.res.Write([]byte{0x05, authMethodNoAcceptable})
	return errNoAcceptableAuthMethod
}

func (c *socksConn) readCmd() error {
	cmd := []byte{0}
	if _, err := c.req.Read(cmd); err != nil {
		return err
	}

	switch cmd[0] {
	case cmdConnect, cmdBind, cmdUdpAssociate:
		c.cmd = cmd[0]
		return nil

	default:
		return errUnsupportedCmd
	}
}

func (c *socksConn) readDestAddr() error {
	addr, err := util.NewAddr().Parse(c.req)
	if err != nil {
		return err
	}
	c.destAddr = addr
	return nil
}

// support CONNECT only, at least for this moment
func (c *socksConn) exec() error {
	// TODO: add support for BIND and UDPAssociate
	switch c.cmd {
	case cmdConnect:
		// TODO: implement bypass whitelist
		// TODO: move actually proxy connection to other packages
		target, err := net.Dial("tcp", c.destAddr.String())
		if err != nil {
			fmt.Println(c.destAddr.String()+":", err)
			errMsg := err.Error()
			// TODO: differentiate more error types
			switch {
			case strings.Contains(errMsg, "no such host"):
				c.sendReply(repHostUnreachable, util.NewAddr())
			case strings.Contains(errMsg, "connection refused"):
				c.sendReply(repConnectionRefused, util.NewAddr())
			case strings.Contains(errMsg, "connection timed out"):
				c.sendReply(repTtlExpired, util.NewAddr())
			default:
				c.sendReply(repGeneralFailure, util.NewAddr())
			}

			return err
		}
		defer target.Close()

		if err := c.sendReply(repSucceeded, c.destAddr); err != nil {
			return err
		}

		errCh := make(chan error, 2)

		go proxy(target, c.req, errCh)
		go proxy(c.res, target, errCh)

		for i := 0; i < 2; i++ {
			err := <-errCh
			if err != nil {
				// return from this function closes target (and conn).
				return err
			}
		}

	default:
		return errUnsupportedCmd
	}
	return nil
}

func (c *socksConn) sendReply(rep byte, addr *util.Addr) error {
	addrBytes, err := addr.Build()
	if err != nil {
		return err
	}

	buf := []byte{0x05, rep, 0x00}

	// writing separately somehow causes addrBytes to be dropped
	// and results in a malformed SOCKS5 reply
	buf = append(buf, addrBytes...)
	if _, err := c.res.Write(buf); err != nil {
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
