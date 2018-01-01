// Package socks5 contains a basic implementation of a SOCKS5 server.
package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/tabjy/groundhog/common/protocol"
	"github.com/tabjy/groundhog/common/tcp"
	"github.com/tabjy/groundhog/common/util"
	"github.com/tabjy/groundhog/common"
	"github.com/tabjy/yagl"
	"errors"
)

// Config defines optional configurations for a SOCKS5 server. The zero value
// for Config is a valid configuration.
type Config struct {
	Host string // IP address or hostname to listen on. Leave empty for an unspecified address.
	Port uint16 // Port to listen on. A port number is automatically chosen if left empty or 0.

	Dialer common.Dialer // Dialer implementation. If nil, net.Dialer would be used.

	// Logger specifies an optional logger
	// If nil, logging goes to os.Stderr via a yagl standard logger.
	Logger yagl.Logger
}

// NewServer takes a SOCKS5 Config and return a tcp.Server. The returned server
// has to be manually started by calling srv.Listen and srv.Server (or just
// srv.ListenAndServer).
func NewServer(config *Config) *tcp.Server {
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

	return &tcp.Server{
		Host: config.Host,
		Port: config.Port,
		Handler: &handler{
			dialer: dialer,
			logger: logger,
		},
		Logger: logger,
	}
}

type handler struct {
	dialer common.Dialer
	logger yagl.Logger
}

func (h *handler) ServeTCP(ctx context.Context, conn net.Conn) {
	s := socks{
		dialer: h.dialer,
		logger: h.logger,
	}
	s.init(ctx, conn)
}

type socks struct {
	dialer common.Dialer
	logger yagl.Logger

	client net.Conn
	target net.Conn

	req io.Reader
	res io.Writer

	dst   *protocol.Addr
	src   *protocol.Addr
	local *protocol.Addr
}

func (s *socks) init(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// watchdog to close connections if context cancelled
	go func() {
		<-ctx.Done() // this doesn't block forever, Server call cancel after ServeTCP returns

		if s.client != nil {
			s.client.Close()
		}

		if s.target != nil {
			s.target.Close()
		}
	}()

	conn.(*net.TCPConn).SetKeepAlive(true)

	s.client = conn
	s.req = bufio.NewReader(conn)
	s.res = conn
	s.local = &protocol.Addr{
		IP:   conn.LocalAddr().(*net.TCPAddr).IP,
		Port: uint16(conn.LocalAddr().(*net.TCPAddr).Port),
	}
	s.src = &protocol.Addr{
		IP:   conn.RemoteAddr().(*net.TCPAddr).IP,
		Port: uint16(conn.RemoteAddr().(*net.TCPAddr).Port),
	}

	if err := s.assertSOCKSVer(); err != nil {
		s.logger.Errorf("failed to assert SOCKS version: %v", err.Error())
		return
	}

	if err := s.auth(); err != nil {
		s.logger.Errorf("failed to authenticate SOCKS user: %v", err.Error())
		return
	}

	if err := s.assertSOCKSVer(); err != nil {
		s.logger.Errorf("failed to assert SOCKS version: %v", err.Error())
		return
	}

	if err := s.assertCmd(); err != nil {
		s.logger.Errorf("failed to assert SOCKS command: %v", err.Error())
		return
	}

	if err := s.assertRsvByte(); err != nil {
		s.logger.Errorf("failed to assert SOCKS reserved byte: %v", err.Error())
		return
	}

	if err := s.readDstAddr(); err != nil {
		s.logger.Errorf("failed to assert parse SOCKS request dst: %v", err.Error())
		return
	}

	s.logger.Tracef("request from %s to %s", s.client.RemoteAddr(), s.dst.String())

	// only CONNECT command is supported for this moment
	var dialErr error
	s.target, dialErr = s.dialer.DialContext(ctx, "tcp", s.dst.String())

	if err := s.reply(dialErr, s.local); err != nil {
		s.logger.Error(err)
		return
	}

	if dialErr != nil {
		s.logger.Errorf("failed to dial target server: %v", dialErr.Error())
		return
	}
	defer s.target.Close()

	s.logger.Tracef("target connected, %s", s.target.RemoteAddr())

	/* it turns out this logic is unnecessary, no error with or without this, but why...
	// XXX: stop using bufio from here, but some bytes are already buffered
	bufReq := s.req.(*bufio.Reader)  // s.req must be *bufio.Reader
	bufLen := bufReq.Buffered()      // get number of bytes buffered
	buffered := make([]byte, bufLen) // make room for buffered bytes

	// load buffered bytes without advancing the reader
	buffered, bufErr := bufReq.Peek(bufLen)
	if bufErr != nil {
		s.logger.Error(bufErr)
		return
	}

	// send buffered bytes to target server
	if _, err := io.Copy(s.target, bytes.NewBuffer(buffered)); err != nil {
		s.logger.Error(err)
		return
	}
	*/

	if _, _, err := util.Proxy(s.target, s.client); err != nil {
		s.logger.Error(err)
		return
	}

	return
}

func (s *socks) assertSOCKSVer() error {
	ver := []byte{0}
	if _, err := s.req.Read(ver); err != nil {
		return err
	}

	// supports SOCKS5 only
	if ver[0] != byte(0x05) {
		return fmt.Errorf("unsupported SOCKS version: %#x", ver[0])
	}

	return nil
}

func (s *socks) auth() error {
	methodLen := []byte{0}
	if _, err := s.req.Read(methodLen); err != nil {
		return err
	}

	methods := make([]byte, int(methodLen[0]))
	if _, err := io.ReadAtLeast(s.req, methods, int(methodLen[0])); err != nil {
		return err
	}

	// supports NO AUTHENTICATION REQUIRED only
	for method := range methods {
		if method == 0x00 { // 0x00 for NO AUTHENTICATION REQUIRED
			s.res.Write([]byte{0x05, 0x00})
			return nil
		}
	}

	return errors.New("no supported SOCKS authentication method")
}

func (s *socks) assertCmd() error {
	cmd := []byte{0}
	if _, err := s.req.Read(cmd); err != nil {
		return err
	}

	if cmd[0] != byte(0x01) {
		return fmt.Errorf("unsupported SOCKS command: %#x", cmd[0])
	}

	return nil
}

func (s *socks) assertRsvByte() error {
	// according to RFC1928, RSV byte must be 0x00
	rsv := []byte{0}
	if _, err := s.req.Read(rsv); err != nil {
		return err
	}

	if rsv[0] != byte(0x00) {
		return fmt.Errorf("illegal SOCKS reserved field: %#x (must be 0x00)", rsv[0])
	}

	return nil
}

func (s *socks) readDstAddr() error {
	addr, err := protocol.NewAddrFromReader(s.req)
	if err != nil {
		return err
	}

	s.dst = addr
	return nil
}

func (s *socks) reply(err error, addr *protocol.Addr) error {
	rep := protocol.ErrToRep(err)

	if rep > 0x08 {
		// this shouldn't happen anyway, but let's be sure
		rep = protocol.RepGeneralFailure
	}

	addrBytes, err := addr.Marshal()
	if err != nil {
		return err
	}

	buf := make([]byte, 3+len(addrBytes))
	buf[0] = 0x05
	buf[1] = rep
	buf[2] = 0x00
	copy(buf[3:], addrBytes)

	if _, err := s.res.Write(buf); err != nil {
		return err
	}

	return nil
}
