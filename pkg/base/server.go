// server.go contains a base implementation of a TCP server
// in order to reduce repeated code in local and remote packages.

package base

import (
	"fmt"
	"gitlab.com/tabjy/groundhog/pkg/util"
	"net"
	"strconv"
	"time"
)

type Server struct {
	host string
	port int

	listener *net.TCPListener

	onConn func(net.Conn, ...*interface{}) error
	cbArgs []*interface{}

	isRunning  bool
	stopSig    chan interface{}
	stoppedSig chan interface{}
}

// cb for callback
func NewServer(host string, port int, onConn func(net.Conn, ...*interface{}) error, cbArgs ...*interface{}) (*Server, error) {
	if host == "" {
		host = "0.0.0.0"
	}

	if port == 0 || port > 65535 {
		return nil, fmt.Errorf(util.ERR_TPL_SRV_INVALID_PORT, port)
	}

	if onConn == nil {
		return nil, fmt.Errorf(util.ERR_TPL_SRV_INVALID_CB)
	}

	return &Server{
		host:       host,
		port:       port,
		onConn:     onConn,
		cbArgs:     cbArgs,
		stopSig:    make(chan interface{}),
		stoppedSig: make(chan interface{}),
		isRunning:  false,
	}, nil
}

func (s *Server) Start() error {
	if s.isRunning {
		return fmt.Errorf(util.ERR_TPL_SRV_ALREADY_STARTED)
	}

	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.host, strconv.Itoa(s.port)))
	if err != err {
		return err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.isRunning = true

	defer func() {
		listener.Close()
		s.isRunning = false
		// inform stop() action has been taken
		s.stoppedSig <- nil
	}()

	// infinite loop listening for connections
	for true {
		select {
		default:
			// on main goroutine, only fatal errors are returned
			if err := s.acceptConn(); err != nil {
				util.GetLogger().Fatal(err)
				return err
			}

			// stopping mechanism
		case <-s.stopSig:
			return nil
		}
	}
	return nil
}

// all error returned are fatal and should cause server to halt
func (s *Server) acceptConn() error {
	// set a deadline so the goroutine is not forever blocked, allowing graceful shutdown
	// not sure if 1 second is a reasonable value
	s.listener.SetDeadline(time.Now().Add(1 * time.Second))
	conn, err := s.listener.AcceptTCP()
	if err != nil {
		netErr, ok := err.(net.Error)
		// if is a timeout, continue to wait for new connections
		if ok && netErr.Timeout() && netErr.Temporary() {
			return nil
		}
		return err
	}

	// handle connection in a new goroutine
	go func() {
		err := s.onConn(conn, s.cbArgs...)
		if err != nil {
			util.GetLogger().Println(err)
		}
	}()

	// continue to next connection
	return nil
}

func (s *Server) Stop() error {
	if !s.isRunning {
		return fmt.Errorf(util.ERR_TPL_SRV_ALREADY_STOPPED)
	}

	s.stopSig <- nil
	<-s.stoppedSig
	return nil
}

func (s *Server) IsRunning() bool {
	return s.isRunning
}
