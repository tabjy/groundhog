package socks5

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

var (
	ErrAlreadyStarted = fmt.Errorf("server has already started")
	ErrAlreadyStopped = fmt.Errorf("server has already stopped")
)

type Server struct {
	config     *Config
	stopSig    chan interface{}
	stoppedSig chan interface{}
	isRunning  bool
}

func NewServer(config *Config) (*Server, error) {
	if config.ListenPort == 0 {
		return nil, ErrInvalidListenPort
	}

	if config.ListenHost == "" {
		return nil, ErrInvalidListenHost
	}

	return &Server{
		config:     config,
		stopSig:    make(chan interface{}),
		stoppedSig: make(chan interface{}),
		isRunning:  false,
	}, nil
}

func (s *Server) Start() error {
	if s.isRunning {
		return ErrAlreadyStarted
	}

	addr, err := net.ResolveTCPAddr("tcp", s.config.ListenHost+":"+strconv.Itoa(s.config.ListenPort))
	if err != err {
		return err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	s.isRunning = true

	defer func() {
		listener.Close()
		s.isRunning = false
		// inform stop() action has been taken
		s.stoppedSig <- nil
	}()

	// infinite loop listening for connections
	for true {
		// stopping mechanism
		select {
		default:
			listener.SetDeadline(time.Now().Add(1 * time.Second)) // not sure if this works well
			conn, err := listener.AcceptTCP()
			if err != nil {
				netErr, ok := err.(net.Error)
				// If this is a timeout, continue to wait for new connections
				if ok && netErr.Timeout() && netErr.Temporary() {
					continue
				}

				return err
			}

			// TODO: implement a general error log package with level control
			go func() {
				err := newSocksConn(conn).serve()
				if err != nil {
					fmt.Println(err)
				}
			}()

		case <-s.stopSig:
			return nil
		}
	}
	return nil
}

func (s *Server) Stop() error {
	if !s.isRunning {
		return ErrAlreadyStopped
	}

	s.stopSig <- nil
	<-s.stoppedSig
	return nil
}

func (s *Server) IsRunning() bool {
	return s.isRunning
}
