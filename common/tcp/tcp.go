// Package tcp implements a basic TCP server.
// Such a TCP server supports graceful shutdown and context.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/tabjy/groundhog/common/adt"
	"github.com/tabjy/yagl"

)

// ErrServerClosed is returned by the Server's Serve, and ListenAndServe,
// methods after a call to Shutdown or Close.
var ErrServerClosed = errors.New("common: Server closed")

// ErrServerNotListening is returned by Server's Serve, and ListenAndServe,
// methods if being called before calling Listen.
var ErrServerNotListening = errors.New("common: Server not listening")

type Handler interface {
	ServeTCP(ctx context.Context, conn net.Conn)
}

type echoHandler struct{}

func (h *echoHandler) ServeTCP(ctx context.Context, conn net.Conn) {
	go func() {
		<-ctx.Done() // this doesn't block forever, Server call cancel after ServeTCP returns
		// conn.Close() // could fail with error, but it's okay
		yagl.Trace("echoHandler goroutine unblocks and exists")
	}()
	if _, err := io.Copy(conn, conn); err != nil {
		if ctx.Err() != nil {
			yagl.Infof("context canceled: %v", ctx.Err())
		} else {
			yagl.Errorf("fail to echo request: %v", err)
		}
	}
}

var EchoHandler = &echoHandler{}

// A Server defines parameters for running a TCP server. The zero value for
// Server is a valid configuration.
type Server struct {
	Host string // IP address or hostname to listen on. Leave empty for an unspecified address.
	Port uint16 // Port to listen on. A port number is automatically chosen if left empty or 0.

	Handler Handler

	// ErrorLog specifies an optional logger
	// If nil, logging goes to os.Stderr via a yagl standard logger
	Logger yagl.Logger

	ln    net.Listener
	conns adt.Set

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (srv *Server) logger() yagl.Logger {
	if srv.Logger == nil {
		return yagl.StdLogger()
	}
	return srv.Logger
}

// Listen listens on srv.Host:srv.Port. If a Listener is ready created, the old
// one will be closed and replaced.
func (srv *Server) Listen() error {
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(int(srv.Port)))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		srv.logger().Errorf("failed to listen on %s: %v", addr, err)
		return err
	}
	srv.ln = ln
	srv.logger().Infof("Server listening on %v", srv.ln.Addr())

	return nil
}

// Serve accepts incoming connections on the Listener ln, creating a new
// service goroutine for each. The service goroutines read requests and then
// call srv.Handler to handle to them. Make sure Listen is called before
// calling this function.
//
// Serve always returns a non-nil error. After Shutdown or Close, the returned
// error is ErrServerClosed.
func (srv *Server) Serve() error {
	if srv.ln == nil {
		return ErrServerNotListening
	}

	srv.conns = adt.NewHashSet()

	if srv.Handler == nil {
		srv.Handler = EchoHandler
	}

	srv.ctx, srv.cancel = context.WithCancel(context.Background())

	for true {
		conn, err := srv.ln.Accept()
		if err != nil {
			// server level error, causing server to stop
			// ln.Accept unblocks and returns error when ln.Close called, by design
			if strings.Contains(err.Error(), "use of closed network connection") {

				return ErrServerClosed
			}
			srv.logger().Errorf("Server stopping for error: %v", err)
			return err
		}

		srv.wg.Add(1)
		go func() {
			defer func() {
				srv.wg.Add(-1)
				srv.conns.Remove(conn)
			}()
			srv.conns.Add(conn)
			srv.logger().Tracef("new connection from %v", conn.RemoteAddr())

			srv.logger().Tracef("connection to be handled by %T", srv.Handler)
			ctx, cancel := context.WithCancel(srv.ctx)
			srv.Handler.ServeTCP(ctx, conn)
			srv.logger().Tracef("handler %T returned, connection closing...", srv.Handler)
			cancel()

			// try to closed connection, even if it's closed by handler already
			if err := conn.Close(); err != nil {
				// test if because conn already closed
				if !strings.Contains(err.Error(), "use of closed network connection") {
					srv.logger().Panicf("failed to close connection from %v, %v", conn.RemoteAddr(), err)
					// goroutine stops here
				}
				srv.logger().Warnf("connection from %v is already closed", conn.RemoteAddr())
			}
			srv.logger().Tracef("connection from %v is now closed", conn.RemoteAddr())


		}()
	}

	// this never happens due to the infinite loop
	return nil
}

// ListenAndServe first call Listen, then calls Server to handle incoming
// connections. If srv.Addr is blank, ":tcp" is used.
//
// ListenAndServe always returns a non-nil error. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) ListenAndServe() error {
	if err := srv.Listen(); err != nil {
		return err
	}

	return srv.Serve()
}

func (srv *Server) forceCloseConns() {
	srv.logger().Tracef("forcing to close all connections, %d remaining", srv.conns.Len())
	srv.conns.ForEach(func(element interface{}) {
		conn := element.(net.Conn)
		srv.logger().Tracef("forcing to close %v", conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			// connection level errors, no need to deal with them, just log
			srv.logger().Errorf("failed to close connection: %v", err)
		}
	})
	srv.conns.Clear()
	srv.wg.Done()
}

// Close immediately closes active net.Listener and closes all active
// connections. This could be unsafe as there might be ongoing goroutines
// handling connections. Close return after Serve returns.
//
// Close returns any error returned from closing the Server's underlying
// Listener(s).
func (srv *Server) Close() error {
	srv.logger().Infof("closing server listening on %v", srv.ln.Addr())

	// first close listener, so no more incoming connections
	if err := srv.ln.Close(); err != nil {
		srv.logger().Errorf("failed to close listener: %v", err)
		return err
	}

	srv.cancel() // notify all handlers to finish whatever is left
	srv.forceCloseConns()

	return nil
}

// Shutdown immediately closes active net.Listener and sends close signals to
// all actives connection through context; still, it's up to connections'
// handlers to decide what to do with close signals. Shutdown wait for all
// connection to be closed before returning.
//
// Best practice: wait for a certain amount of time, then just call Close to
// force close all connections.
//
// Shutdown returns any error returned from closing the Server's underlying
// Listener(s).
func (srv *Server) Shutdown() error {
	srv.logger().Infof("shutting down server listening on %v", srv.ln.Addr())

	// first close listener, so no more incoming connections
	if err := srv.ln.Close(); err != nil {
		srv.logger().Errorf("failed to close listener: %v", err)
		return err
	}

	srv.cancel() // notify all handler to finish whatever is left
	srv.logger().Infof("shutdown signal sent, waiting for all connection to be closed, %d remaining", srv.conns.Len())
	srv.wg.Wait()
	// by the time wg.Wait unblocks, all connection SHOULD be closed
	// but let's just check for sure, for debug purpose
	if srv.conns.Len() != 0 {
		srv.Logger.Warn("not all connection are closed upon Shutdown!")
		srv.forceCloseConns()
	}

	return nil
}
