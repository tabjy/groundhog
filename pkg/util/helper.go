// helper.go contains series of convenient functions to be invoked from packages.
// Only functions should be exported from this file.

package util

import (
	"net"
	"io"
)

func GetAvailPort() (port int, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr, _ := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

type closeWriter interface {
	CloseWrite() error
}

func Proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}