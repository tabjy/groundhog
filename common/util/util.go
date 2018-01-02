// Package util provides a few utility functions.
package util

import (
	"io"
	"sync"
	"net"
)

// Proxy connect two ReadWriter, forward data between them in a full-duplex
// manner. Proxy returns upon either EOF is reached on both ReadWriter or an
// error occurs.
func Proxy(lhs io.ReadWriter, rhs io.ReadWriter) (lhsWritten, rhsWritten int64, err error) {
	var wg sync.WaitGroup

	// copy from rhs to lhs
	wg.Add(1)
	go func() {
		lhsWritten, err = io.Copy(lhs, rhs)
		closeNetConn(lhs, rhs)
		if err != nil {
			wg.Done()
		} else {
			wg.Add(-1)
		}
	}()

	// copy from lhs to rhs
	wg.Add(1)
	go func() {
		rhsWritten, err = io.Copy(rhs, lhs)
		closeNetConn(lhs, rhs)
		if err != nil {
			wg.Done()
		} else {
			wg.Add(-1)
		}
	}()

	wg.Wait()
	return
}

func closeNetConn(rws... io.ReadWriter) {
	for _, v := range rws {
		if conn, ok := v.(net.Conn); ok {
			conn.Close()
		}
	}
}