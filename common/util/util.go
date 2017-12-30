// Package util provides a few utility functions.
package util

import (
	"io"
	"sync"
)

type closerWrite interface {
	CloseWrite() error
}
type closerRead interface {
	CloseRead() error
}

// Proxy connect two ReadWriter, forward data between them in a full-duplex
// manner. Proxy returns upon either EOF is reached on both ReadWriter or an
// error occurs.
func Proxy(lhs io.ReadWriter, rhs io.ReadWriter) (lhsWritten, rhsWritten int64, err error) {
	var wg sync.WaitGroup

	// copy from rhs to lhs
	wg.Add(1)
	go func() {
		lhsWritten, err = io.Copy(lhs, rhs)
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
		if err != nil {
			wg.Done()
		} else {
			wg.Add(-1)
		}
	}()

	wg.Wait()
	return
}
