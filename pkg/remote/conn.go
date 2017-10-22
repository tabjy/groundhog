package remote

import (
	"io"
)

type clientConn struct {
	req io.Reader
	res io.Writer
}
