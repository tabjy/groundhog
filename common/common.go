package common

import (
	"context"
	"net"
)

// Dialer interface contains two function being used by a SOCKS5 server. It
// determine how a SOCKS5 server create connection to target server. In most
// cases, a zero-value net.Dialer is sufficient enough.
//
// Caller cannot assume Dialer returns a *net.TCPConn even if network is
// specified to be "tcp" (in case that returned net.Conn is a decrypted
// net.TCPConn).
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
