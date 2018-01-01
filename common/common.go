package common

import (
	"net"
	"context"
)

// Dialer interface contains two function being used by a SOCKS5 server. It
// determine how a SOCKS5 server create connection to target server. In most
// cases, a zero-value net.Dialer is sufficient enough.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
