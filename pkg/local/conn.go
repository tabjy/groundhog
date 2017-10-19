package local

import (
	"net"
	"gitlab.com/tabjy/groundhog/pkg/util"
)

type proxyConn struct {
	conn         net.Conn
	destAddr     *util.Addr
	clientConfig *Config
}

func newProxyConn(addr *util.Addr, config *Config) *proxyConn {
	return &proxyConn{
		destAddr:     addr,
		clientConfig: config,
	}
}


func (c *proxyConn) connect() error {
	target
}
