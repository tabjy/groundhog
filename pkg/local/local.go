package local

import (
	"crypto/rsa"
	"net"

	"gitlab.com/tabjy/groundhog/pkg/util"
)

type Config struct {
	Host string
	Port int

	PrivateKey   rsa.PrivateKey
	CipherMethod byte
}

type Client struct {
	config *Config
}

func NewClient(config *Config) (*Client, error) {
	return &Client{
		config,
	}, nil
}

func (c *Client) GetConn(addr *util.Addr) (net.Conn, byte) {
	// TODO: implement bypass whitelist
	target, err := c.getProxyConn(addr)
	if err != nil {
		return nil, util.ConnErrToRep(err)
	}
	return target, util.REP_SUCCEEDED
}

func (c *Client) getProxyConn(addr *util.Addr) (net.Conn, error) {
	return newProxyConn(addr, c.config).connect()
}