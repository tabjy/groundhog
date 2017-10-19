package local

import (
	"crypto/rsa"
	"sync"
	"fmt"
	"gitlab.com/tabjy/groundhog/pkg/util"
	"io"
	"net"
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

var clientInstance *Client
var once sync.Once

func InitClient(config *Config) {
	once.Do(func() {
		clientInstance = &Client{
			config,
		}
	})
}

func GetClient() (*Client, error) {
	if clientInstance == nil {
		return nil, fmt.Errorf(util.ERR_TPL_CLIENT_NOT_INIT)
	}
	return clientInstance, nil
}


func (c *Client) HandleProxy(req io.Reader, res io.Writer, addr *util.Addr) error {
	// TODO: implement bypass whitelist

}


func (c *Client) getProxyConn(addr *util.Addr) (net.Conn, error) {

}

