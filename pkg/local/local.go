package local

import (
	"crypto/rsa"
	"sync"
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

func GetClient() *Client {
	return clientInstance
}


func (c *Client) handleProxy() error {

}
