package remote

import (
	"crypto/rsa"
	"net"

	"github.com/tabjy/groundhog/pkg/util"
	"github.com/tabjy/groundhog/pkg/base"
)

type Config struct {
	Host string
	Port int

	PrivateKey             *rsa.PrivateKey
	SupportedCipherMethods []byte
}

type Server struct {
	config *Config
}

func GenerateDefaultConfig() (*Config, error) {
	port, err := util.GetAvailPort()
	if err != nil {
		return nil, err
	}

	return &Config{
		Host: "127.0.0.1",
		Port: port,
	}, nil
}

func NewServer(config *Config) (*base.Server, error) {
	return base.NewServer(config.Host, config.Port, func(conn net.Conn) error {
		return newProxyConn(conn, config).serve()
	})
}
