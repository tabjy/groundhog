package remote

import (
	"crypto/rsa"
	"gitlab.com/tabjy/groundhog/pkg/util"
	"gitlab.com/tabjy/groundhog/pkg/base"
	"net"
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
