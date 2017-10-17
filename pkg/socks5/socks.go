package socks5

import (
	"gitlab.com/tabjy/groundhog/pkg/base"
	"gitlab.com/tabjy/groundhog/pkg/util"
)

type Config struct {
	Host string
	Port int
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
	return base.NewServer(config.Host, config.Port, handleConn, nil)
}
