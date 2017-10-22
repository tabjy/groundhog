package socks5

import (
	"net"
	"fmt"

	"gitlab.com/tabjy/groundhog/pkg/base"
	"gitlab.com/tabjy/groundhog/pkg/util"
)

type Config struct {
	Host string
	Port int
	Dial func(addr *util.Addr) (net.Conn, byte)
}

func GenerateDefaultConfig() (*Config, error) {
	port, err := util.GetAvailPort()
	if err != nil {
		return nil, err
	}

	return &Config{
		Host: "127.0.0.1",
		Port: port,
		Dial: func(addr *util.Addr) (net.Conn, byte) {
			target, err := net.Dial("tcp", addr.String())

			return target, util.ConnErrToRep(err)
		},
	}, nil
}

func NewServer(config *Config) (*base.Server, error) {
	if config.Dial == nil {
		return nil, fmt.Errorf(util.ERR_TPL_SRV_INVALID_DIAL_FUNC)
	}
	return base.NewServer(config.Host, config.Port, func(conn net.Conn) error {
		return newSocksConn(conn, config).serve()
	})
}
