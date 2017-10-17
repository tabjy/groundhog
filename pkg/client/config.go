package client

import "crypto/rsa"

type Config struct {
	Host         string
	Port         int
	PrivateKey   rsa.PrivateKey
	CipherMethod byte
}
