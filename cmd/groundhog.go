// TestFlag project main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"crypto/rsa"
	"crypto/rand"
	"strings"

	"github.com/tabjy/groundhog/pkg/util"
	"github.com/tabjy/groundhog/pkg/remote"
	"github.com/tabjy/groundhog/pkg/local"
	"github.com/tabjy/groundhog/pkg/socks5"
)

var (
	isServerMode bool
	isClientMode bool
	isKeyGenMode bool

	host string
	port int

	cipher string

	socks5Host string
	socks5Port int
)

func init() {
	flag.BoolVar(&isServerMode, "server", false, "run in server mode")
	flag.BoolVar(&isClientMode, "client", false, "run in client mode")
	flag.BoolVar(&isKeyGenMode, "key-gen", false, "generate RSA key pair")

	flag.StringVar(&host, "host", "", "server/client hostname")
	flag.IntVar(&port, "port", 1081, "server/client port")

	flag.StringVar(&cipher, "cipher", "", `client: cipher name, server: acceptable cipher names, separated by ","`)

	flag.StringVar(&socks5Host, "socks5-host", "127.0.0.1", "hostname for local SOCKS5 server")
	flag.IntVar(&socks5Port, "socks5-port", 1080, "port for local SOCKS5 server")
}

func main() {
	flag.Parse()

	switch {
	case isServerMode:
		startServerMode()
	case isClientMode:
		startClientMode()
	case isKeyGenMode:
		startKeyGenMode()
	default:
		fmt.Println("no working mode sepcified")
		os.Exit(1)
	}
}

func startServerMode() {
	keyPath, err := util.GetRSAKeyPath()
	assert(err)

	keyPair, err := util.ReadRSAKey(keyPath)
	assert(err)

	config, err := remote.GenerateDefaultConfig()
	assert(err)

	config.Port = port

	if host != "" {
		config.Host = host
	} else {
		config.Host = "0.0.0.0"
	}

	config.PrivateKey = keyPair

	if cipher == "" {
		assert(fmt.Errorf("no cipher sepecified"))
	}

	cipherStrings := strings.Split(cipher, ",")

	config.SupportedCipherMethods = make([]byte, len(cipherStrings))
	for i, v := range cipherStrings {
		switch strings.ToUpper(v) {
		case "PLAINTEXT":
			config.SupportedCipherMethods[i] = util.CIPHER_PLAINTEXT
		case "AES-128-CFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_128_CFB
		case "AES-192-CFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_192_CFB
		case "AES-256-CFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_256_CFB
		case "AES-128-CTR":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_128_CTR
		case "AES-192-CTR":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_192_CFB
		case "AES-256-CTR":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_256_CTR
		case "AES-128-OFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_128_OFB
		case "AES-192-OFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_192_OFB
		case "AES-256-OFB":
			config.SupportedCipherMethods[i] = util.CIPHER_AES_256_OFB
		default:
			assert(fmt.Errorf("invalid cipher method: %s", v))
		}
	}

	server, err := remote.NewServer(config)
	assert(err)

	fmt.Printf("Groundhog server running on %s:%d\n", config.Host, config.Port)
	if err := server.Start(); err != nil {
		assert(err)
	}
}

func startClientMode() {
	keyPath, err := util.GetRSAKeyPath()
	assert(err)

	keyPair, err := util.ReadRSAKey(keyPath)
	assert(err)

	if host == "" {
		assert(fmt.Errorf("invalid host: %s", host))
	}

	config := &local.Config{
		Host: host,
		Port: port,
		PrivateKey: keyPair,
	}

	switch strings.ToUpper(cipher) {
	case "PLAINTEXT":
		config.CipherMethod = util.CIPHER_PLAINTEXT
	case "AES-128-CFB":
		config.CipherMethod = util.CIPHER_AES_128_CFB
	case "AES-192-CFB":
		config.CipherMethod = util.CIPHER_AES_192_CFB
	case "AES-256-CFB":
		config.CipherMethod = util.CIPHER_AES_256_CFB
	case "AES-128-CTR":
		config.CipherMethod = util.CIPHER_AES_128_CTR
	case "AES-192-CTR":
		config.CipherMethod = util.CIPHER_AES_192_CFB
	case "AES-256-CTR":
		config.CipherMethod = util.CIPHER_AES_256_CTR
	case "AES-128-OFB":
		config.CipherMethod = util.CIPHER_AES_128_OFB
	case "AES-192-OFB":
		config.CipherMethod = util.CIPHER_AES_192_OFB
	case "AES-256-OFB":
		config.CipherMethod = util.CIPHER_AES_256_OFB
	default:
		assert(fmt.Errorf("invalid cipher method: %s", cipher))
	}

	client := local.NewClient(config)

	socks5Config, err := socks5.GenerateDefaultConfig()
	assert(err)

	socks5Config.Port = socks5Port
	socks5Config.Host = socks5Host
	socks5Config.Dial = client.GetConn

	server, err := socks5.NewServer(socks5Config)
	assert(err)

	fmt.Printf("SOCKS5 server running on %s:%d\n", socks5Config.Host, socks5Config.Port)
	fmt.Printf("All traffic to SOCKS5 server routing through %s:%d\n", config.Host, config.Port)
	if err := server.Start(); err != nil {
		assert(err)
	}
}

func startKeyGenMode() {
	fmt.Println("Generating public/private rsa key pair...")
	keyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	assert(err)

	path, err := util.GetRSAKeyPath()
	assert(err)

	err = util.WriteRSAKey(path, keyPair)
	assert(err)

	fmt.Println("Done. PEM encoded key pair wrote to", path)
}

func assert(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
