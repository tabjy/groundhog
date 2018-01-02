package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tabjy/groundhog/client"
	"github.com/tabjy/groundhog/cmd/groundhog/internal"
	"github.com/tabjy/groundhog/common/protocol"
	"github.com/tabjy/groundhog/server"
	"github.com/tabjy/groundhog/socks5"
	"github.com/tabjy/yagl"
)

var (
	isServerMode bool
	isClientMode bool
	isKeyGenMode bool

	host string
	port int

	ciphers string

	socks5Host string
	socks5Port int

	logger   yagl.Logger
	logLevel string
)

func init() {
	flag.BoolVar(&isServerMode, "server", false, "run in server mode")
	flag.BoolVar(&isClientMode, "client", false, "run in client mode")
	flag.BoolVar(&isKeyGenMode, "key-gen", false, "generate RSA key pair")

	flag.StringVar(&host, "host", "localhost", "server/client hostname")
	flag.IntVar(&port, "port", 1081, "server/client port")

	flag.StringVar(&ciphers, "cipher", "", `client: cipher name, server: acceptable cipher names, separated by ","`)

	flag.StringVar(&socks5Host, "socks5-host", "localhost", "hostname for local SOCKS5 server")
	flag.IntVar(&socks5Port, "socks5-port", 1080, "port for local SOCKS5 server")

	flag.StringVar(&logLevel, "log-level", "info", "logging level")
}

func main() {
	flag.Parse()

	initLogger()

	switch {
	case isServerMode:
		serverMode()
	case isClientMode:
		clientMode()
	case isKeyGenMode:
		keyGenMode()
	default:
		logger.Fatal("no working mode specified")
	}
}

func initLogger() {
	var level int

	switch logLevel {
	case "trace":
		level = yagl.LvlTrace
	case "debug":
		level = yagl.LvlDebug
	case "info":
		level = yagl.LvlInfo
	case "warn":
		level = yagl.LvlWarn
	case "error":
		level = yagl.LvlError
	case "panic":
		level = yagl.LvlPanic
	case "fatal":
		level = yagl.LvlFatal
	default:
		fmt.Fprintf(os.Stderr, "unrecognized logging level: %s\n", level)
		os.Exit(1)
	}

	logger = yagl.New(
		yagl.FlgDate|yagl.FlgTime|yagl.FlgShortFile,
		level,
		os.Stderr,
	)
}

func serverMode() {
	keyPath, err := internal.GetRSAKeyPath()
	if err != nil {
		logger.Fatalf("unable to get RSA key storing path: %s", err)
	}

	keyPair, err := internal.ReadRSAKey(keyPath)
	if err != nil {
		logger.Fatalf("unable tp read RSA key pair: %s\ntry run key-gen first", err)
	}

	var methods []byte
	if ciphers == "" {
		logger.Warnf("no cipher specified, default to PLAINTEXT (not recommended!)")
	} else {
		cipherStrings := strings.Split(ciphers, ",")
		methods = make([]byte, len(cipherStrings))
		for i, v := range cipherStrings {
			switch strings.ToUpper(v) {
			case "PLAINTEXT":
				methods[i] = protocol.CipherPlaintext
			case "AES-128-CFB":
				methods[i] = protocol.CipherAES128CFB
			case "AES-192-CFB":
				methods[i] = protocol.CipherAES192CFB
			case "AES-256-CFB":
				methods[i] = protocol.CipherAES256CFB
			case "AES-128-CTR":
				methods[i] = protocol.CipherAES128CTR
			case "AES-192-CTR":
				methods[i] = protocol.CipherAES192CTR
			case "AES-256-CTR":
				methods[i] = protocol.CipherAES256CTR
			case "AES-128-OFB":
				methods[i] = protocol.CipherAES128OFB
			case "AES-192-OFB":
				methods[i] = protocol.CipherAES192OFB
			case "AES-256-OFB":
				methods[i] = protocol.CipherAES256OFB
			default:
				logger.Fatalf("unrecognized cipher method: %s", v)
			}
		}
	}

	srv, _ := server.NewServer(&server.Config{
		Host:          host,
		Port:          uint16(port),
		RSAKey:        keyPair,
		CipherMethods: methods,
		Logger:        logger,
	})

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		shuttingDown := false
		for true {
			switch <-sigs {
			case syscall.SIGINT, syscall.SIGTERM:
				if !shuttingDown {
					logger.Info("server shutdown in progress, press ctrl+c again for emergency shutdown")
					shuttingDown = true
					srv.Shutdown()
					os.Exit(0)
				} else {
					logger.Info("emergency shutdown issued")
					os.Exit(0)
				}
			}
		}
	}()

	if err := srv.ListenAndServe(); err != nil {
		logger.Errorf(err.Error())
	}
}

func clientMode() {
	keyPath, err := internal.GetRSAKeyPath()
	if err != nil {
		logger.Fatalf("unable to get RSA key storing path: %s", err)
	}

	keyPair, err := internal.ReadRSAKey(keyPath)
	if err != nil {
		logger.Fatalf("unable tp read RSA key pair: %s\ntry run key-gen first", err)
	}

	dialer := &client.Client{
		Host:   host,
		Port:   uint16(port),
		RSAKey: keyPair,
		Logger: logger,
	}

	switch strings.ToUpper(ciphers) {
	case "PLAINTEXT":
		dialer.CipherMethod = protocol.CipherPlaintext
	case "AES-128-CFB":
		dialer.CipherMethod = protocol.CipherAES128CFB
	case "AES-192-CFB":
		dialer.CipherMethod = protocol.CipherAES192CFB
	case "AES-256-CFB":
		dialer.CipherMethod = protocol.CipherAES256CFB
	case "AES-128-CTR":
		dialer.CipherMethod = protocol.CipherAES128CTR
	case "AES-192-CTR":
		dialer.CipherMethod = protocol.CipherAES192CTR
	case "AES-256-CTR":
		dialer.CipherMethod = protocol.CipherAES256CTR
	case "AES-128-OFB":
		dialer.CipherMethod = protocol.CipherAES128OFB
	case "AES-192-OFB":
		dialer.CipherMethod = protocol.CipherAES192OFB
	case "AES-256-OFB":
		dialer.CipherMethod = protocol.CipherAES256OFB
	default:
		logger.Fatalf("unrecognized cipher method: %s", ciphers)
	}

	srv := socks5.NewServer(&socks5.Config{
		Host:   socks5Host,
		Port:   uint16(socks5Port),
		Dialer: dialer,
		Logger: logger,
	})

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		shuttingDown := false
		for true {
			switch <-sigs {
			case syscall.SIGINT, syscall.SIGTERM:
				if !shuttingDown {
					logger.Info("client shutdown in progress, press ctrl+c again for emergency shutdown")
					shuttingDown = true
					srv.Shutdown()
					os.Exit(0)
				} else {
					logger.Info("emergency shutdown issued")
					os.Exit(0)
				}
			}
		}
	}()

	if err := srv.ListenAndServe(); err != nil {
		logger.Errorf(err.Error())
	}
}

func keyGenMode() {
	logger.Info("Generating public/private rsa key pair...")
	keyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Fatalf("unable to generate key pair: %s", err)
	}

	keyPath, err := internal.GetRSAKeyPath()
	if err != nil {
		logger.Fatalf("unable to get RSA key storing path: %s", err)
	}

	err = internal.WriteRSAKey(keyPath, keyPair)
	if err != nil {
		logger.Fatalf("unable to write key pair", err)
	}

	logger.Infof("Done. PEM encoded key pair wrote to %s", keyPath)
}