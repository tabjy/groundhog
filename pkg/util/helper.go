// helper.go contains series of convenient functions to be invoked from packages.
// Only functions should be exported from this file.

package util

import (
	"net"
	"io"
	"strings"
	"path/filepath"
	"os/user"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"os"
)

func GetAvailPort() (port int, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr, _ := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

type closeWriter interface {
	CloseWrite() error
}
type closeReader interface {
	CloseRead() error
}

func IOCopy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	if tcpConn, ok := src.(closeReader); ok {
		tcpConn.CloseRead()
	}
	errCh <- err
}

func ConnErrToRep(err error) byte {
	if err == nil {
		return REP_SUCCEEDED
	}

	errMsg := err.Error()
	switch  {
	case strings.Contains(errMsg, "no such host"):
		return REP_HOST_UNREACHABLE
	case strings.Contains(errMsg, "connection refused"):
		return REP_CONN_REFUSED
	case strings.Contains(errMsg, "connection timed out"):
		return REP_TTL_EXPIRED
	default:
		return REP_GENERAL_FAILURE
	}
}


func GetRSAKeyPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return filepath.Join(usr.HomeDir, ".groundhog", "id_rsa"), nil
}

func ReadRSAKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)

	keyPair, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func WriteRSAKey(path string, keyPair *rsa.PrivateKey) (error) {
	folder := filepath.Join(path, "..")
	os.Mkdir(folder, 0700)

	pemString := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	})

	if err := ioutil.WriteFile(path, pemString, 0600); err != nil {
		return err
	}

	return nil
}