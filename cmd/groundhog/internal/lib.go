package internal

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"os/user"
)

// GetRSAKeyPath returns a default file storing user RSA key pair. On *nix,
// it's ~/.groundhog/id_rsa. On Windows, it's C:\Users\<username>\.groundhog\
// id_rsa.
func GetRSAKeyPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return filepath.Join(usr.HomeDir, ".groundhog", "id_rsa"), nil
}

// ReadRSAKey returns user RSA key pair storing in giving path.
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

// WriteRSAKey store an RSA key pair to giving path.
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

