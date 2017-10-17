// crypto.go contains set of stream ciphers packaged into pipes to create
// transparent interface for callers. ie. local and remote packages.
// input symmetric encryption key only, iv's would be automatically handled

package crypto

import (
	"net"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"crypto/rand"
)

// Return a duplex pipe. The key argument should be the AES key,
// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func CreateAESCFBPipe(key []byte, errCh chan error) (net.Conn, net.Conn, error) {
	// same session key for both direction
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	plainSideInner, plainSideOuter := net.Pipe()
	cipherSideInner, cipherSideOuter := net.Pipe()

	// iv should always be AES Block Size, 16 bytes
	// two different IV's should be used, to prevent attack if connecting to a ping-pong server
	go func() {
		encryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
			errCh <- err
		}
		if _, err := cipherSideInner.Write(encryptIV); err != nil {
			errCh <- err
		}
		encryptStream := cipher.NewCFBEncrypter(block, encryptIV)
		encryptor := &cipher.StreamWriter{S: encryptStream, W: cipherSideInner}
		io.Copy(encryptor, plainSideInner)
	}()


	go func() {
		decryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadAtLeast(cipherSideInner, decryptIV, aes.BlockSize); err != nil {
			errCh <- err
		}
		decryptStream := cipher.NewCFBDecrypter(block, decryptIV)
		decryptor := &cipher.StreamReader{S: decryptStream, R: cipherSideInner}
		io.Copy(plainSideInner, decryptor)
	}()

	return plainSideOuter, cipherSideOuter, nil
}