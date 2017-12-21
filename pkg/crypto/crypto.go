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

	"github.com/tabjy/groundhog/pkg/util"
)

func CreateAESCFBPipe(key []byte, errCh chan error) (plainSide net.Conn, cipherSide net.Conn, err error) {
	return createStreamCipherPipe(key, cipher.NewCFBEncrypter, cipher.NewCFBDecrypter, errCh)
}

func CreateAESCTRPipe(key []byte, errCh chan error) (plainSide net.Conn, cipherSide net.Conn, err error) {
	return createStreamCipherPipe(key, cipher.NewCTR, cipher.NewCTR, errCh)
}

func CreateAESOFBPipe(key []byte, errCh chan error) (plainSide net.Conn, cipherSide net.Conn, err error) {
	return createStreamCipherPipe(key, cipher.NewOFB, cipher.NewOFB, errCh)
}

// Return a duplex pipe. The key argument should be the AES key,
// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func createStreamCipherPipe(key []byte, streamEncryptor, streamDecryptor func(block cipher.Block, iv []byte) cipher.Stream, errCh chan error) (plainSide net.Conn, cipherSide net.Conn, err error) {
	// same session key for both direction
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	plainSideInner, plainSideOuter := net.Pipe()
	cipherSideInner, cipherSideOuter := net.Pipe()

	go func() {
		// iv should always be AES Block Size, 16 bytes
		encryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, encryptIV); err != nil {
			errCh <- err
		}
		if _, err := cipherSideInner.Write(encryptIV); err != nil {
			errCh <- err
		}
		encryptStream := streamEncryptor(block, encryptIV)
		encryptor := &cipher.StreamWriter{S: encryptStream, W: cipherSideInner}
		util.IOCopy(encryptor, plainSideInner, errCh)
	}()

	go func() {
		// two different IV's should be used, to prevent attack if connecting to a ping-pong server
		decryptIV := make([]byte, aes.BlockSize)
		if _, err := io.ReadAtLeast(cipherSideInner, decryptIV, aes.BlockSize); err != nil {
			errCh <- err
		}
		decryptStream := streamDecryptor(block, decryptIV)
		decryptor := &cipher.StreamReader{S: decryptStream, R: cipherSideInner}

		util.IOCopy(plainSideInner, decryptor, errCh)
	}()

	return plainSideOuter, cipherSideOuter, nil
}
