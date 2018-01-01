package crypto

import (
	"crypto/cipher"
	"io"
	"errors"
	"crypto/aes"
)

type readWriter struct {
	io.Reader
	io.Writer
}

type StreamEncryptDecrypter struct {
	EncryptKey []byte
	DecryptKey []byte

	StreamEncrypter func(block cipher.Block, iv []byte) cipher.Stream
	StreamDecrypter func(block cipher.Block, iv []byte) cipher.Stream

	EncryptStream cipher.Stream
	DecryptStream cipher.Stream

	EncryptIV []byte
	DecryptIV []byte
}

func (ed *StreamEncryptDecrypter) initCipherStream() error {
	if ed.EncryptStream == nil {
		if ed.StreamEncrypter == nil || ed.EncryptKey == nil {
			return errors.New("at least one of EncryptStream OR EncryptKey and StreamEncrypter must be set")
		}

		if ed.EncryptIV == nil {
			return errors.New("encrypt IV must be set")
		}

		block, err := aes.NewCipher(ed.EncryptKey)
		if err != nil {
			return err
		}
		ed.EncryptStream = ed.StreamEncrypter(block, ed.EncryptIV)
	}

	if ed.DecryptStream == nil {
		if ed.StreamDecrypter == nil || ed.DecryptKey == nil {
			return errors.New("at least one of DecryptStream OR DecryptKey and StreamDecrypter must be set")
		}

		if ed.DecryptIV == nil {
			return errors.New("decrypt IV must be set")
		}

		block, err := aes.NewCipher(ed.DecryptKey)
		if err != nil {
			return err
		}
		ed.DecryptStream = ed.StreamDecrypter(block, ed.DecryptIV)
	}

	return nil
}

// Ciphertext takes a duplex io.ReadWriter with plaintext, encrypt and return a
// corresponding ciphertext io.ReadWriter. Any ciphertext write to returned
// io.ReadWriter will be decrypted and write to plaintext. Any plaintext read
// from plaintext will be encrypted and write to returned io.ReadWriter.
func (ed *StreamEncryptDecrypter) Ciphertext(plaintext io.ReadWriter) (io.ReadWriter, error) {
	if err := ed.initCipherStream(); err != nil {
		return nil, err
	}

	// logic here could be simpler if golang has a built-in duplex pipe.
	// net.Pipe is a solution, but seems too heavy,
	// with possibility of causing memory leak if not careful
	cipherRdIn, cipherWtOut := io.Pipe()
	cipherRdOut, cipherWtIn := io.Pipe()

	ciphertext := &readWriter{
		cipherRdOut,
		cipherWtOut,
	}

	// decrypt ciphertext to plaintext
	go func() {
		decrypter := &cipher.StreamReader{S: ed.DecryptStream, R: cipherRdIn}
		io.Copy(plaintext, decrypter)
		cipherWtOut.Close()
		cipherRdIn.Close()
	}()

	// encrypt plaintext to ciphertext
	go func() {
		encrypter := &cipher.StreamWriter{S: ed.EncryptStream, W: cipherWtIn}
		io.Copy(encrypter, plaintext)
		cipherWtIn.Close()
		cipherRdOut.Close()
	}()

	return ciphertext, nil
}

// Plaintext takes a duplex io.ReadWriter with ciphertext, decrypt and return a
// corresponding plaintext io.ReadWriter. Any plaintext write to returned
// io.ReadWriter will be encrypted and write to ciphertext. Any ciphertext read
// from ciphertext will be decrypted and write to returned io.ReadWriter.
func (ed *StreamEncryptDecrypter) Plaintext(ciphertext io.ReadWriter) (io.ReadWriter, error) {
	if err := ed.initCipherStream(); err != nil {
		return nil, err
	}

	plainRdIn, plainWtOut := io.Pipe()
	plainRdOut, plainWtIn := io.Pipe()

	plaintext := &readWriter{
		plainRdOut,
		plainWtOut,
	}

	// encrypt plaintext to ciphertext
	go func() {
		encrypter := &cipher.StreamWriter{S: ed.EncryptStream, W: ciphertext}
		io.Copy(encrypter, plainRdIn)
		plainWtIn.Close()
		plainRdOut.Close()
	}()

	// decrypt ciphertext to plaintext
	go func() {
		decrypter := &cipher.StreamReader{S: ed.DecryptStream, R: ciphertext}
		io.Copy(plainWtIn, decrypter)
		plainWtOut.Close()
		plainRdIn.Close()
	}()

	return plaintext, nil
}