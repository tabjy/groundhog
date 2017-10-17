package crypto

const (
	// TODO: add more cipher method, and those with authentication
	Method_PLAINTEXT  byte = 0x00
	Method_AES_128_CBF byte = 0x01
	Method_AES_192_CBF byte = 0x02
	Method_AES_256_CBF byte = 0x03
)