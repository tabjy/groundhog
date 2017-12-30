// Package protocol provides common components used in SOCKS5/Groundhog
// implementations. Still, these components can also be used for non-
// SOCKS5/Groundhog protocols.
package protocol

import "strings"

// Address type indication byte used for SOCKS5 and Groundhog protocol
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

// Reply code indication any error
const (
	// 0x00 to 0x08 are SOCKS5 REP code, which Groundhog is also compatible
	RepSucceeded               byte = 0x00
	RepGeneralFailure          byte = 0x01
	RepNotAllowByRuleset       byte = 0x02
	RepNetworkUnreachable      byte = 0x03
	RepHostUnreachable         byte = 0x04
	RepConnectionRefused       byte = 0x05
	RepTTLExpired              byte = 0x06
	RepCommandNotSupported     byte = 0x07
	RepAddressTypeNotSupported byte = 0x08

	// additional rep code for groundhog protocol
	RepCipherNotSupported byte = 0x09
)

// Cipher method indication byte used by Groundhog protocol
const (
	CipherPlaintext byte = 0x00
	CipherAES128CFB byte = 0x01
	CipherAES192CFB byte = 0x02
	CipherAES256CFB byte = 0x03
	CipherAES128CTR byte = 0x04
	CipherAES192CTR byte = 0x05
	CipherAES256CTR byte = 0x06
	CipherAES128OFB byte = 0x07
	CipherAES192OFB byte = 0x08
	CipherAES256OFB byte = 0x09
)

// ErrToRepCode convert error to SOCKS/Groundhog protocol reply code by
// matching string pattern in error message.
//		0x00 succeeded
// 		0x01 general server failure
//		0x02 connection not allowed by ruleset
//	 	0x03 Network unreachable
// 		0x04 Host unreachable
// 		0x05 Connection refused
// 		0x06 TTL expired
// 		0x07 Command not supported
// 		0x08 Address type not supported
// 		0x09 to 0xFF for additional groundhog reply code
func ErrToRep(err error) byte {
	if err == nil {
		return RepSucceeded
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return RepNetworkUnreachable
	case strings.Contains(msg, "connection refused"):
		return RepConnectionRefused
	case strings.Contains(msg, "connection timed out"):
		return RepTTLExpired
	default:
		return RepGeneralFailure
	}
}
