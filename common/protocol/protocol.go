// Package protocol provides common components used in SOCKS5/Groundhog
// implementations. Still, these components can also be used for non-
// SOCKS5/Groundhog protocols.
package protocol

import (
	"strings"
	"errors"
)

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
//	 	0x03 network unreachable
// 		0x04 host unreachable
// 		0x05 connection refused
// 		0x06 TTL expired
// 		0x07 command not supported
// 		0x08 address type not supported
// 		0x09 to 0xFF for additional groundhog reply code
func ErrToRep(err error) byte {
	if err == nil {
		return RepSucceeded
	}

	msg := err.Error()
	// TODO: don't hard code these values
	switch {
	case strings.Contains(msg, "general server failure"):
		return RepGeneralFailure
	case strings.Contains(msg, "connection not allowed by ruleset"):
		return RepNotAllowByRuleset
	case strings.Contains(msg, "network unreachable"):
		return RepNetworkUnreachable
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "host unreachable"):
		return RepNetworkUnreachable
	case strings.Contains(msg, "connection refused"):
		return RepConnectionRefused
	case strings.Contains(msg, "connection timed out"), strings.Contains(msg, "TTL expired"):
		return RepTTLExpired
	case strings.Contains(msg, "command not supported"):
		return RepCommandNotSupported
	case strings.Contains(msg, "address type not supported"):
		return RepAddressTypeNotSupported
	case strings.Contains(msg, "cipher not supported"):
		return RepCipherNotSupported
	default:
		return RepGeneralFailure
	}
}

func RepToErr(rep byte) error {
	// TODO: don't hard code these values
	switch rep {
	case RepSucceeded:
		return nil
	case RepGeneralFailure:
		return errors.New("general server failure")
	case RepNotAllowByRuleset:
		return errors.New("connection not allowed by ruleset")
	case RepNetworkUnreachable:
		return errors.New("network unreachable")
	case RepHostUnreachable:
		return errors.New("host unreachable")
	case RepConnectionRefused:
		return errors.New("connection refused")
	case RepTTLExpired:
		return errors.New("TTL expired")
	case RepCommandNotSupported:
		return errors.New("command not supported")
	case RepAddressTypeNotSupported:
		return errors.New("address type not supported")
	case RepCipherNotSupported:
		return errors.New("cipher not supported")
	default:
		return errors.New("invalid reply code")
	}
}