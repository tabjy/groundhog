// Package protocol provides common components used in SOCKS5/Groundhog
// implementations. Still, these components can also be used for non-
// SOCKS5/Groundhog protocols.
package protocol

import "strings"

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
		return 0x00
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return 0x03
	case strings.Contains(msg, "connection refused"):
		return 0x05
	case strings.Contains(msg, "connection timed out"):
		return 0x06
	default:
		return 0x01
	}
}
