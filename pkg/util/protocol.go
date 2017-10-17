// protocol.go contains sets of constants use in various protocols, including GROUNDHOG SOCKS5.
// Different protocols may share constants for similar purposes

package util

const (
	ADDR_TYP_IPV4   byte = 0x01
	ADDR_TYP_DOMAIN byte = 0x03
	ADDR_TYP_IPV6   byte = 0x04

	REP_SUCCEEDED              byte = 0x00
	REP_GENERAL_FAILURE        byte = 0x01
	REP_NOT_ALLOW_BYRULESET    byte = 0x02
	REP_NETWORK_UNREACHABLE    byte = 0x03
	REP_HOST_UNREACHABLE       byte = 0x04
	REP_CONN_REFUSED           byte = 0x05
	REP_TTL_EXPIRED            byte = 0x06
	REP_CMD_NOT_SUPPORTED      byte = 0x07
	REP_ADDR_TYP_NOT_SUPPORTED byte = 0x08

	SOCKS_AUTH_NO_AUTH            byte = 0x00
	SOCKS_AUTH_GSSAPI             byte = 0x01
	SOCKS_AUTH_USER_PASS          byte = 0x02
	SOCKS_AUTH_USER_NO_ACCEPTABLE byte = 0xff

	SOCKS_CMD_CONNECT       byte = 0x01
	SOCKS_CMD_BIND          byte = 0x02
	SOCKS_CMD_UDP_ASSOCIATE byte = 0x03

	CIPHER_PLAINTEXT   byte = 0x00
	CIPHER_AES_128_CBF byte = 0x01
	CIPHER_AES_192_CBF byte = 0x02
	CIPHER_AES_256_CBF byte = 0x03
)
