// errortpl.go contains template strings of errors that would be used.

package util

const (
	ERR_TPL_SRV_INVALID_HOST    = "invalid listening host %s"
	ERR_TPL_SRV_INVALID_PORT    = "invalid listening port %d"
	ERR_TPL_SRV_INVALID_CB      = "invalid onConn callback"
	ERR_TPL_SRV_ALREADY_STARTED = "server has already started"
	ERR_TPL_SRV_ALREADY_STOPPED = "server has already stopped"

	ERR_TPL_SOCKS_UNSUPPORTED_VER           = "unsupported SOCKS version %d"
	ERR_TPL_SOCKS_UNSUPPORTED_CMD           = "unsupported SOCKS command %#x"
	ERR_TPL_SOCKS_NO_ACCEPTABLE_AUTH_METHOD = "no supported SOCKS authentication method"
	ERR_TPL_SOCKS_ILLEGAL_RSV_FIELD         = "illegal SOCKS reserved field, expect 0x00, got %#x"
	ERR_TPL_SOCKS_GENERAL_FAILURE           = "general SOCKS server failure"
	ERR_TPL_SOCKS_NOT_ALLOWED_BY_RULESET    = "connection not allowed by ruleset"

	ERR_TPL_SUPPORTED_ADDR_TYPE = "unsupported address type %#x"

	ERR_TPL_CLIENT_NOT_INIT = "local client not initialized"
)
