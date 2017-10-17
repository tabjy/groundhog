// helper.go contains series of convenient functions to be invoked from packages.
// Only functions should be exported from this file.

package util

import "net"

func GetAvailPort() (port int, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr, _ := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}
