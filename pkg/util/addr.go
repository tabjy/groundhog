package util

import (
	"net"
	"fmt"
	"io"
	"bytes"
)

const (
	ATypIPv4   byte = 0x01
	ATypDomain byte = 0x03
	ATypIPv6   byte = 0x04
)

var (
	errUnsupportedAddrType = fmt.Errorf("unsupported address Typee")
)

type Addr struct {
	ATyp   byte
	IP     net.IP
	Domain string
	Port   uint16
}

func NewAddr() *Addr {
	return &Addr{
		ATyp: ATypIPv4,
		IP:   []byte{0x00, 0x00, 0x00, 0x00},
		Port: 0,
	}
}

func (a *Addr) ParseFromBuffer(buf []byte) (*Addr, error) {
	return a.Parse(bytes.NewReader(buf))
}

func (a *Addr) Parse(reader io.Reader) (*Addr, error) {
	Type := []byte{0x00}
	if _, err := reader.Read(Type); err != nil {
		return nil, err
	}

	switch Type[0] {
	case ATypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(reader, addr, len(addr)); err != nil {
			return nil, err
		}

		a.ATyp = ATypIPv4
		a.IP = addr

	case ATypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(reader, addr, len(addr)); err != nil {
			return nil, err
		}

		a.ATyp = ATypIPv6
		a.IP = addr

	case ATypDomain:
		domainLen := []byte{0x00}
		if _, err := reader.Read(domainLen); err != nil {
			return nil, err
		}

		domain := make([]byte, int(domainLen[0]))
		if _, err := io.ReadAtLeast(reader, domain, int(domainLen[0])); err != nil {
			return nil, err
		}

		a.ATyp = ATypDomain
		a.Domain = string(domain)

		// some SOCKS5 clients don't necessarily follow the rule,
		// ip address are sometimes encoded in string, and AType == 0x03
		ip := net.ParseIP(a.Domain)
		if ip != nil {
			a.IP = ip
			if ip.To4() != nil {
				a.ATyp = ATypIPv4
			} else {
				a.ATyp = ATypIPv6
			}
		}

	default:
		return nil, errUnsupportedAddrType
	}

	portBuf := []byte{0x00, 0x00}
	if _, err := io.ReadAtLeast(reader, portBuf, 2); err != nil {
		return nil, err
	}
	a.Port = (uint16(portBuf[0]) << 8) | uint16(portBuf[1])

	return a, nil
}

func (a *Addr) Build() ([]byte, error) {
	ret := []byte{0x00}
	ret[0] = a.ATyp

	switch a.ATyp {
	case ATypIPv4:
		ret = append(ret, a.IP.To4()...)

	case ATypIPv6:
		ret = append(ret, a.IP.To16()...)

	case ATypDomain:
		ret = append(ret, byte(uint8(len(a.Domain))))
		ret = append(ret, a.Domain...)

	default:
		return nil, errUnsupportedAddrType
	}

	ret = append(ret, []byte{byte(a.Port >> 8), byte(a.Port & 0xff)}...)
	return ret, nil
}

func (a Addr) String() string {
	switch a.ATyp {
	case ATypIPv4:
		return fmt.Sprintf("%s:%d", a.IP, a.Port)

	case ATypIPv6:
		return fmt.Sprintf("[%s]:%d", a.IP, a.Port)

	case ATypDomain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)

	default:
		// this should not happen anyway...
		return fmt.Sprintf(errUnsupportedAddrType.Error())
	}
}
