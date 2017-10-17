package util

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

type Addr struct {
	ATyp   byte
	IP     net.IP
	Domain string
	Port   uint16
}

func NewAddr() *Addr {
	return &Addr{
		ATyp: ADDR_TYP_IPV4,
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
	case ADDR_TYP_IPV4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(reader, addr, len(addr)); err != nil {
			return nil, err
		}

		a.ATyp = ADDR_TYP_IPV4
		a.IP = addr

	case ADDR_TYP_IPV6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(reader, addr, len(addr)); err != nil {
			return nil, err
		}

		a.ATyp = ADDR_TYP_IPV6
		a.IP = addr

	case ADDR_TYP_DOMAIN:
		domainLen := []byte{0x00}
		if _, err := reader.Read(domainLen); err != nil {
			return nil, err
		}

		domain := make([]byte, int(domainLen[0]))
		if _, err := io.ReadAtLeast(reader, domain, int(domainLen[0])); err != nil {
			return nil, err
		}

		a.ATyp = ADDR_TYP_DOMAIN
		a.Domain = string(domain)

		// some SOCKS5 clients don't necessarily follow the rule,
		// ip address are sometimes encoded in string, and AType == 0x03
		ip := net.ParseIP(a.Domain)
		if ip != nil {
			a.IP = ip
			if ip.To4() != nil {
				a.ATyp = ADDR_TYP_IPV4
			} else {
				a.ATyp = ADDR_TYP_IPV6
			}
		}

	default:
		return nil, fmt.Errorf(ERR_TPL_SUPPORTED_ADDR_TYPE, Type[0])
	}

	portBuf := []byte{0x00, 0x00}
	if _, err := io.ReadAtLeast(reader, portBuf, 2); err != nil {
		return nil, err
	}
	a.Port = (uint16(portBuf[0]) << 8) | uint16(portBuf[1])

	return a, nil
}

func (a *Addr) Build() ([]byte, error) {
	var host []byte

	switch a.ATyp {
	case ADDR_TYP_IPV4:
		host = []byte(a.IP.To4())

	case ADDR_TYP_IPV6:
		host = []byte(a.IP.To16())

	case ADDR_TYP_DOMAIN:
		host = append([]byte{byte(len(a.Domain))}, a.Domain...)

	default:
		return nil, fmt.Errorf(ERR_TPL_SUPPORTED_ADDR_TYPE, a.ATyp)
	}

	buf := make([]byte, 1+len(host)+2)
	buf[0] = a.ATyp
	copy(buf[1:], host)
	buf[1+len(host)] = byte(a.Port >> 8)
	buf[1+len(host)+1] = byte(a.Port & 0xff)

	return buf, nil
}

func (a Addr) String() string {
	switch a.ATyp {
	case ADDR_TYP_IPV4:
		return fmt.Sprintf("%s:%d", a.IP, a.Port)

	case ADDR_TYP_IPV6:
		return fmt.Sprintf("[%s]:%d", a.IP, a.Port)

	case ADDR_TYP_DOMAIN:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)

	default:
		// this should not happen anyway...
		return fmt.Sprintf(ERR_TPL_SUPPORTED_ADDR_TYPE, a.ATyp)
	}
}
