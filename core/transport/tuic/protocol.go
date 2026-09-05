// Derived from wyx2685/Xray-core 83ad74c46335, transport/internet/tuic.
// Licensed under MPL-2.0; see LICENSE and README.md in this directory.

package tuic

import (
	"encoding/binary"
	"io"
	stdnet "net"

	xnet "github.com/xtls/xray-core/common/net"
)

const (
	tuicVersion byte = 5

	commandAuthenticate byte = 0
	commandConnect      byte = 1
	commandPacket       byte = 2
	commandDissociate   byte = 3
	commandHeartbeat    byte = 4
)

const (
	TUICVersion byte = tuicVersion

	TUICCommandAuthenticate byte = commandAuthenticate
	TUICCommandConnect      byte = commandConnect
	TUICCommandPacket       byte = commandPacket
	TUICCommandDissociate   byte = commandDissociate
	TUICCommandHeartbeat    byte = commandHeartbeat
)

const authenticateLen = 2 + 16 + 32

const (
	addressTypeDomain byte = 0x00
	addressTypeIPv4   byte = 0x01
	addressTypeIPv6   byte = 0x02
	addressTypeNone   byte = 0xff
)

func ReadDestination(reader io.Reader, network xnet.Network) (xnet.Destination, error) {
	return readDestination(reader, network)
}

func readDestination(reader io.Reader, network xnet.Network) (xnet.Destination, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return xnet.Destination{}, err
	}
	switch addressType[0] {
	case addressTypeNone:
		return xnet.Destination{}, nil
	case addressTypeDomain:
		var domainLength [1]byte
		if _, err := io.ReadFull(reader, domainLength[:]); err != nil {
			return xnet.Destination{}, err
		}
		domain := make([]byte, int(domainLength[0]))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return xnet.Destination{}, err
		}
		port, err := readPort(reader)
		if err != nil {
			return xnet.Destination{}, err
		}
		return destinationFromAddress(network, xnet.DomainAddress(string(domain)), port), nil
	case addressTypeIPv4:
		ip := make([]byte, stdnet.IPv4len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return xnet.Destination{}, err
		}
		port, err := readPort(reader)
		if err != nil {
			return xnet.Destination{}, err
		}
		return destinationFromAddress(network, xnet.IPAddress(ip), port), nil
	case addressTypeIPv6:
		ip := make([]byte, stdnet.IPv6len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return xnet.Destination{}, err
		}
		port, err := readPort(reader)
		if err != nil {
			return xnet.Destination{}, err
		}
		return destinationFromAddress(network, xnet.IPAddress(ip), port), nil
	default:
		return xnet.Destination{}, io.ErrUnexpectedEOF
	}
}

func writeDestination(writer io.Writer, destination xnet.Destination) error {
	if !destination.IsValid() {
		_, err := writer.Write([]byte{addressTypeNone})
		return err
	}
	switch {
	case destination.Address.Family().IsDomain():
		domain := destination.Address.Domain()
		if len(domain) > 255 {
			return io.ErrShortBuffer
		}
		if _, err := writer.Write([]byte{addressTypeDomain, byte(len(domain))}); err != nil {
			return err
		}
		if _, err := writer.Write([]byte(domain)); err != nil {
			return err
		}
	case destination.Address.Family().IsIPv4():
		if _, err := writer.Write([]byte{addressTypeIPv4}); err != nil {
			return err
		}
		if _, err := writer.Write(destination.Address.IP().To4()); err != nil {
			return err
		}
	case destination.Address.Family().IsIPv6():
		if _, err := writer.Write([]byte{addressTypeIPv6}); err != nil {
			return err
		}
		if _, err := writer.Write(destination.Address.IP().To16()); err != nil {
			return err
		}
	default:
		_, err := writer.Write([]byte{addressTypeNone})
		return err
	}
	return binary.Write(writer, binary.BigEndian, uint16(destination.Port))
}

func destinationLen(destination xnet.Destination) int {
	if !destination.IsValid() {
		return 1
	}
	switch {
	case destination.Address.Family().IsDomain():
		return 1 + 1 + len(destination.Address.Domain()) + 2
	case destination.Address.Family().IsIPv4():
		return 1 + stdnet.IPv4len + 2
	case destination.Address.Family().IsIPv6():
		return 1 + stdnet.IPv6len + 2
	default:
		return 1
	}
}

func readPort(reader io.Reader) (xnet.Port, error) {
	var port uint16
	if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
		return 0, err
	}
	return xnet.Port(port), nil
}

func destinationFromAddress(network xnet.Network, address xnet.Address, port xnet.Port) xnet.Destination {
	switch network {
	case xnet.Network_TCP:
		return xnet.TCPDestination(address, port)
	case xnet.Network_UDP:
		return xnet.UDPDestination(address, port)
	default:
		return xnet.Destination{}
	}
}
