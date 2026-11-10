// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	DefaultALPN         = "nw3"
	FlowHeaderLen       = 1
	SetupResultLen      = 1
	MaxFlowID           = 1<<30 - 1
	TargetATYPIPv4      = 0x01
	TargetATYPDomain    = 0x03
	TargetATYPIPv6      = 0x04
	TargetMaxDomainLen  = 253
	TargetMaxEncodedLen = 1 + 1 + TargetMaxDomainLen + 2
)

var (
	ErrInvalidFlowHeader  = errors.New("nowhere: invalid flow start")
	ErrInvalidTarget      = errors.New("nowhere: invalid target")
	ErrInvalidSetupResult = errors.New("nowhere: invalid setup result")
)

type FlowID uint32
type FlowKind uint8

const (
	FlowKindTCP FlowKind = iota
	FlowKindUDP
)

type Carrier uint8

const (
	CarrierTLSTCP Carrier = iota
	CarrierQUIC
)

type FlowHeader struct{ Kind FlowKind }

func EncodeFlowHeader(header FlowHeader) ([FlowHeaderLen]byte, error) {
	if header.Kind > FlowKindUDP {
		return [FlowHeaderLen]byte{}, ErrInvalidFlowHeader
	}
	return [FlowHeaderLen]byte{byte(header.Kind)}, nil
}
func DecodeFlowHeader(input []byte) (FlowHeader, error) {
	if len(input) != 1 {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	return FlowHeader{Kind: FlowKind(input[0] & 1)}, nil
}
func ReadFlowHeader(reader io.Reader) (FlowHeader, error) {
	var b [1]byte
	if _, err := io.ReadFull(reader, b[:]); err != nil {
		return FlowHeader{}, err
	}
	return DecodeFlowHeader(b[:])
}
func UDPFlowID(streamID uint64) (FlowID, error) {
	if streamID&3 != 0 {
		return 0, ErrInvalidFlowHeader
	}
	id := (streamID >> 2) + 1
	if id == 0 || id > MaxFlowID {
		return 0, ErrInvalidFlowHeader
	}
	return FlowID(id), nil
}

type SetupResult uint8

const (
	SetupReady SetupResult = iota
	SetupInvalidRequest
	SetupFlowLimit
	SetupDialFailed
	SetupInternalError
)

func (result SetupResult) Validate() error {
	if result > SetupInternalError {
		return ErrInvalidSetupResult
	}
	return nil
}

func DecodeSetupResult(input []byte) (SetupResult, error) {
	if len(input) != SetupResultLen {
		return 0, ErrInvalidSetupResult
	}
	result := SetupResult(input[0])
	if err := result.Validate(); err != nil {
		return 0, err
	}
	return result, nil
}

func ReadSetupResult(reader io.Reader) (SetupResult, error) {
	var input [SetupResultLen]byte
	if _, err := io.ReadFull(reader, input[:]); err != nil {
		return 0, fmt.Errorf("nowhere: read setup result: %w", err)
	}
	return DecodeSetupResult(input[:])
}

func WriteSetupResult(writer io.Writer, result SetupResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	return writeFull(writer, []byte{byte(result)})
}

func EncodeTarget(target M.Socksaddr, output []byte) (int, error) {
	target = target.Unwrap()
	if !target.IsValid() || target.Port == 0 {
		return 0, ErrInvalidTarget
	}
	if target.IsIP() {
		if target.Addr.Is4() {
			if len(output) < 7 {
				return 0, io.ErrShortBuffer
			}
			output[0] = TargetATYPIPv4
			address := target.Addr.As4()
			copy(output[1:5], address[:])
			binary.BigEndian.PutUint16(output[5:7], target.Port)
			return 7, nil
		}
		if len(output) < 19 {
			return 0, io.ErrShortBuffer
		}
		output[0] = TargetATYPIPv6
		address := target.Addr.As16()
		copy(output[1:17], address[:])
		binary.BigEndian.PutUint16(output[17:19], target.Port)
		return 19, nil
	}
	host := target.Fqdn
	if err := validateWireDomain(host); err != nil {
		return 0, err
	}
	length := 1 + 1 + len(host) + 2
	if len(output) < length {
		return 0, io.ErrShortBuffer
	}
	output[0] = TargetATYPDomain
	output[1] = byte(len(host))
	copy(output[2:], host)
	binary.BigEndian.PutUint16(output[2+len(host):length], target.Port)
	return length, nil
}

func ReadTarget(reader io.Reader) (M.Socksaddr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(reader, atyp[:]); err != nil {
		return M.Socksaddr{}, fmt.Errorf("nowhere: read target type: %w", err)
	}
	switch atyp[0] {
	case TargetATYPIPv4:
		var input [6]byte
		if _, err := io.ReadFull(reader, input[:]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("nowhere: read IPv4 target: %w", err)
		}
		address := netip.AddrFrom4([4]byte(input[:4]))
		port := binary.BigEndian.Uint16(input[4:])
		if port == 0 {
			return M.Socksaddr{}, ErrInvalidTarget
		}
		return M.SocksaddrFrom(address, port), nil
	case TargetATYPIPv6:
		var input [18]byte
		if _, err := io.ReadFull(reader, input[:]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("nowhere: read IPv6 target: %w", err)
		}
		address := netip.AddrFrom16([16]byte(input[:16]))
		port := binary.BigEndian.Uint16(input[16:])
		if port == 0 {
			return M.Socksaddr{}, ErrInvalidTarget
		}
		return M.SocksaddrFrom(address, port), nil
	case TargetATYPDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("nowhere: read domain length: %w", err)
		}
		if length[0] == 0 || int(length[0]) > TargetMaxDomainLen {
			return M.Socksaddr{}, ErrInvalidTarget
		}
		var input [TargetMaxDomainLen + 2]byte
		encodedLength := int(length[0]) + 2
		if _, err := io.ReadFull(reader, input[:encodedLength]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("nowhere: read domain target: %w", err)
		}
		host := string(input[:encodedLength-2])
		port := binary.BigEndian.Uint16(input[encodedLength-2 : encodedLength])
		if port == 0 {
			return M.Socksaddr{}, ErrInvalidTarget
		}
		if err := validateWireDomain(host); err != nil {
			return M.Socksaddr{}, err
		}
		return M.Socksaddr{Fqdn: host, Port: port}, nil
	default:
		return M.Socksaddr{}, ErrInvalidTarget
	}
}

func validateWireDomain(host string) error {
	if len(host) == 0 || len(host) > TargetMaxDomainLen || strings.HasSuffix(host, ".") {
		return ErrInvalidTarget
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ErrInvalidTarget
		}
		for index := range len(label) {
			character := label[index]
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return ErrInvalidTarget
		}
	}
	return nil
}
