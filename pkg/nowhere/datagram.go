// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"encoding/binary"
	"errors"
)

const (
	UDPHeaderLen         = 4
	UDPFragmentHeaderLen = 12
	UDPPacketMax         = 1<<16 - 1
)

var ErrInvalidUDPFrame = errors.New("nowhere: invalid UDP frame")

type UDPFrameType uint8

const (
	UDPFrameData UDPFrameType = iota
	UDPFrameFragment
	UDPFrameClose
)

type UDPFrame struct {
	Type          UDPFrameType
	FlowID        FlowID
	PacketID      uint32
	FragmentIndex uint8
	FragmentCount uint8
	TotalLength   uint16
	Payload       []byte
}

func DecodeUDPFrame(input []byte) (UDPFrame, error) {
	if len(input) < UDPHeaderLen {
		return UDPFrame{}, ErrInvalidUDPFrame
	}
	word := binary.BigEndian.Uint32(input[:4])
	flowID := FlowID(word & MaxFlowID)
	if flowID == 0 || flowID > MaxFlowID {
		return UDPFrame{}, ErrInvalidUDPFrame
	}
	frameType := UDPFrameType(word >> 30)
	switch frameType {
	case UDPFrameData:
		if len(input)-UDPHeaderLen > UDPPacketMax {
			return UDPFrame{}, ErrInvalidUDPFrame
		}
		return UDPFrame{Type: frameType, FlowID: flowID, Payload: input[UDPHeaderLen:]}, nil
	case UDPFrameFragment:
		if len(input) <= UDPFragmentHeaderLen {
			return UDPFrame{}, ErrInvalidUDPFrame
		}
		frame := UDPFrame{
			Type:          frameType,
			FlowID:        flowID,
			PacketID:      binary.BigEndian.Uint32(input[4:8]),
			FragmentIndex: input[8],
			FragmentCount: input[9],
			TotalLength:   binary.BigEndian.Uint16(input[10:12]),
			Payload:       input[UDPFragmentHeaderLen:],
		}
		if !validUDPFragment(frame) {
			return UDPFrame{}, ErrInvalidUDPFrame
		}
		return frame, nil
	case UDPFrameClose:
		if len(input) != UDPHeaderLen {
			return UDPFrame{}, ErrInvalidUDPFrame
		}
		return UDPFrame{Type: frameType, FlowID: flowID}, nil
	default:
		return UDPFrame{}, ErrInvalidUDPFrame
	}
}

func EncodeUDPData(flowID FlowID, payload []byte) ([]byte, error) {
	if flowID == 0 || flowID > MaxFlowID || len(payload) > UDPPacketMax {
		return nil, ErrInvalidUDPFrame
	}
	output := make([]byte, UDPHeaderLen+len(payload))
	binary.BigEndian.PutUint32(output[:4], uint32(flowID))
	copy(output[UDPHeaderLen:], payload)
	return output, nil
}

func EncodeUDPClose(flowID FlowID) ([UDPHeaderLen]byte, error) {
	var output [UDPHeaderLen]byte
	if flowID == 0 || flowID > MaxFlowID {
		return output, ErrInvalidUDPFrame
	}
	binary.BigEndian.PutUint32(output[:4], uint32(UDPFrameClose)<<30|uint32(flowID))
	return output, nil
}

func EncodeUDPFragments(flowID FlowID, packetID uint32, payload []byte, maxDatagramSize int) ([][]byte, error) {
	if flowID == 0 || flowID > MaxFlowID || len(payload) > UDPPacketMax || maxDatagramSize < UDPHeaderLen {
		return nil, ErrInvalidUDPFrame
	}
	if len(payload)+UDPHeaderLen <= maxDatagramSize {
		frame, err := EncodeUDPData(flowID, payload)
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	}
	if packetID == 0 || len(payload) == 0 || maxDatagramSize <= UDPFragmentHeaderLen {
		return nil, ErrInvalidUDPFrame
	}
	fragmentPayloadSize := maxDatagramSize - UDPFragmentHeaderLen
	fragmentCount := (len(payload) + fragmentPayloadSize - 1) / fragmentPayloadSize
	if fragmentCount < 2 || fragmentCount > 255 {
		return nil, ErrInvalidUDPFrame
	}
	frames := make([][]byte, fragmentCount)
	for index := range fragmentCount {
		begin := index * fragmentPayloadSize
		end := min(begin+fragmentPayloadSize, len(payload))
		frame := make([]byte, UDPFragmentHeaderLen+end-begin)
		binary.BigEndian.PutUint32(frame[:4], uint32(UDPFrameFragment)<<30|uint32(flowID))
		binary.BigEndian.PutUint32(frame[4:8], packetID)
		frame[8] = byte(index)
		frame[9] = byte(fragmentCount)
		binary.BigEndian.PutUint16(frame[10:12], uint16(len(payload)))
		copy(frame[UDPFragmentHeaderLen:], payload[begin:end])
		frames[index] = frame
	}
	return frames, nil
}

func validUDPFragment(frame UDPFrame) bool {
	return frame.PacketID != 0 &&
		frame.FragmentCount >= 2 &&
		frame.FragmentIndex < frame.FragmentCount &&
		frame.TotalLength != 0 &&
		len(frame.Payload) != 0 &&
		len(frame.Payload)+int(frame.FragmentCount)-1 <= int(frame.TotalLength)
}
