// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	UOTHeaderLen = 2
	UOTPacketMax = 1<<16 - 1
)

var ErrInvalidUOTPacket = errors.New("nowhere: invalid UoT packet")

func EncodeUOTHeader(payloadLength int) ([UOTHeaderLen]byte, error) {
	var header [UOTHeaderLen]byte
	if payloadLength < 0 || payloadLength > UOTPacketMax {
		return header, ErrInvalidUOTPacket
	}
	binary.BigEndian.PutUint16(header[:], uint16(payloadLength))
	return header, nil
}

func WriteUOTPacket(writer io.Writer, payload []byte) error {
	header, err := EncodeUOTHeader(len(payload))
	if err != nil {
		return err
	}
	if err = writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

// ReadUOTPacket reads one packet into output. A clean EOF before the next
// length header returns io.EOF; a partial header or payload returns
// io.ErrUnexpectedEOF through io.ReadFull.
func ReadUOTPacket(reader io.Reader, output []byte) (int, error) {
	var header [UOTHeaderLen]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length > len(output) {
		return 0, io.ErrShortBuffer
	}
	if length == 0 {
		return 0, nil
	}
	_, err := io.ReadFull(reader, output[:length])
	return length, err
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
