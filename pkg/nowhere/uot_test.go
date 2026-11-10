// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestUOTMatchesUpstreamVectors(t *testing.T) {
	var wire bytes.Buffer
	for _, payload := range [][]byte{nil, []byte("abc")} {
		if err := WriteUOTPacket(&wire, payload); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := wire.Bytes(), []byte{0, 0, 0, 3, 'a', 'b', 'c'}; !bytes.Equal(got, want) {
		t.Fatalf("wire=%x want=%x", got, want)
	}
	output := make([]byte, UOTPacketMax)
	if length, err := ReadUOTPacket(&wire, output); err != nil || length != 0 {
		t.Fatalf("empty length=%d err=%v", length, err)
	}
	if length, err := ReadUOTPacket(&wire, output); err != nil || string(output[:length]) != "abc" {
		t.Fatalf("payload=%q err=%v", output[:length], err)
	}
	if _, err := ReadUOTPacket(&wire, output); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF err=%v", err)
	}
}

func TestUOTRejectsTruncation(t *testing.T) {
	output := make([]byte, 16)
	if _, err := ReadUOTPacket(bytes.NewReader([]byte{0}), output); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("header err=%v", err)
	}
	if _, err := ReadUOTPacket(bytes.NewReader([]byte{0, 2, 1}), output); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("payload err=%v", err)
	}
}

func TestUOTMaximumPacket(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, UOTPacketMax)
	var wire bytes.Buffer
	if err := WriteUOTPacket(&wire, payload); err != nil {
		t.Fatal(err)
	}
	output := make([]byte, UOTPacketMax)
	length, err := ReadUOTPacket(&wire, output)
	if err != nil || length != UOTPacketMax || !bytes.Equal(output, payload) {
		t.Fatalf("length=%d err=%v", length, err)
	}
	if _, err = EncodeUOTHeader(UOTPacketMax + 1); !errors.Is(err, ErrInvalidUOTPacket) {
		t.Fatalf("oversize err=%v", err)
	}
}
