// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestUDPDataAndCloseMatchUpstreamVectors(t *testing.T) {
	data, err := EncodeUDPData(0x01020304, []byte{0xaa, 0xbb})
	if err != nil || !bytes.Equal(data, []byte{1, 2, 3, 4, 0xaa, 0xbb}) {
		t.Fatalf("data=%x err=%v", data, err)
	}
	closeFrame, err := EncodeUDPClose(0x01020304)
	if err != nil || closeFrame != [4]byte{0x81, 2, 3, 4} {
		t.Fatalf("close=%x err=%v", closeFrame, err)
	}
	decoded, err := DecodeUDPFrame(data)
	if err != nil || decoded.Type != UDPFrameData || decoded.FlowID != 0x01020304 || !bytes.Equal(decoded.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}

func TestUDPFragmentHeaderMatchesUpstreamVector(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 2500)
	frames, err := EncodeUDPFragments(0x01020304, 0x11223344, payload, 1200)
	if err != nil || len(frames) != 3 {
		t.Fatalf("frames=%d err=%v", len(frames), err)
	}
	want := []byte{0x41, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0, 3, 0x09, 0xc4}
	if !bytes.Equal(frames[0][:UDPFragmentHeaderLen], want) {
		t.Fatalf("header=%x want=%x", frames[0][:UDPFragmentHeaderLen], want)
	}
}

func TestUDPFragmentPlannerAcceptsUnfragmentedZeroPacketWithoutPacketID(t *testing.T) {
	frames, err := EncodeUDPFragments(7, 0, nil, UDPHeaderLen)
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0], []byte{0, 0, 0, 7}) {
		t.Fatalf("frames=%x err=%v", frames, err)
	}
}

func TestUDPFrameRejectsInvalidShapes(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{0, 0, 0, 0, 0},
		{0xc0, 0, 0, 1},
		{0x40, 0, 0, 1},
		{0x80, 0, 0, 1, 0},
		{0x40, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1},
	} {
		if _, err := DecodeUDPFrame(input); err == nil {
			t.Fatalf("accepted %x", input)
		}
	}
	if _, err := EncodeUDPFragments(1, 1, make([]byte, 256), UDPFragmentHeaderLen+1); err == nil {
		t.Fatal("accepted 256 fragments")
	}
}

func TestUDPFragmentsRoundTripOutOfOrder(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	frames, err := EncodeUDPFragments(7, 11, payload, 1200)
	if err != nil || len(frames) < 2 {
		t.Fatalf("frames=%d err=%v", len(frames), err)
	}
	reassembler, err := NewDatagramReassembler(DefaultReassemblyConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var complete []byte
	for index := len(frames) - 1; index >= 0; index-- {
		frame, decodeErr := DecodeUDPFrame(frames[index])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		result, done, pushErr := reassembler.Push(frame, now)
		if pushErr != nil {
			t.Fatal(pushErr)
		}
		if done {
			complete = result
		}
	}
	if !bytes.Equal(complete, payload) || reassembler.SlotCount() != 0 || reassembler.ReservedBytes() != 0 {
		t.Fatalf("complete=%d slots=%d bytes=%d", len(complete), reassembler.SlotCount(), reassembler.ReservedBytes())
	}
}

func TestReassemblerDropsConflictsAndExpiresSlots(t *testing.T) {
	config := ReassemblyConfig{MaxSlots: 1, MaxBytes: 128, TTL: time.Second}
	reassembler, err := NewDatagramReassembler(config)
	if err != nil {
		t.Fatal(err)
	}
	frames, _ := EncodeUDPFragments(1, 1, bytes.Repeat([]byte{1}, 100), 64)
	first, _ := DecodeUDPFrame(frames[0])
	now := time.Now()
	if _, _, err = reassembler.Push(first, now); err != nil {
		t.Fatal(err)
	}
	conflict := first
	conflict.Payload = bytes.Repeat([]byte{2}, len(first.Payload))
	if _, _, err = reassembler.Push(conflict, now); !errors.Is(err, ErrReassemblyConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	if reassembler.SlotCount() != 0 || reassembler.ReservedBytes() != 0 {
		t.Fatal("conflict retained a slot")
	}
	if _, _, err = reassembler.Push(first, now); err != nil {
		t.Fatal(err)
	}
	if expired := reassembler.Expire(now.Add(time.Second)); expired != 0 {
		t.Fatalf("expired at exact boundary: %d", expired)
	}
	if expired := reassembler.Expire(now.Add(time.Second + time.Nanosecond)); expired != 1 {
		t.Fatalf("expired=%d", expired)
	}
}
