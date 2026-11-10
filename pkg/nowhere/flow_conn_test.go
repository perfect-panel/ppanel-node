// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestPacketFlowConnClosesIdleFlow(t *testing.T) {
	closed := make(chan struct{})
	flow := &UDPFlow{
		Target: M.ParseSocksaddr("192.0.2.53:53"),
		Reader: emptyPacketSource{}, Writer: discardPacketSink{},
		close: sync.OnceFunc(func() { close(closed) }),
	}
	connection := newPacketFlowConn(flow, 20*time.Millisecond)
	t.Cleanup(func() { _ = connection.Close() })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("idle UDP flow remained open")
	}
}

func TestPacketFlowConnActivityDefersIdleClose(t *testing.T) {
	closed := make(chan struct{})
	flow := &UDPFlow{
		Target: M.ParseSocksaddr("192.0.2.53:53"),
		Reader: emptyPacketSource{}, Writer: discardPacketSink{},
		close: sync.OnceFunc(func() { close(closed) }),
	}
	connection := newPacketFlowConn(flow, 40*time.Millisecond)
	t.Cleanup(func() { _ = connection.Close() })
	time.Sleep(25 * time.Millisecond)
	connection.touchIdle()
	time.Sleep(25 * time.Millisecond)
	select {
	case <-closed:
		t.Fatal("active UDP flow closed at its original deadline")
	default:
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("UDP flow remained open after the renewed idle deadline")
	}
}

type emptyPacketSource struct{}

func (emptyPacketSource) ReadPacket([]byte) (int, error) { return 0, io.EOF }

type discardPacketSink struct{}

func (discardPacketSink) WritePacket([]byte) error { return nil }

func TestFlowSetupGatesPayloadAndRetainsResultFailure(t *testing.T) {
	failure := errors.New("setup write failed")
	for _, packet := range []bool{false, true} {
		t.Run(fmt.Sprint(packet), func(t *testing.T) {
			var calls int
			result := func(SetupResult) error { calls++; return failure }
			if !packet {
				conn := newTCPFlowConn(&TCPFlow{Reader: bytes.NewReader([]byte("hidden")), Writer: io.Discard, Result: result})
				defer conn.Close()
				if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, ErrSetupPending) {
					t.Fatalf("early read=%v", err)
				}
				if _, err := conn.Write([]byte("hidden")); !errors.Is(err, ErrSetupPending) {
					t.Fatalf("early write=%v", err)
				}
				for range 2 {
					if err := conn.HandshakeSuccess(); !errors.Is(err, failure) {
						t.Fatalf("lost error=%v", err)
					}
				}
			} else {
				conn := newPacketFlowConn(&UDPFlow{Reader: emptyPacketSource{}, Writer: discardPacketSink{}, Result: result}, 0)
				defer conn.Close()
				if _, _, err := conn.WaitReadPacket(); !errors.Is(err, ErrSetupPending) {
					t.Fatalf("early read=%v", err)
				}
				for range 2 {
					if err := conn.HandshakeSuccess(); !errors.Is(err, failure) {
						t.Fatalf("lost error=%v", err)
					}
				}
			}
			if calls != 1 {
				t.Fatalf("result written %d times", calls)
			}
		})
	}
	conn := newTCPFlowConn(&TCPFlow{Reader: bytes.NewReader(nil), Writer: io.Discard, Result: func(SetupResult) error { return nil }})
	defer conn.Close()
	if err := conn.Reject(SetupDialFailed); err != nil {
		t.Fatal(err)
	}
	if err := conn.HandshakeSuccess(); !errors.Is(err, ErrSetupRejected) {
		t.Fatalf("failure changed to READY: %v", err)
	}
}

func TestFlowSetupDeadlineClosesOnlyPendingFlow(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprint(ready), func(t *testing.T) {
			closed := make(chan struct{})
			conn := newTCPFlowConn(&TCPFlow{Reader: bytes.NewReader(nil), Writer: io.Discard, setupDeadline: time.Now().Add(30 * time.Millisecond), close: sync.OnceFunc(func() { close(closed) }), Result: func(SetupResult) error { return nil }})
			defer conn.Close()
			if ready {
				if err := conn.HandshakeSuccess(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-closed:
				if ready {
					t.Fatal("READY flow expired")
				}
			case <-time.After(100 * time.Millisecond):
				if !ready {
					t.Fatal("pending flow did not expire")
				}
			}
		})
	}
}
