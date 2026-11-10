// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlog"
)

func captureInitial(t testing.TB) []byte {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	transport := &quic.Transport{Conn: sender, ConnectionIDLength: 8}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, _ := transport.Dial(ctx, raw.LocalAddr(), &tls.Config{NextProtos: []string{DefaultALPN}, InsecureSkipVerify: true}, &quic.Config{Versions: []quic.Version{quic.Version1}})
		if c != nil {
			_ = c.CloseWithError(0, "")
		}
	}()
	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	packet := make([]byte, 65535)
	n, _, err := raw.ReadFrom(packet)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	return packet[:n]
}
func TestInitialSelectionRequiresAEAD(t *testing.T) {
	packet := captureInitial(t)
	if !validClientInitial(packet) {
		t.Fatal("rejected independent quic-go Initial")
	}
	for i := range packet {
		changed := bytes.Clone(packet)
		changed[i] ^= 1
		if validClientInitial(changed) {
			t.Fatalf("accepted corrupted Initial byte %d", i)
		}
	}
	for size := 0; size < len(packet); size++ {
		if validClientInitial(packet[:size]) {
			t.Fatalf("accepted truncated Initial size %d", size)
		}
	}
}

type queuedMorphPacketConn struct {
	packets [][]byte
	last    []byte
	peer    *net.UDPAddr
}

func (c *queuedMorphPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.packets) == 0 {
		return 0, c.peer, io.EOF
	}
	v := c.packets[0]
	c.packets = c.packets[1:]
	return copy(p, v), c.peer, nil
}
func (c *queuedMorphPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.last = bytes.Clone(p)
	return len(p), nil
}
func (c *queuedMorphPacketConn) LocalAddr() net.Addr              { return c.peer }
func (c *queuedMorphPacketConn) Close() error                     { return nil }
func (c *queuedMorphPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *queuedMorphPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedMorphPacketConn) SetWriteDeadline(time.Time) error { return nil }
func maskPacket(t *testing.T, packet []byte, key [32]byte) []byte {
	t.Helper()
	wire := make([]byte, 12+len(packet))
	if err := morphXOR(wire[12:], packet, key, [12]byte{}, 0); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestMorphUDPUserIsolationCIDRotationAndRevocation(t *testing.T) {
	auth := NewAuthenticator()
	users := []User{{Name: "alice", Key: []byte(testSharedKey)}, {Name: "bob", Key: []byte("11111111111111111111111111111111")}}
	update, err := PrepareAuthUpdate(users)
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.Commit(update); err != nil {
		t.Fatal(err)
	}
	raw := &queuedMorphPacketConn{peer: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7777}}
	conn := newMorphPacketConn(raw, auth)
	credentials := []*authCredential{auth.users.Load().user("alice"), auth.users.Load().user("bob")}
	var initials [][]byte
	for _, credential := range credentials {
		initial := captureInitial(t)
		initials = append(initials, initial)
		raw.packets = append(raw.packets, maskPacket(t, initial, credential.morph.UDPC2S))
	}
	output := make([]byte, 65535)
	for _, initial := range initials {
		n, _, err := conn.ReadFrom(output)
		if err != nil || !bytes.Equal(output[:n], initial) {
			t.Fatalf("read=%d %v", n, err)
		}
	}
	if len(conn.routes) != 2 {
		t.Fatalf("routes=%d", len(conn.routes))
	}
	for index, initial := range initials {
		_, clientID, _, _ := quicLongIDs(initial)
		payload := append([]byte{0x40}, clientID...)
		payload = append(payload, bytes.Repeat([]byte{0x42}, 32)...)
		if _, err = conn.WriteTo(payload, raw.peer); err != nil {
			t.Fatal(err)
		}
		var nonce [12]byte
		copy(nonce[:], raw.last[:12])
		decoded := make([]byte, len(raw.last)-12)
		_ = morphXOR(decoded, raw.last[12:], credentials[index].morph.UDPS2C, nonce, 0)
		if !bytes.Equal(decoded, payload) {
			t.Fatal("another user's outbound key")
		}
	}
	var alice *morphUDPRoute
	for route := range conn.routes {
		if route.authentication.Identity == "alice" {
			alice = route
		}
	}
	trace := &morphTrace{packet: conn, route: alice}
	recorder := trace.AddProducer()
	serverID := quic.ConnectionIDFromBytes([]byte("rotated!"))
	clientID := quic.ConnectionIDFromBytes([]byte("client!!"))
	recorder.RecordEvent(qlog.PacketSent{Frames: []qlog.Frame{{Frame: &qlog.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: serverID}}}})
	recorder.RecordEvent(qlog.PacketReceived{Frames: []qlog.Frame{{Frame: &qlog.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: clientID}}}})
	short := append([]byte{0x40}, serverID.Bytes()...)
	short = append(short, bytes.Repeat([]byte{1}, 32)...)
	raw.packets = append(raw.packets, maskPacket(t, short, credentials[0].morph.UDPC2S))
	if n, _, err := conn.ReadFrom(output); err != nil || !bytes.Equal(output[:n], short) {
		t.Fatalf("rotated input %v", err)
	}
	reply := append([]byte{0x40}, clientID.Bytes()...)
	reply = append(reply, bytes.Repeat([]byte{2}, 32)...)
	if _, err = conn.WriteTo(reply, raw.peer); err != nil {
		t.Fatal(err)
	}
	update, err = PrepareAuthUpdate(users[1:])
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.Commit(update); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.WriteTo(reply, raw.peer); !errors.Is(err, ErrMorph) {
		t.Fatalf("revoked route write=%v", err)
	}
	raw.packets = append(raw.packets, make([]byte, 12), maskPacket(t, short, credentials[0].morph.UDPC2S))
	if _, _, err = conn.ReadFrom(output); !errors.Is(err, io.EOF) {
		t.Fatalf("revoked route read=%v", err)
	}
	_ = recorder.Close()
	if len(conn.routes) != 1 {
		t.Fatalf("closed routes=%d", len(conn.routes))
	}
}
