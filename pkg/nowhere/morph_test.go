// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
)

func TestMorphUpstreamKeyAndPreludeVectors(t *testing.T) {
	keys := deriveMorphKeys([]byte("test portal key"))
	for got, want := range map[[32]byte]string{
		keys.TCPC2S: "f3d2fabc455a59c400d09d400b5a0b9b221e2b157589fc87674b902111ea1014",
		keys.TCPS2C: "190cfc4c689b24d4bfc8431f46d9f2d1bcbf6222eed612a3ea12d04ff4e4af8c",
		keys.UDPC2S: "20221bde5d70b44211a22c7e62967945d7d85bcde0d17a3b28d1fa686f8e5c1f",
		keys.UDPS2C: "78938ee9245028e7de63ac27b0ab64c68df2961a2cf39da1394f0f242bf8b389",
	} {
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("derived key mismatch: %x", got)
		}
	}
	keys = deriveMorphKeys([]byte(testSharedKey))
	prelude, nonce := fixedPrelude()
	value, valid := decodePrelude(keys, prelude, nonce)
	if !valid || value.identity != 0x0123456789abcdef || value.counter != 1 {
		t.Fatalf("decoded=%+v valid=%v", value, valid)
	}
	for i := range prelude {
		for bit := uint(0); bit < 8; bit++ {
			changed := bytes.Clone(prelude)
			changed[i] ^= 1 << bit
			if _, valid = decodePrelude(keys, changed, nonce); valid {
				t.Fatalf("accepted mutation at %d bit %d", i, bit)
			}
		}
	}
	nonce[0] ^= 1
	if _, valid = decodePrelude(keys, prelude, nonce); valid {
		t.Fatal("accepted another nonce")
	}
}
func fixedPrelude() ([]byte, []byte) {
	prelude := make([]byte, 64)
	for i := 0; i < 32; i++ {
		prelude[i] = byte(i)
	}
	tail, _ := hex.DecodeString("898f9c840e570537225e187fb7e4c990df489547d61b9e515bad2a8f4dd84d86")
	copy(prelude[32:], tail)
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	return prelude, nonce
}
func TestPreludeReplayWindowCommitAndCredentialIsolation(t *testing.T) {
	replay := newPreludeReplay(2)
	var key AuthKey
	value := preludeIdentity{identity: 7, counter: 1}
	if !replay.accept(key, value, false) || len(replay.index) != 0 {
		t.Fatal("precheck reserved counter")
	}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			if replay.accept(key, value, true) {
				accepted.Add(1)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent accepted=%d", accepted.Load())
	}
	for _, counter := range []uint64{0, 1, maxPreludeCounter + 1} {
		if replay.accept(key, preludeIdentity{7, counter}, true) {
			t.Fatalf("accepted counter %d", counter)
		}
	}
	if !replay.accept(key, preludeIdentity{7, 1025}, true) || replay.accept(key, preludeIdentity{7, 1}, true) || !replay.accept(key, preludeIdentity{7, 2}, true) || replay.accept(key, preludeIdentity{7, 2}, true) {
		t.Fatal("sliding window boundary")
	}
	other := key
	other[0] = 1
	if !replay.accept(other, value, true) {
		t.Fatal("cross-user replay collision")
	}
	if !replay.accept(key, preludeIdentity{8, 1}, true) || len(replay.index) != 2 || !replay.accept(key, value, false) {
		t.Fatal("FIFO eviction")
	}
}

type partialMorphConn struct {
	net.Conn
	written bytes.Buffer
	fail    bool
}

func (c *partialMorphConn) Write(p []byte) (int, error) {
	if !c.fail {
		c.fail = true
		n, _ := c.written.Write(p[:min(7, len(p))])
		return n, io.ErrUnexpectedEOF
	}
	return c.written.Write(p)
}
func TestMorphTCPShortWriteResumesAtTransmittedOffset(t *testing.T) {
	raw := &partialMorphConn{}
	keys := deriveMorphKeys([]byte(testSharedKey))
	conn := &morphTCPConn{Conn: raw, keys: keys}
	conn.canWrite.Store(true)
	payload := bytes.Repeat([]byte("fragmented-morph"), 20)
	n, err := conn.Write(payload)
	if n != 7 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial=%d %v", n, err)
	}
	if _, err = conn.Write(payload[n:]); err != nil {
		t.Fatal(err)
	}
	cipher, _ := chacha20.NewUnauthenticatedCipher(keys.TCPS2C[:], conn.nonce[:])
	decoded := bytes.Clone(raw.written.Bytes())
	cipher.XORKeyStream(decoded, decoded)
	if !bytes.Equal(decoded, payload) {
		t.Fatal("short write skipped keystream")
	}
	if err = morphXOR(nil, nil, keys.TCPS2C, conn.nonce, morphStreamLimit); err != nil {
		t.Fatal(err)
	}
	if err = morphXOR(make([]byte, 2), []byte{1, 2}, keys.TCPS2C, conn.nonce, morphStreamLimit-1); err == nil {
		t.Fatal("counter wrapped")
	}
}

func TestMorphPreludeNotCommittedUntilClientHello(t *testing.T) {
	portal := testHandlerPortal(t, &recordingServerHandler{})
	portal.prelude = newPreludeReplay(8)
	update, err := PrepareAuthUpdate([]User{{Name: "alice", Key: []byte(testSharedKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = portal.authenticator.Commit(update); err != nil {
		t.Fatal(err)
	}
	prelude, nonce := fixedPrelude()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _, _ = b.Write(append(prelude, nonce...)) }()
	masked, config, err := portal.acceptMorphTCP(a, &tls.Config{}, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(portal.prelude.index) != 0 {
		t.Fatal("bootstrap committed without ClientHello")
	}
	if _, err = masked.Write([]byte("alert")); err == nil {
		t.Fatal("response before ClientHello")
	}
	if _, err = config.GetConfigForClient(&tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS13}, SupportedProtos: []string{DefaultALPN}}); err != nil {
		t.Fatal(err)
	}
	if len(portal.prelude.index) != 1 {
		t.Fatal("ClientHello did not commit")
	}
	if _, err = config.GetConfigForClient(&tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS13}, SupportedProtos: []string{DefaultALPN}}); !errors.Is(err, ErrMorphReplay) {
		t.Fatalf("duplicate commit=%v", err)
	}
}

type lingerTestConn struct {
	net.Conn
	values []int
}

func (c *lingerTestConn) SetLinger(value int) error { c.values = append(c.values, value); return nil }
func TestMorphInvalidPreludeIsSilentUntilDeadline(t *testing.T) {
	portal := testHandlerPortal(t, &recordingServerHandler{})
	portal.morph = true
	portal.prelude = newPreludeReplay(8)
	portal.handshakeTimeout = 80 * time.Millisecond
	update, _ := PrepareAuthUpdate([]User{{Name: "alice", Key: []byte(testSharedKey)}})
	if err := portal.authenticator.Commit(update); err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	raw := &lingerTestConn{Conn: server}
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); portal.HandleTLS(t.Context(), raw, &tls.Config{}, DefaultALPN) }()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write(make([]byte, 76)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := client.Read(b[:])
	if n != 0 || err == nil {
		t.Fatalf("silent rejection read=%d %v", n, err)
	}
	<-done
	if time.Since(start) < 60*time.Millisecond {
		t.Fatal("rejected before absolute deadline")
	}
	if len(raw.values) != 1 || raw.values[0] != 0 {
		t.Fatalf("linger changed before authentication: %v", raw.values)
	}
	if len(portal.prelude.index) != 0 {
		t.Fatal("invalid bootstrap consumed replay state")
	}
}
