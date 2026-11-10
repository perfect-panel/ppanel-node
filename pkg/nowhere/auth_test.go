// SPDX-License-Identifier: GPL-3.0-only

package nowhere

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

const testSharedKey = "0123456789abcdef0123456789abcdef"

func testExporter() TLSExporter {
	var e TLSExporter
	for i := range e {
		e[i] = byte(i)
	}
	return e
}
func TestAuthMatchesUpstreamFixedVectors(t *testing.T) {
	key, err := DeriveAuthKey([]byte(testSharedKey))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key[:]) != "1b5bddc7018f44cece1942211f94e5302c86827fda2e29bb4676ab667e5c95fb" {
		t.Fatalf("key=%x", key)
	}
	for transport, want := range map[AuthTransport]string{AuthTransportTLSTCP: "1a26d8eb72ead8a223b54fd1f04f8e32", AuthTransportQUIC: "7cbb323bd019bb51370c92a50a36a08f"} {
		frame, err := EncodeAuthFrame(key, transport, testExporter())
		if err != nil || hex.EncodeToString(frame[:]) != want {
			t.Fatalf("frame=%x err=%v", frame, err)
		}
		if err = ValidateAuthFrame(frame, key, transport, testExporter()); err != nil {
			t.Fatal(err)
		}
		other := testExporter()
		other[0] ^= 1
		if ValidateAuthFrame(frame, key, transport, other) == nil {
			t.Fatal("accepted another connection's exporter")
		}
		if ValidateAuthFrame(frame, key, AuthTransport(3-byte(transport)), testExporter()) == nil {
			t.Fatal("accepted cross-transport replay")
		}
	}
	egress, _ := hex.DecodeString("4c96702866b5d287ca58c7caffef0e0e")
	var frame AuthFrame
	copy(frame[:], egress)
	if ValidateAuthFrame(frame, key, AuthTransportTLSTCP, testExporter()) == nil {
		t.Fatal("accepted Egress role as Vector")
	}
}
func TestSharedKeyValidation(t *testing.T) {
	for _, key := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{'a'}, 31), bytes.Repeat([]byte{'a'}, 33), bytes.Repeat([]byte{'A'}, 32), []byte("01234567-89ab-cdef-0123-456789abcdef")} {
		if _, err := DeriveAuthKey(key); !errors.Is(err, ErrInvalidSharedKey) {
			t.Fatalf("key %q: %v", key, err)
		}
	}
}
func TestAuthenticatorCachesCredentialsAndRemapsUpdates(t *testing.T) {
	users := make([]User, 64)
	for i := range users {
		users[i] = User{Name: fmt.Sprint(i), Key: []byte(fmt.Sprintf("%032x", i+1))}
	}
	a := NewAuthenticator()
	update, _ := PrepareAuthUpdate(users)
	if err := a.Commit(update); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("127.0.0.1")
	for _, index := range []int{0, 63, 31, 0} {
		key, _ := DeriveAuthKey(users[index].Key)
		frame, _ := EncodeAuthFrame(key, AuthTransportTLSTCP, testExporter())
		got, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source)
		if err != nil || got.Identity != users[index].Name {
			t.Fatal(got, err)
		}
	}
	key, _ := DeriveAuthKey(users[63].Key)
	frame, _ := EncodeAuthFrame(key, AuthTransportTLSTCP, testExporter())
	update, _ = PrepareAuthUpdate([]User{users[63], users[0]})
	_ = a.Commit(update)
	got, err := a.AuthenticateConnection(frame, AuthTransportTLSTCP, testExporter(), source)
	if err != nil || got.Identity != users[63].Name {
		t.Fatal(got, err)
	}
}
func TestAuthenticationPublicationTracksCredentialAndIdentity(t *testing.T) {
	a := NewAuthenticator()
	user := User{Name: "alice", Key: []byte(testSharedKey)}
	update, _ := PrepareAuthUpdate([]User{user})
	_ = a.Commit(update)
	key, _ := DeriveAuthKey(user.Key)
	frame, _ := EncodeAuthFrame(key, AuthTransportQUIC, testExporter())
	admitted, err := a.AuthenticateConnection(frame, AuthTransportQUIC, testExporter(), netip.Addr{})
	if err != nil || !a.IsCurrent(admitted) {
		t.Fatal(err)
	}
	user.Name = "bob"
	update, _ = PrepareAuthUpdate([]User{user})
	_ = a.Commit(update)
	if a.IsCurrent(admitted) {
		t.Fatal("credential reassignment retained old owner")
	}
	changed, err := a.AuthenticateConnection(frame, AuthTransportQUIC, testExporter(), netip.Addr{})
	if err != nil || changed.Identity != "bob" {
		t.Fatal(changed, err)
	}
	update, _ = PrepareAuthUpdate(nil)
	_ = a.Commit(update)
	if a.IsCurrent(changed) {
		t.Fatal("removed user remains current")
	}
	if _, err = a.AuthenticateConnection(frame, AuthTransportQUIC, testExporter(), netip.Addr{}); !errors.Is(err, ErrNoUsers) {
		t.Fatal(err)
	}
}
