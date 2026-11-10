// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/nowhere/internal/authscan"
)

func BenchmarkAuthenticatorMultiUser(b *testing.B) {
	for _, count := range []int{1, 1_000, 10_000} {
		b.Run(fmt.Sprintf("users=%d", count), func(b *testing.B) {
			authenticator, key := benchmarkAuthenticator(b, count)
			var coldSequence atomic.Uint64
			var exporter TLSExporter
			for index := range exporter {
				exporter[index] = byte(index)
			}
			b.Run("cached", func(b *testing.B) {
				frame, err := EncodeAuthFrame(key, AuthTransportTLSTCP, exporter)
				if err != nil {
					b.Fatal(err)
				}
				source := netip.MustParseAddr("192.0.2.1")
				if _, err = authenticator.Authenticate(frame, AuthTransportTLSTCP, exporter, source); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if _, err = authenticator.Authenticate(frame, AuthTransportTLSTCP, exporter, source); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("cold", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					value := coldSequence.Add(1)
					frame, err := EncodeAuthFrame(key, AuthTransportTLSTCP, exporter)
					if err != nil {
						b.Fatal(err)
					}
					var address [16]byte
					address[0], address[1] = 0x20, 0x01
					binary.BigEndian.PutUint64(address[8:], value)
					source := netip.AddrFrom16(address)
					if _, err = authenticator.Authenticate(frame, AuthTransportTLSTCP, exporter, source); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("morph-selected", func(b *testing.B) {
				selected := authenticator.users.Load().credential(key).authentication()
				frame, err := EncodeAuthFrame(key, AuthTransportTLSTCP, exporter)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					value := coldSequence.Add(1)
					var address [16]byte
					address[0] = 0xfd
					binary.BigEndian.PutUint64(address[8:], value)
					if _, err := authenticator.authenticateSelected(frame, AuthTransportTLSTCP, exporter, netip.AddrFrom16(address), selected); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func benchmarkAuthenticator(b *testing.B, count int) (*Authenticator, AuthKey) {
	b.Helper()
	records := make([]User, count)
	for index := range records {
		records[index] = User{Name: fmt.Sprint(index + 1), Key: []byte(fmt.Sprintf("%032x", index+1))}
	}
	update, err := PrepareAuthUpdate(records)
	if err != nil {
		b.Fatal(err)
	}
	authenticator := NewAuthenticator()
	// Keep the production scan guard in the measured path, but give this
	// throughput benchmark enough budget to avoid measuring intentional DoS
	// throttling after a long benchtime.
	maxInt := int(^uint(0) >> 1)
	authenticator.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{
		WorkRate: maxInt / 4, WorkBurst: maxInt / 2,
	})
	if err = authenticator.Commit(update); err != nil {
		b.Fatal(err)
	}
	key, err := DeriveAuthKey(records[len(records)-1].Key)
	if err != nil {
		b.Fatal(err)
	}
	return authenticator, key
}
