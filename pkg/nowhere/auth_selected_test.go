// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/perfect-panel/nowhere/internal/authscan"
)

func selectedAuthFixture(t *testing.T, count int) (*Authenticator, []User, Authentication) {
	t.Helper()
	records := make([]User, count)
	for i := range records {
		records[i] = User{Name: fmt.Sprintf("user-%d", i), Key: []byte(fmt.Sprintf("%032x", i+1))}
	}
	a := NewAuthenticator()
	commitSelectedUsers(t, a, records)
	key, err := DeriveAuthKey(records[count-1].Key)
	if err != nil {
		t.Fatal(err)
	}
	return a, records, a.users.Load().credential(key).authentication()
}
func commitSelectedUsers(t *testing.T, a *Authenticator, users []User) {
	t.Helper()
	update, err := PrepareAuthUpdate(users)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(update); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedAuthenticationUsesOneWorkUnitWithoutScan(t *testing.T) {
	for _, transport := range []AuthTransport{AuthTransportTLSTCP, AuthTransportQUIC} {
		t.Run(fmt.Sprint(transport), func(t *testing.T) {
			a, _, selected := selectedAuthFixture(t, 32)
			source := netip.MustParseAddr("127.0.0.1")
			now := time.Now()
			a.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: 1, WorkBurst: 100, TimeFunc: func() time.Time { return now }})
			permit, ok := a.guard.Acquire(source, 99)
			if !ok {
				t.Fatal("reserve budget")
			}
			permit.Release()
			frame, _ := EncodeAuthFrame(selected.key, transport, testExporter())
			// One work unit remains: a cold scan must be refused, while the selected
			// credential can still be verified without touching unrelated candidates.
			if _, err := a.AuthenticateConnection(frame, transport, testExporter(), source); !errors.Is(err, authscan.ErrLimited) {
				t.Fatalf("control scan=%v", err)
			}
			got, err := a.authenticateSelected(frame, transport, testExporter(), source, selected)
			if err != nil || got != selected {
				t.Fatalf("selected auth=%+v %v", got, err)
			}
			candidates, loaded := a.addressCache.Load(source, authCacheGeneration)
			if !loaded || candidates.Count() != 1 || candidates.At(0) != selected.id {
				t.Fatalf("successful auth cache=%+v", candidates)
			}
		})
	}
}

func TestSelectedAuthenticationRejectsOtherUserAndReplay(t *testing.T) {
	for _, transport := range []AuthTransport{AuthTransportTLSTCP, AuthTransportQUIC} {
		for _, mode := range []string{"other_user", "wrong_exporter", "wrong_transport", "invalid_transport"} {
			t.Run(fmt.Sprintf("%d/%s", transport, mode), func(t *testing.T) {
				a, records, selected := selectedAuthFixture(t, 2)
				key := selected.key
				exporter := testExporter()
				frameTransport := transport
				switch mode {
				case "other_user":
					key, _ = DeriveAuthKey(records[0].Key)
				case "wrong_exporter":
					exporter[0] ^= 1
				case "wrong_transport":
					frameTransport = AuthTransport(3 - byte(transport))
				}
				frame, _ := EncodeAuthFrame(key, frameTransport, exporter)
				source := netip.MustParseAddr("127.0.0.1")
				verifyTransport := transport
				if mode == "invalid_transport" {
					verifyTransport = 0
				}
				got, err := a.authenticateSelected(frame, verifyTransport, testExporter(), source, selected)
				if err == nil || got != (Authentication{}) {
					t.Fatalf("accepted mismatch: %+v %v", got, err)
				}
				if candidates, loaded := a.addressCache.Load(source, authCacheGeneration); loaded || candidates.Count() != 0 {
					t.Fatal("failed auth warmed candidate cache")
				}
				if mode != "invalid_transport" && !a.guard.SourceBlocked(source) {
					t.Fatal("failed tag did not arm source backoff")
				}
			})
		}
	}
}
func TestSelectedAuthenticationChecksCurrentKeyAndOwner(t *testing.T) {
	for _, mode := range []string{"reordered", "removed", "rotated", "reassigned"} {
		t.Run(mode, func(t *testing.T) {
			a, records, selected := selectedAuthFixture(t, 2)
			frame, _ := EncodeAuthFrame(selected.key, AuthTransportQUIC, testExporter())
			switch mode {
			case "reordered":
				records[0], records[1] = records[1], records[0]
			case "removed":
				records = records[:1]
			case "rotated":
				records[1].Key = []byte(testSharedKey)
			case "reassigned":
				records[1].Name = "new-owner"
			}
			commitSelectedUsers(t, a, records)
			source := netip.MustParseAddr("127.0.0.1")
			got, err := a.authenticateSelected(frame, AuthTransportQUIC, testExporter(), source, selected)
			if mode == "reordered" {
				if err != nil || got != selected {
					t.Fatalf("valid reordered owner=%+v %v", got, err)
				}
			} else {
				if !errors.Is(err, ErrAuthentication) {
					t.Fatalf("stale selection=%v", err)
				}
				if hasCurrentCachedCandidate(a, source) {
					t.Fatal("stale selection warmed cache")
				}
			}
		})
	}
}
func TestSelectedAuthenticationKeepsGuardLimits(t *testing.T) {
	for _, mode := range []string{"cooldown", "cached_cooldown", "budget", "concurrency"} {
		t.Run(mode, func(t *testing.T) {
			a, _, selected := selectedAuthFixture(t, 1)
			source := netip.MustParseAddr("127.0.0.1")
			now := time.Now()
			a.guard = authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: 1, WorkBurst: 8, Concurrent: 1, TimeFunc: func() time.Time { return now }})
			if mode != "cooldown" {
				a.addressCache.Store(source, authCacheGeneration, selected.id)
			}
			switch mode {
			case "cooldown", "cached_cooldown":
				permit, ok := a.guard.Acquire(source, 1)
				if !ok {
					t.Fatal("acquire")
				}
				permit.Done(false)
			case "budget":
				permit, ok := a.guard.Acquire(source, 8)
				if !ok {
					t.Fatal("acquire")
				}
				permit.Release()
			case "concurrency":
				permit, ok := a.guard.Acquire(source, 1)
				if !ok {
					t.Fatal("acquire")
				}
				defer permit.Release()
			}
			frame, _ := EncodeAuthFrame(selected.key, AuthTransportTLSTCP, testExporter())
			_, err := a.authenticateSelected(frame, AuthTransportTLSTCP, testExporter(), source, selected)
			if mode == "cached_cooldown" {
				if err != nil || a.guard.SourceBlocked(source) {
					t.Fatalf("cached valid auth=%v", err)
				}
			} else if !errors.Is(err, authscan.ErrLimited) {
				t.Fatalf("guard bypassed: %v", err)
			}
		})
	}
}
func TestSelectedAuthenticationConcurrentRemovalDoesNotRepublishCache(t *testing.T) {
	for range 100 {
		a, _, selected := selectedAuthFixture(t, 1)
		frame, _ := EncodeAuthFrame(selected.key, AuthTransportTLSTCP, testExporter())
		source := netip.MustParseAddr("127.0.0.1")
		update, err := PrepareAuthUpdate(nil)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Go(func() {
			<-start
			_, _ = a.authenticateSelected(frame, AuthTransportTLSTCP, testExporter(), source, selected)
		})
		workers.Go(func() {
			<-start
			if err := a.Commit(update); err != nil {
				t.Error(err)
			}
		})
		close(start)
		workers.Wait()
		if _, err = a.authenticateSelected(frame, AuthTransportTLSTCP, testExporter(), source, selected); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("accepted after removal: %v", err)
		}
		if hasCurrentCachedCandidate(a, source) {
			t.Fatal("old authentication republished removed user's cache")
		}
	}
}
func TestMorphQUICSelectionRequiresBoundRoute(t *testing.T) {
	if _, ok := morphQUICSelection(context.Background()); ok {
		t.Fatal("accepted missing binding")
	}
	binding := &morphQUICBinding{}
	ctx := context.WithValue(context.Background(), morphQUICContextKey{}, binding)
	if _, ok := morphQUICSelection(ctx); ok {
		t.Fatal("accepted missing route")
	}
	selected := Authentication{Identity: "alice", key: AuthKey{1}}
	binding.route.Store(&morphUDPRoute{authentication: selected})
	if got, ok := morphQUICSelection(ctx); !ok || got != selected {
		t.Fatalf("selection=%+v %v", got, ok)
	}
}

func hasCurrentCachedCandidate(a *Authenticator, source netip.Addr) bool {
	candidates, _ := a.addressCache.Load(source, authCacheGeneration)
	state := a.users.Load()
	for i := 0; i < candidates.Count(); i++ {
		if state.candidate(candidates.At(i)) != nil {
			return true
		}
	}
	return false
}
