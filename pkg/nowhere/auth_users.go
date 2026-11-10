// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"crypto/hmac"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/perfect-panel/nowhere/internal/authscan"
)

const (
	authCacheEntriesPerShard = 512
	nowhereAuthScanWorkRate  = 1 << 22
)

var (
	ErrNoUsers          = errors.New("nowhere: no users configured")
	ErrAuthentication   = errors.New("nowhere: authentication failed")
	ErrDuplicateAuthKey = errors.New("nowhere: duplicate derived authentication key")
	ErrInvalidUser      = errors.New("nowhere: invalid user")
)

// User is one stable application identity and its Nowhere shared key. Name is
// carried through sing's authenticated-user context and is never serialized on
// the wire. Each name and each key must be unique within an authenticator.
type User struct {
	Name string
	Key  []byte
}

// Authentication is the stable identity and credential admitted for one
// physical carrier. The credential remains private so callers cannot forge a
// publication check after a user update.
type Authentication struct {
	Identity string
	key      AuthKey
	id       uint64
}

type Authenticator struct {
	users        atomic.Pointer[authGeneration]
	updateMu     sync.RWMutex
	addressCache *authscan.Cache[netip.Addr]
	guard        *authscan.Guard[netip.Addr]
}

func NewAuthenticator() *Authenticator {
	authenticator := &Authenticator{
		addressCache: authscan.NewCacheWithCapacity(authscan.HashAddr, authCacheEntriesPerShard),
		guard:        authscan.NewGuard(authscan.HashAddr, authscan.GuardOptions{WorkRate: nowhereAuthScanWorkRate}),
	}
	authenticator.users.Store(&authGeneration{generation: 1})
	return authenticator
}

func (authenticator *Authenticator) Authenticate(
	frame AuthFrame,
	transport AuthTransport,
	exporter TLSExporter,
	source netip.Addr,
) (string, error) {
	authentication, err := authenticator.AuthenticateConnection(frame, transport, exporter, source)
	return authentication.Identity, err
}

// AuthenticateConnection authenticates one connection against an immutable
// user generation. If a user update races the scan, it retries rather than
// attributing the connection to a removed or changed credential.
func (authenticator *Authenticator) AuthenticateConnection(frame AuthFrame, transport AuthTransport, exporter TLSExporter, source netip.Addr) (Authentication, error) {
	if transport != AuthTransportTLSTCP && transport != AuthTransportQUIC {
		return Authentication{}, ErrInvalidAuthFrame
	}
	for {
		state := authenticator.users.Load()
		if state == nil || state.count == 0 {
			return Authentication{}, ErrNoUsers
		}
		var tried [authscan.CandidateCapacity]uint64
		triedCount := 0
		candidates, _ := authenticator.addressCache.Load(source, authCacheGeneration)
		var matched *authCredential
		for i := 0; i < candidates.Count(); i++ {
			c := state.candidate(candidates.At(i))
			if c == nil {
				continue
			}
			tried[triedCount] = c.id
			triedCount++
			if validAuthTag(frame[:], c.mac, transport, exporter) {
				matched = c
				break
			}
		}
		if matched != nil {
			if result, current := authenticator.publishMatch(state, matched, source); current {
				return result, nil
			}
			continue
		}
		permit, allowed := authenticator.guard.Acquire(source, state.count-triedCount)
		if !allowed {
			return Authentication{}, authscan.ErrLimited
		}
		state.each(func(c *authCredential) bool {
			for _, id := range tried[:triedCount] {
				if id == c.id {
					return true
				}
			}
			if validAuthTag(frame[:], c.mac, transport, exporter) {
				matched = c
				return false
			}
			return true
		})
		if matched != nil {
			if result, current := authenticator.publishMatch(state, matched, source); current {
				permit.Done(true)
				return result, nil
			}
			permit.Release()
			continue
		}
		authenticator.updateMu.RLock()
		current := authenticator.users.Load() == state
		authenticator.updateMu.RUnlock()
		if !current {
			permit.Release()
			continue
		}
		permit.Done(false)
		return Authentication{}, ErrAuthentication
	}
}

// authenticateSelected verifies only the credential selected by Morph. A Morph
// match remains tentative until the exporter-bound tag succeeds; mismatches do
// not fall back to other users or publish authentication cache entries.
func (authenticator *Authenticator) authenticateSelected(
	frame AuthFrame,
	transport AuthTransport,
	exporter TLSExporter,
	source netip.Addr,
	selected Authentication,
) (Authentication, error) {
	if transport != AuthTransportTLSTCP && transport != AuthTransportQUIC {
		return Authentication{}, ErrInvalidAuthFrame
	}
	// Hold publication stable through verification and cache admission. Looking
	// up by key also handles reordered snapshots without retaining stale indexes.
	authenticator.updateMu.RLock()
	defer authenticator.updateMu.RUnlock()
	state := authenticator.users.Load()
	if state == nil {
		return Authentication{}, ErrAuthentication
	}
	credential := state.credential(selected.key)
	if credential == nil || credential.identity != selected.Identity || credential.id != selected.id {
		return Authentication{}, ErrAuthentication
	}
	candidates, _ := authenticator.addressCache.Load(source, authCacheGeneration)
	var permit *authscan.Permit[netip.Addr]
	var allowed bool
	if source.IsValid() && candidates.Contains(credential.id) {
		// Only a previously authenticated candidate can bypass source cooldown.
		permit, allowed = authenticator.guard.AcquireKnown(source, 1)
	} else {
		permit, allowed = authenticator.guard.Acquire(source, 1)
	}
	if !allowed {
		return Authentication{}, authscan.ErrLimited
	}
	defer permit.Release()
	if !validAuthTag(frame[:], credential.mac, transport, exporter) {
		permit.Done(false)
		return Authentication{}, ErrAuthentication
	}
	authenticator.admit(source, credential.id)
	return selected, nil
}

func (authenticator *Authenticator) admit(source netip.Addr, id uint64) {
	if source.IsValid() {
		authenticator.addressCache.Store(source, authCacheGeneration, id)
		authenticator.guard.Reset(source)
	}
}

func (authenticator *Authenticator) publishMatch(
	state *authGeneration,
	credential *authCredential,
	source netip.Addr,
) (Authentication, bool) {
	authenticator.updateMu.RLock()
	defer authenticator.updateMu.RUnlock()
	if authenticator.users.Load() != state || state.candidate(credential.id) != credential {
		return Authentication{}, false
	}
	authenticator.admit(source, credential.id)
	return credential.authentication(), true
}

// IsCurrent reports whether an authenticated carrier still belongs to a
// currently published user with the same credential and reporting identity.
func (authenticator *Authenticator) IsCurrent(authentication Authentication) bool {
	state := authenticator.users.Load()
	if state == nil {
		return false
	}
	credential := state.credential(authentication.key)
	return credential != nil && credential.identity == authentication.Identity && credential.id == authentication.id
}

func validAuthTag(
	tag []byte,
	mac authenticationMAC,
	transport AuthTransport,
	exporter TLSExporter,
) bool {
	expected := mac.tag(transport, exporter)
	return hmac.Equal(tag, expected[:])
}
