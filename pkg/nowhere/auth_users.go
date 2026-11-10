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
// the wire.
type User struct {
	Name string
	Key  []byte
}

type authCredential struct {
	identity string
	key      AuthKey
	mac      authenticationMAC
	morph    MorphKeys
}

type authGeneration struct {
	generation  uint64
	credentials []authCredential
	byKey       map[AuthKey]int
}

type AuthUpdate struct {
	state *authGeneration
}

// Authentication is the stable identity and credential admitted for one
// physical carrier. The credential remains private so callers cannot forge a
// publication check after a user update.
type Authentication struct {
	Identity string
	key      AuthKey
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
	authenticator.users.Store(&authGeneration{generation: 1, byKey: make(map[AuthKey]int)})
	return authenticator
}

func PrepareAuthUpdate(records []User) (*AuthUpdate, error) {
	state := &authGeneration{
		credentials: make([]authCredential, len(records)),
		byKey:       make(map[AuthKey]int, len(records)),
	}
	for index, user := range records {
		if user.Name == "" || len(user.Key) == 0 {
			return nil, ErrInvalidUser
		}
		key, err := DeriveAuthKey(user.Key)
		if err != nil {
			return nil, err
		}
		if _, exists := state.byKey[key]; exists {
			return nil, ErrDuplicateAuthKey
		}
		state.credentials[index] = authCredential{
			identity: user.Name,
			key:      key,
			mac:      newAuthenticationMAC(key),
			morph:    deriveMorphKeys(user.Key),
		}
		state.byKey[key] = index
	}
	return &AuthUpdate{state: state}, nil
}

func (authenticator *Authenticator) Commit(update *AuthUpdate) error {
	if update == nil || update.state == nil {
		return errors.New("nowhere: invalid authentication update")
	}
	authenticator.updateMu.Lock()
	defer authenticator.updateMu.Unlock()
	current := authenticator.users.Load()
	state := *update.state
	state.generation = 1
	if current != nil {
		state.generation = current.generation + 1
		mapping := make([]int, len(current.credentials))
		for oldIndex, credential := range current.credentials {
			mapping[oldIndex] = -1
			if newIndex, exists := state.byKey[credential.key]; exists {
				mapping[oldIndex] = newIndex
			}
		}
		authenticator.addressCache.RemapGeneration(current.generation, state.generation, mapping)
	}
	authenticator.users.Store(&state)
	update.state = nil
	return nil
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
func (authenticator *Authenticator) AuthenticateConnection(
	frame AuthFrame,
	transport AuthTransport,
	exporter TLSExporter,
	source netip.Addr,
) (Authentication, error) {
	if transport != AuthTransportTLSTCP && transport != AuthTransportQUIC {
		return Authentication{}, ErrInvalidAuthFrame
	}
	tag := frame[:]
	for {
		state := authenticator.users.Load()
		if state == nil || len(state.credentials) == 0 {
			return Authentication{}, ErrNoUsers
		}
		var tried [8]uint32
		triedCount := 0
		wasTried := func(index uint32) bool {
			for position := range triedCount {
				if tried[position] == index {
					return true
				}
			}
			return false
		}
		tryCandidates := func(candidates authscan.Candidates) (uint32, bool) {
			for position := 0; position < candidates.Count(); position++ {
				index := candidates.At(position)
				if int(index) >= len(state.credentials) {
					continue
				}
				if wasTried(index) {
					continue
				}
				tried[triedCount] = index
				triedCount++
				credential := state.credentials[index]
				if validAuthTag(tag, credential.mac, transport, exporter) {
					return index, true
				}
			}
			return 0, false
		}
		var matchedIndex uint32
		matched := false
		if !matched && source.IsValid() {
			if candidates, loaded := authenticator.addressCache.Load(source, state.generation); loaded {
				matchedIndex, matched = tryCandidates(candidates)
			}
		}
		if matched {
			if authentication, current := authenticator.publishMatch(state, matchedIndex, source); current {
				return authentication, nil
			}
			continue
		}

		work := len(state.credentials) - triedCount
		permit, allowed := authenticator.guard.Acquire(source, work)
		if !allowed {
			return Authentication{}, authscan.ErrLimited
		}
		for index, credential := range state.credentials {
			if wasTried(uint32(index)) || !validAuthTag(tag, credential.mac, transport, exporter) {
				continue
			}
			matchedIndex, matched = uint32(index), true
			break
		}
		if matched {
			if authentication, current := authenticator.publishMatch(state, matchedIndex, source); current {
				permit.Done(true)
				return authentication, nil
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
	index, exists := state.byKey[selected.key]
	if !exists || state.credentials[index].identity != selected.Identity {
		return Authentication{}, ErrAuthentication
	}
	candidates, _ := authenticator.addressCache.Load(source, state.generation)
	var permit *authscan.Permit[netip.Addr]
	var allowed bool
	if source.IsValid() && candidates.Contains(uint32(index)) {
		// Only a previously authenticated candidate can bypass source cooldown.
		permit, allowed = authenticator.guard.AcquireKnown(source, 1)
	} else {
		permit, allowed = authenticator.guard.Acquire(source, 1)
	}
	if !allowed {
		return Authentication{}, authscan.ErrLimited
	}
	defer permit.Release()
	if !validAuthTag(frame[:], state.credentials[index].mac, transport, exporter) {
		permit.Done(false)
		return Authentication{}, ErrAuthentication
	}
	authenticator.admit(source, state.generation, uint32(index))
	return selected, nil
}

func (authenticator *Authenticator) admit(source netip.Addr, generation uint64, index uint32) {
	if source.IsValid() {
		authenticator.addressCache.Store(source, generation, index)
		authenticator.guard.Reset(source)
	}
}

func (authenticator *Authenticator) publishMatch(
	state *authGeneration,
	index uint32,
	source netip.Addr,
) (Authentication, bool) {
	authenticator.updateMu.RLock()
	defer authenticator.updateMu.RUnlock()
	if authenticator.users.Load() != state || int(index) >= len(state.credentials) {
		return Authentication{}, false
	}
	credential := state.credentials[index]
	authenticator.admit(source, state.generation, index)
	return Authentication{Identity: credential.identity, key: credential.key}, true
}

// IsCurrent reports whether an authenticated carrier still belongs to a
// currently published user with the same credential and reporting identity.
func (authenticator *Authenticator) IsCurrent(authentication Authentication) bool {
	state := authenticator.users.Load()
	if state == nil {
		return false
	}
	index, exists := state.byKey[authentication.key]
	return exists && state.credentials[index].identity == authentication.Identity
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
