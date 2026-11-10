// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"errors"
	"maps"
	"sync"
	"sync/atomic"
)

const authShardCount = 256

// Cached candidates are opaque credential IDs, not offsets into a user list.
// IDs are never reused, so unchanged candidates survive updates without a
// whole-cache remap; removed/reassigned credentials fail the current-ID lookup.
const authCacheGeneration uint64 = 1

var credentialSerial atomic.Uint64

// ErrStaleAuthUpdate means a prepared delta no longer targets the current table.
var ErrStaleAuthUpdate = errors.New("nowhere: authentication table changed; prepare update again")

// ErrDuplicateIdentity identifies multiple keys assigned to one name in a batch.
var ErrDuplicateIdentity = errors.New("nowhere: duplicate user identity")

type authCredential struct {
	identity string
	key      AuthKey
	id       uint64
	shared   [32]byte
	mac      authenticationMAC
	morph    MorphKeys
}

func (c *authCredential) authentication() Authentication {
	return Authentication{Identity: c.identity, key: c.key, id: c.id}
}

type authShard struct {
	byKey map[AuthKey]*authCredential
	byID  map[uint64]*authCredential
}

// Immutable once published. Delta updates clone only affected index shards;
// unchanged credentials and all of their derived keys remain shared.
type authGeneration struct {
	generation uint64
	count      int
	shards     [authShardCount]*authShard
	names      [authShardCount]map[string]*authCredential
}

func (s *authGeneration) credential(key AuthKey) *authCredential {
	if shard := s.shards[key[0]]; shard != nil {
		return shard.byKey[key]
	}
	return nil
}
func (s *authGeneration) candidate(id uint64) *authCredential {
	if shard := s.shards[byte(id)]; shard != nil {
		return shard.byID[id]
	}
	return nil
}
func identityShard(name string) byte {
	h := uint64(14695981039346656037)
	for i := range len(name) {
		h = (h ^ uint64(name[i])) * 1099511628211
	}
	return byte(h ^ (h >> 32))
}
func (s *authGeneration) user(name string) *authCredential { return s.names[identityShard(name)][name] }
func (s *authGeneration) each(visit func(*authCredential) bool) {
	for _, shard := range s.shards {
		if shard != nil {
			for _, c := range shard.byKey {
				if !visit(c) {
					return
				}
			}
		}
	}
}

type AuthUpdate struct {
	mu    sync.Mutex
	state *authGeneration
	base  *authGeneration
	owner *Authenticator
}

type authMutation struct {
	state   *authGeneration
	keys    [authShardCount]bool
	names   [authShardCount]bool
	changed bool
}

func (m *authMutation) keyShard(index byte) *authShard {
	if !m.keys[index] {
		old := m.state.shards[index]
		copy := &authShard{byKey: make(map[AuthKey]*authCredential), byID: make(map[uint64]*authCredential)}
		if old != nil {
			copy.byKey = maps.Clone(old.byKey)
			copy.byID = maps.Clone(old.byID)
		}
		m.state.shards[index] = copy
		m.keys[index] = true
	}
	return m.state.shards[index]
}
func (m *authMutation) nameShard(name string) map[string]*authCredential {
	i := identityShard(name)
	if !m.names[i] {
		copy := maps.Clone(m.state.names[i])
		if copy == nil {
			copy = make(map[string]*authCredential)
		}
		m.state.names[i] = copy
		m.names[i] = true
	}
	return m.state.names[i]
}
func (m *authMutation) remove(c *authCredential) {
	shard := m.keyShard(c.key[0])
	delete(shard.byKey, c.key)
	delete(shard.byID, c.id)
	delete(m.nameShard(c.identity), c.identity)
	m.state.count--
	m.changed = true
}
func (m *authMutation) put(c *authCredential) {
	shard := m.keyShard(c.key[0])
	shard.byKey[c.key] = c
	shard.byID[c.id] = c
	m.nameShard(c.identity)[c.identity] = c
	m.state.count++
	m.changed = true
}

// PrepareAuthUpdate prepares an initial/full replacement table. Applications
// with additions/removals should use Authenticator.PrepareChanges instead.
func PrepareAuthUpdate(records []User) (*AuthUpdate, error) {
	state, err := prepareChanges(&authGeneration{}, records, nil)
	if err != nil {
		return nil, err
	}
	return &AuthUpdate{state: state}, nil
}

// PrepareChanges stages upserts and identity removals against one immutable
// snapshot. No state is changed until Commit. Concurrent writers must re-prepare
// if Commit returns ErrStaleAuthUpdate; stale deltas never overwrite newer ones.
func (a *Authenticator) PrepareChanges(upserts []User, remove []string) (*AuthUpdate, error) {
	base := a.users.Load()
	state, err := prepareChanges(base, upserts, remove)
	if err != nil {
		return nil, err
	}
	return &AuthUpdate{owner: a, base: base, state: state}, nil
}

func prepareChanges(base *authGeneration, upserts []User, remove []string) (*authGeneration, error) {
	next := *base
	m := authMutation{state: &next}
	for _, name := range remove {
		if old := m.state.user(name); old != nil {
			m.remove(old)
		}
	}
	type pendingUser struct {
		name   string
		shared [32]byte
	}
	pending := make([]pendingUser, 0, len(upserts))
	seen := make(map[string]struct{}, len(upserts))
	for _, user := range upserts {
		if user.Name == "" {
			return nil, ErrInvalidUser
		}
		if !ValidSharedKey(user.Key) {
			return nil, ErrInvalidSharedKey
		}
		if _, exists := seen[user.Name]; exists {
			return nil, ErrDuplicateIdentity
		}
		seen[user.Name] = struct{}{}
		shared := [32]byte(user.Key)
		if old := m.state.user(user.Name); old != nil {
			if old.shared == shared {
				continue
			}
			m.remove(old)
		}
		pending = append(pending, pendingUser{user.Name, shared})
	}
	// Remove all replaced credentials before inserting any, so a batch may
	// atomically exchange keys between identities without transient duplicates.
	for _, user := range pending {
		key, _ := DeriveAuthKey(user.shared[:])
		if m.state.credential(key) != nil {
			return nil, ErrDuplicateAuthKey
		}
		c := &authCredential{identity: user.name, key: key, shared: user.shared}
		if previous := base.credential(key); previous != nil && previous.shared == user.shared {
			c.mac, c.morph = previous.mac, previous.morph
		} else {
			c.mac = newAuthenticationMAC(key)
			c.morph = deriveMorphKeys(user.shared[:])
		}
		serial := credentialSerial.Add(1)
		if serial >= 1<<56 {
			return nil, errors.New("nowhere: credential ID space exhausted")
		}
		c.id = serial<<8 | uint64(key[0])
		m.put(c)
	}
	if !m.changed {
		return base, nil
	}
	for i := range authShardCount {
		if m.keys[i] && len(next.shards[i].byKey) == 0 {
			next.shards[i] = nil
		}
		if m.names[i] && len(next.names[i]) == 0 {
			next.names[i] = nil
		}
	}
	return &next, nil
}

func (a *Authenticator) Commit(update *AuthUpdate) error {
	if update == nil {
		return errors.New("nowhere: invalid authentication update")
	}
	update.mu.Lock()
	defer update.mu.Unlock()
	if update.state == nil {
		return errors.New("nowhere: invalid authentication update")
	}
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	current := a.users.Load()
	if update.owner != nil && (update.owner != a || update.base != current) {
		return ErrStaleAuthUpdate
	}
	state := update.state
	if state != current {
		if update.owner == nil && current.count != 0 {
			// Preserve live credentials/candidate IDs for callers of the full
			// replacement API, including a replacement that only changes order.
			state.each(func(c *authCredential) bool {
				old := current.credential(c.key)
				if old != nil && old.identity == c.identity && old.shared == c.shared {
					shard := state.shards[c.key[0]]
					shard.byKey[c.key] = old
					delete(shard.byID, c.id)
					shard.byID[old.id] = old
					state.names[identityShard(c.identity)][c.identity] = old
				}
				return true
			})
		}
		state.generation = current.generation + 1
		a.users.Store(state)
	}
	update.state, update.base, update.owner = nil, nil, nil
	return nil
}
