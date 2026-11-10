// SPDX-License-Identifier: GPL-3.0-or-later
package authscan

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
)

const (
	shardCount        = 64
	entriesPerShard   = 64
	candidateCapacity = 4
)

// CandidateCapacity is the maximum remembered credentials per source.
const CandidateCapacity = candidateCapacity

type Candidates struct {
	generation uint64
	indexes    [candidateCapacity]uint64
	count      uint8
}

func (c Candidates) Count() int            { return int(c.count) }
func (c Candidates) At(index int) uint64   { return c.indexes[index] }
func (c Candidates) First() (uint64, bool) { return c.indexes[0], c.count > 0 }
func (c Candidates) Contains(value uint64) bool {
	for index := 0; index < int(c.count); index++ {
		if c.indexes[index] == value {
			return true
		}
	}
	return false
}

type Cache[K comparable] struct {
	hash              func(K) uint64
	perShard          int
	minimumGeneration atomic.Uint64
	shards            [shardCount]cacheShard[K]
}

type cacheShard[K comparable] struct {
	access  sync.RWMutex
	entries map[K]Candidates
}

func NewCache[K comparable](hash func(K) uint64) *Cache[K] {
	return NewCacheWithCapacity(hash, entriesPerShard)
}

// NewCacheWithCapacity bounds each shard at the given number of entries instead of the
// default. A service whose user count exceeds the default total — shardCount times
// entriesPerShard — otherwise evicts entries faster than clients return, so every
// connection pays the full scan the cache exists to avoid.
func NewCacheWithCapacity[K comparable](hash func(K) uint64, perShard int) *Cache[K] {
	if perShard < 1 {
		perShard = entriesPerShard
	}
	return &Cache[K]{hash: hash, perShard: perShard}
}

func (c *Cache[K]) Load(key K, generation uint64) (Candidates, bool) {
	shard := &c.shards[c.hash(key)&(shardCount-1)]
	shard.access.RLock()
	candidates, loaded := shard.entries[key]
	shard.access.RUnlock()
	if !loaded || candidates.generation != generation {
		return Candidates{}, false
	}
	return candidates, true
}

func (c *Cache[K]) Store(key K, generation uint64, userIndex uint64) {
	if generation < c.minimumGeneration.Load() {
		return
	}
	shard := &c.shards[c.hash(key)&(shardCount-1)]
	shard.access.Lock()
	defer shard.access.Unlock()
	// RemapGeneration advances the floor before taking every shard lock. Store
	// may have passed the optimistic check above while a remap was in progress,
	// so validate again while holding the target shard lock.
	if generation < c.minimumGeneration.Load() {
		return
	}
	if shard.entries == nil {
		// Sized for the common case, not the ceiling: perShard only bounds growth, and
		// preallocating it in every shard would charge a listener with a few active keys
		// for a capacity it may never use.
		shard.entries = make(map[K]Candidates, min(c.perShard, entriesPerShard))
	}
	candidates, loaded := shard.entries[key]
	if loaded && candidates.generation == generation && candidates.count > 0 && candidates.indexes[0] == userIndex {
		return
	}
	if !loaded && len(shard.entries) >= c.perShard {
		for evicted := range shard.entries {
			delete(shard.entries, evicted)
			break
		}
	}
	if candidates.generation != generation {
		candidates = Candidates{generation: generation}
	}
	position := int(candidates.count)
	for index := 0; index < int(candidates.count); index++ {
		if candidates.indexes[index] == userIndex {
			position = index
			break
		}
	}
	// Only a value that was not already present adds one. Counting a promotion as an
	// addition would expose slots that were never written, and callers read every slot up
	// to count as a real candidate.
	added := position == int(candidates.count)
	if position >= candidateCapacity {
		position = candidateCapacity - 1
	}
	copy(candidates.indexes[1:position+1], candidates.indexes[:position])
	candidates.indexes[0] = userIndex
	if added && candidates.count < candidateCapacity {
		candidates.count++
	}
	shard.entries[key] = candidates
}

// RemapGeneration carries cached candidates into a newly published immutable
// user table. mapping is indexed by the old user index; a negative or missing
// value drops a credential that changed or disappeared.
func (c *Cache[K]) RemapGeneration(from, to uint64, mapping []int) {
	if from == 0 || from == to {
		return
	}
	c.minimumGeneration.Store(to)
	for shardIndex := range c.shards {
		shard := &c.shards[shardIndex]
		shard.access.Lock()
		for key, candidates := range shard.entries {
			if candidates.generation != from {
				delete(shard.entries, key)
				continue
			}
			remapped := Candidates{generation: to}
			for candidateIndex := 0; candidateIndex < candidates.Count(); candidateIndex++ {
				oldID := candidates.At(candidateIndex)
				if oldID >= uint64(len(mapping)) || mapping[int(oldID)] < 0 {
					continue
				}
				newIndex := uint64(mapping[int(oldID)])
				if remapped.Contains(newIndex) {
					continue
				}
				remapped.indexes[remapped.count] = newIndex
				remapped.count++
				if remapped.Count() == candidateCapacity {
					break
				}
			}
			if remapped.Count() == 0 {
				delete(shard.entries, key)
			} else {
				shard.entries[key] = remapped
			}
		}
		shard.access.Unlock()
	}
}

func HashAddr(addr netip.Addr) uint64 {
	if !addr.IsValid() {
		return 0
	}
	if addr.Is4() {
		value := addr.As4()
		return mix(uint64(binary.LittleEndian.Uint32(value[:])))
	}
	value := addr.As16()
	return mix(binary.LittleEndian.Uint64(value[:8]) ^ binary.LittleEndian.Uint64(value[8:]))
}

func HashAddrPort(addr netip.AddrPort) uint64 {
	return mix(HashAddr(addr.Addr()) ^ uint64(addr.Port())*0x9e3779b97f4a7c15)
}

func mix(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	return value ^ value>>31
}
