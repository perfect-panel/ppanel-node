// SPDX-License-Identifier: GPL-3.0-or-later
package authscan

import (
	"errors"
	"runtime"
	"sync"
	"time"
)

var ErrLimited = errors.New("authentication scan limited")

type GuardOptions struct {
	WorkRate   int
	WorkBurst  int
	Concurrent int
	TimeFunc   func() time.Time
}

type Guard[K comparable] struct {
	hash    func(K) uint64
	now     func() time.Time
	slots   chan struct{}
	rate    float64
	burst   float64
	budget  sync.Mutex
	tokens  float64
	updated time.Time
	shards  [shardCount]failureShard[K]
}

type failureShard[K comparable] struct {
	access  sync.Mutex
	entries map[K]failureEntry
}

type failureEntry struct {
	failures     uint8
	blockedUntil time.Time
	lastFailure  time.Time
}

type Permit[K comparable] struct {
	guard *Guard[K]
	key   K
	once  sync.Once
}

func NewGuard[K comparable](hash func(K) uint64, options GuardOptions) *Guard[K] {
	if options.WorkRate <= 0 {
		options.WorkRate = 1 << 18
	}
	if options.WorkBurst <= 0 {
		options.WorkBurst = options.WorkRate * 2
	}
	if options.Concurrent <= 0 {
		options.Concurrent = min(max(runtime.GOMAXPROCS(0), 1), 32)
	}
	if options.TimeFunc == nil {
		options.TimeFunc = time.Now
	}
	now := options.TimeFunc()
	return &Guard[K]{hash: hash, now: options.TimeFunc, slots: make(chan struct{}, options.Concurrent),
		rate: float64(options.WorkRate), burst: float64(options.WorkBurst),
		tokens: float64(options.WorkBurst), updated: now}
}

func (g *Guard[K]) Acquire(key K, work int) (*Permit[K], bool) {
	return g.acquire(key, work, false)
}

// AcquireKnown skips only the source's failure cooldown. Callers must restrict
// this path to previously authenticated candidates; work tokens and concurrent
// slots are shared with Acquire and remain mandatory.
func (g *Guard[K]) AcquireKnown(key K, work int) (*Permit[K], bool) {
	return g.acquire(key, work, true)
}

// SourceBlocked reports whether an ordinary scan would be refused by the
// source cooldown. It does not reserve work or a concurrency slot.
func (g *Guard[K]) SourceBlocked(key K) bool {
	return g.blocked(key, g.now())
}

func (g *Guard[K]) acquire(key K, work int, known bool) (*Permit[K], bool) {
	now := g.now()
	if !known && g.blocked(key, now) {
		return nil, false
	}
	select {
	case g.slots <- struct{}{}:
	default:
		return nil, false
	}
	if !g.consume(now, work) {
		<-g.slots
		return nil, false
	}
	return &Permit[K]{guard: g, key: key}, true
}

func (p *Permit[K]) Done(success bool) {
	if p == nil || p.guard == nil {
		return
	}
	p.once.Do(func() {
		if success {
			p.guard.Reset(p.key)
		} else {
			p.guard.fail(p.key, p.guard.now())
		}
		<-p.guard.slots
	})
}

// Release returns the permit without judging the key. Use it when work finished
// inconclusively rather than in failure — for instance when a cached guess did not match
// and the caller is about to search properly. Reporting that as a failure would arm the
// key's backoff and make the very next Acquire refuse the search that was meant to follow.
//
// Release settles the permit: it shares Done's one-shot guard, so a later Done on the same
// permit is silently ignored rather than recording the verdict. A caller that may still
// need to judge the key must therefore keep the permit and call Done, not release first and
// judge afterwards.
func (p *Permit[K]) Release() {
	if p == nil || p.guard == nil {
		return
	}
	p.once.Do(func() {
		<-p.guard.slots
	})
}

func (g *Guard[K]) Reset(key K) {
	shard := &g.shards[g.hash(key)&(shardCount-1)]
	shard.access.Lock()
	delete(shard.entries, key)
	shard.access.Unlock()
}

func (g *Guard[K]) consume(now time.Time, work int) bool {
	if work < 1 {
		work = 1
	}
	g.budget.Lock()
	defer g.budget.Unlock()
	elapsed := now.Sub(g.updated)
	if elapsed > 0 {
		g.tokens = min(g.burst, g.tokens+elapsed.Seconds()*g.rate)
		g.updated = now
	}
	charge := min(float64(work), g.burst)
	if g.tokens < charge {
		return false
	}
	g.tokens -= charge
	return true
}

func (g *Guard[K]) blocked(key K, now time.Time) bool {
	shard := &g.shards[g.hash(key)&(shardCount-1)]
	shard.access.Lock()
	entry, loaded := shard.entries[key]
	shard.access.Unlock()
	return loaded && now.Before(entry.blockedUntil)
}

func (g *Guard[K]) fail(key K, now time.Time) {
	shard := &g.shards[g.hash(key)&(shardCount-1)]
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.entries == nil {
		shard.entries = make(map[K]failureEntry, entriesPerShard)
	}
	entry, loaded := shard.entries[key]
	if !loaded && len(shard.entries) >= entriesPerShard {
		for evicted := range shard.entries {
			delete(shard.entries, evicted)
			break
		}
	}
	if !loaded || now.Sub(entry.lastFailure) > 30*time.Second {
		entry.failures = 0
	}
	if entry.failures < 7 {
		entry.failures++
	}
	delay := 25 * time.Millisecond * time.Duration(1<<uint(entry.failures-1))
	entry.blockedUntil = now.Add(min(delay, 2*time.Second))
	entry.lastFailure = now
	shard.entries[key] = entry
}
