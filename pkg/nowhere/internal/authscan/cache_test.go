package authscan

import (
	"sync"
	"testing"
)

func TestCachePromotesRecentCandidatesAndInvalidatesGeneration(t *testing.T) {
	cache := NewCache[int](func(value int) uint64 { return uint64(value) })
	for index := uint64(0); index < candidateCapacity+2; index++ {
		cache.Store(7, 1, index)
	}
	candidates, loaded := cache.Load(7, 1)
	if !loaded || candidates.Count() != candidateCapacity {
		t.Fatalf("candidates = %+v, loaded=%v", candidates, loaded)
	}
	if first, _ := candidates.First(); first != candidateCapacity+1 || candidates.Contains(0) {
		t.Fatalf("unexpected candidate order: %+v", candidates)
	}
	if _, loaded = cache.Load(7, 2); loaded {
		t.Fatal("stale generation remained visible")
	}
}

func TestCacheBoundsSourceEntries(t *testing.T) {
	cache := NewCache[int](func(int) uint64 { return 0 })
	for key := 0; key < entriesPerShard*2; key++ {
		cache.Store(key, 1, uint64(key))
	}
	if entries := len(cache.shards[0].entries); entries != entriesPerShard {
		t.Fatalf("entries = %d, want %d", entries, entriesPerShard)
	}
}

// Storing a value that is already remembered promotes it rather than adding one. Counting
// a promotion as an addition would expose slots that were never written, and callers treat
// every slot up to the count as a real candidate.
func TestCachePromotionDoesNotInflateCount(t *testing.T) {
	cache := NewCache[int](func(key int) uint64 { return uint64(key) })
	for _, value := range []uint64{111, 222, 111, 222} {
		cache.Store(7, 1, value)
	}
	candidates, loaded := cache.Load(7, 1)
	if !loaded {
		t.Fatal("stored candidates were not loaded back")
	}
	if candidates.Count() != 2 {
		t.Fatalf("count = %d after four stores of two distinct values, want 2", candidates.Count())
	}
	if candidates.Contains(0) {
		t.Fatal("a slot that was never written is reported as a candidate")
	}
	if first, ok := candidates.First(); !ok || first != 222 {
		t.Fatalf("first = %d, want the most recently stored value", first)
	}
}

// A service whose key count exceeds the default total must be able to raise it, or it
// evicts entries faster than its clients return and every lookup misses.
func TestCacheWithCapacityBoundsAtTheGivenSize(t *testing.T) {
	const perShard = 512
	cache := NewCacheWithCapacity[int](func(int) uint64 { return 0 }, perShard)
	for key := range perShard * 2 {
		cache.Store(key, 1, uint64(key))
	}
	resident := 0
	for key := range perShard * 2 {
		if _, loaded := cache.Load(key, 1); loaded {
			resident++
		}
	}
	if resident != perShard {
		t.Fatalf("resident entries = %d, want %d", resident, perShard)
	}
	// The default must be unchanged for every existing caller.
	byDefault := NewCache[int](func(int) uint64 { return 0 })
	for key := range entriesPerShard * 2 {
		byDefault.Store(key, 1, uint64(key))
	}
	resident = 0
	for key := range entriesPerShard * 2 {
		if _, loaded := byDefault.Load(key, 1); loaded {
			resident++
		}
	}
	if resident != entriesPerShard {
		t.Fatalf("default resident entries = %d, want %d", resident, entriesPerShard)
	}
}

func TestCacheRemapsUnchangedCandidatesAcrossGeneration(t *testing.T) {
	cache := NewCache[int](func(value int) uint64 { return uint64(value) })
	for _, index := range []uint64{1, 3, 2} {
		cache.Store(7, 4, index)
	}
	cache.Store(8, 3, 1)
	cache.RemapGeneration(4, 5, []int{0, 4, -1, 1})

	candidates, loaded := cache.Load(7, 5)
	if !loaded || candidates.Count() != 2 {
		t.Fatalf("remapped candidates = %+v, loaded=%v", candidates, loaded)
	}
	if candidates.At(0) != 1 || candidates.At(1) != 4 {
		t.Fatalf("remapped candidate order = %+v", candidates)
	}
	if _, loaded = cache.Load(8, 3); loaded {
		t.Fatal("stale generation survived remap")
	}
	cache.Store(7, 4, 3)
	if candidates, loaded = cache.Load(7, 5); !loaded || candidates.Count() != 2 {
		t.Fatal("a late store from the old snapshot overwrote the remapped candidates")
	}
}

func TestCacheRemapRejectsStoreAlreadyInFlight(t *testing.T) {
	hashStarted := make(chan struct{})
	continueHash := make(chan struct{})
	var once sync.Once
	cache := NewCache(func(int) uint64 {
		once.Do(func() {
			close(hashStarted)
			<-continueHash
		})
		return 0
	})
	stored := make(chan struct{})
	go func() {
		cache.Store(1, 1, 7)
		close(stored)
	}()
	<-hashStarted
	cache.RemapGeneration(1, 2, []int{7})
	close(continueHash)
	<-stored
	if _, loaded := cache.Load(1, 1); loaded {
		t.Fatal("in-flight store repopulated an expired generation")
	}
}
