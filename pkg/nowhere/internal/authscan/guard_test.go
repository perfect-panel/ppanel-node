package authscan

import (
	"testing"
	"time"
)

func TestGuardBoundsWorkAndPenalizesFailures(t *testing.T) {
	now := time.Unix(100, 0)
	guard := NewGuard[int](func(value int) uint64 { return uint64(value) }, GuardOptions{
		WorkRate: 10, WorkBurst: 10, Concurrent: 1, TimeFunc: func() time.Time { return now },
	})
	permit, allowed := guard.Acquire(1, 6)
	if !allowed {
		t.Fatal("initial scan was rejected")
	}
	if _, allowed = guard.Acquire(2, 1); allowed {
		t.Fatal("concurrent scan bypassed the slot limit")
	}
	permit.Done(false)
	if _, allowed = guard.Acquire(1, 1); allowed {
		t.Fatal("failed source bypassed backoff")
	}
	if _, allowed = guard.Acquire(2, 5); allowed {
		t.Fatal("work budget was exceeded")
	}
	now = now.Add(time.Second)
	permit, allowed = guard.Acquire(1, 5)
	if !allowed {
		t.Fatal("refilled scan was rejected")
	}
	permit.Done(true)
	permit, allowed = guard.Acquire(1, 5)
	if !allowed {
		t.Fatal("successful source remained penalized")
	}
	permit.Done(true)
}

func TestGuardBoundsFailureEntries(t *testing.T) {
	now := time.Unix(100, 0)
	guard := NewGuard[int](func(int) uint64 { return 0 }, GuardOptions{
		WorkRate: 1 << 20, WorkBurst: 1 << 20, Concurrent: 1, TimeFunc: func() time.Time { return now },
	})
	for key := 0; key < entriesPerShard*2; key++ {
		permit, allowed := guard.Acquire(key, 1)
		if !allowed {
			t.Fatalf("scan %d was rejected", key)
		}
		permit.Done(false)
	}
	if entries := len(guard.shards[0].entries); entries != entriesPerShard {
		t.Fatalf("entries = %d, want %d", entries, entriesPerShard)
	}
}

func TestKnownCandidatesShareWorkAndConcurrencyLimits(t *testing.T) {
	now := time.Unix(100, 0)
	guard := NewGuard[int](func(value int) uint64 { return uint64(value) }, GuardOptions{
		WorkRate: 3, WorkBurst: 3, Concurrent: 1, TimeFunc: func() time.Time { return now },
	})
	failed, allowed := guard.Acquire(1, 1)
	if !allowed {
		t.Fatal("initial scan rejected")
	}
	failed.Done(false)
	if !guard.SourceBlocked(1) {
		t.Fatal("failure did not arm source cooldown")
	}
	known, allowed := guard.AcquireKnown(1, 1)
	if !allowed {
		t.Fatal("known candidate was rejected by source cooldown")
	}
	if _, allowed := guard.AcquireKnown(2, 1); allowed {
		t.Fatal("known candidate bypassed concurrency limit")
	}
	known.Release()
	known.Done(true)
	if !guard.SourceBlocked(1) {
		t.Fatal("released candidate reset source cooldown")
	}
	ordinary, allowed := guard.Acquire(2, 1)
	if !allowed {
		t.Fatal("remaining shared work token was unavailable")
	}
	ordinary.Release()
	if _, allowed := guard.AcquireKnown(1, 1); allowed {
		t.Fatal("known candidate bypassed exhausted shared work budget")
	}
	now = now.Add(time.Second)
	if guard.SourceBlocked(1) {
		t.Fatal("source cooldown did not expire")
	}
	known, allowed = guard.AcquireKnown(1, 1)
	if !allowed {
		t.Fatal("refilled work budget was unavailable")
	}
	known.Release()
}
