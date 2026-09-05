package core

import (
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/common/counter"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
)

func TestTrafficDrainPreservesConcurrentWrites(t *testing.T) {
	c := New(nil, nil)
	c.dispatcher = &dispatcher.DefaultDispatcher{}
	c.users.uidMap["user"] = 7
	counts := counter.NewTrafficCounter()
	c.dispatcher.Counter.Store("node", counts)
	storage := counts.GetCounter("user")
	const writers, iterations = 8, 50000
	var wg sync.WaitGroup
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			for range iterations {
				storage.UpCounter.Add(1)
				storage.DownCounter.Add(2)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var up, down int64
	drain := func() {
		values, err := c.GetUserTrafficSlice("node", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			up += value.Upload
			down += value.Download
		}
	}
	for {
		drain()
		select {
		case <-done:
			drain()
			if up != writers*iterations || down != 2*writers*iterations {
				t.Fatalf("lost traffic: up=%d down=%d", up, down)
			}
			return
		default:
		}
	}
}

func TestTrafficBelowThresholdIsRetained(t *testing.T) {
	c := New(nil, nil)
	c.dispatcher = &dispatcher.DefaultDispatcher{}
	c.users.uidMap["user"] = 7
	counts := counter.NewTrafficCounter()
	c.dispatcher.Counter.Store("node", counts)
	counts.Tx("user", 50)
	got, _ := c.GetUserTrafficSlice("node", 100)
	if len(got) != 0 {
		t.Fatal("reported below threshold")
	}
	counts.Tx("user", 60)
	got, _ = c.GetUserTrafficSlice("node", 100)
	if len(got) != 1 || got[0].Upload != 110 {
		t.Fatalf("traffic = %+v", got)
	}
}
