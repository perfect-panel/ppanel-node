package counter

import (
	"sync"
	"sync/atomic"
)

type TrafficCounter struct {
	Counters sync.Map
}

type TrafficStorage struct {
	UpCounter   atomic.Int64
	DownCounter atomic.Int64
}

func NewTrafficCounter() *TrafficCounter {
	return &TrafficCounter{}
}

func (c *TrafficCounter) GetCounter(uuid string) *TrafficStorage {
	if cts, ok := c.Counters.Load(uuid); ok {
		return cts.(*TrafficStorage)
	}
	newStorage := &TrafficStorage{}
	if cts, loaded := c.Counters.LoadOrStore(uuid, newStorage); loaded {
		return cts.(*TrafficStorage)
	}
	return newStorage
}

func (c *TrafficCounter) GetUpCount(uuid string) int64 {
	if cts, ok := c.Counters.Load(uuid); ok {
		return cts.(*TrafficStorage).UpCounter.Load()
	}
	return 0
}

func (c *TrafficCounter) GetDownCount(uuid string) int64 {
	if cts, ok := c.Counters.Load(uuid); ok {
		return cts.(*TrafficStorage).DownCounter.Load()
	}
	return 0
}

func (c *TrafficCounter) Len() int {
	length := 0
	c.Counters.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	return length
}

func (c *TrafficCounter) Reset(uuid string) {
	if cts, ok := c.Counters.Load(uuid); ok {
		cts.(*TrafficStorage).UpCounter.Store(0)
		cts.(*TrafficStorage).DownCounter.Store(0)
	}
}

func (c *TrafficCounter) Delete(uuid string) {
	c.Counters.Delete(uuid)
}

func (c *TrafficCounter) Rx(uuid string, n int) {
	cts := c.GetCounter(uuid)
	cts.DownCounter.Add(int64(n))
}

func (c *TrafficCounter) Tx(uuid string, n int) {
	cts := c.GetCounter(uuid)
	cts.UpCounter.Add(int64(n))
}
