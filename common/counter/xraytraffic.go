package counter

import (
	"sync/atomic"

	fstats "github.com/xtls/xray-core/features/stats"
)

var _ fstats.Counter = (*XrayTrafficCounter)(nil)

type XrayTrafficCounter struct {
	V *atomic.Int64
}

func (c *XrayTrafficCounter) Value() int64 {
	return c.V.Load()
}

func (c *XrayTrafficCounter) Set(newValue int64) int64 {
	return c.V.Swap(newValue)
}

func (c *XrayTrafficCounter) Add(delta int64) int64 {
	return c.V.Add(delta)
}
