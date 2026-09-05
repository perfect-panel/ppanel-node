package dispatcher

import (
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

var _ buf.TimeoutReader = (*CounterReader)(nil)

type CounterReader struct {
	Reader  buf.TimeoutReader
	Counter *atomic.Int64
}

func (c *CounterReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBufferTimeout(timeout)
	if mb.Len() > 0 {
		c.Counter.Add(int64(mb.Len()))
	}
	return mb, err
}

func (c *CounterReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.Reader.ReadMultiBuffer()
	if mb.Len() > 0 {
		c.Counter.Add(int64(mb.Len()))
	}
	return mb, err
}
