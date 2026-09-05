package dispatcher

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type eofReader struct{ timeout time.Duration }

func (r *eofReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Write([]byte("tail"))
	return buf.MultiBuffer{b}, io.EOF
}
func (r *eofReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	r.timeout = timeout
	return r.ReadMultiBuffer()
}

func TestCounterReaderPreservesFinalBytesAndTimeout(t *testing.T) {
	for _, timed := range []bool{false, true} {
		source := &eofReader{}
		count := &atomic.Int64{}
		reader := &CounterReader{Reader: source, Counter: count}
		var mb buf.MultiBuffer
		var err error
		if timed {
			mb, err = reader.ReadMultiBufferTimeout(50 * time.Millisecond)
		} else {
			mb, err = reader.ReadMultiBuffer()
		}
		if err != io.EOF || mb.Len() != 4 || count.Load() != 4 {
			t.Fatalf("final read: bytes=%d count=%d err=%v", mb.Len(), count.Load(), err)
		}
		buf.ReleaseMulti(mb)
		if timed && source.timeout != 50*time.Millisecond {
			t.Fatalf("timeout = %s", source.timeout)
		}
	}
}

func TestSniffingCachePreservesPayloadReturnedWithEOF(t *testing.T) {
	count := &atomic.Int64{}
	reader := &cachedReader{reader: &CounterReader{Reader: &eofReader{}, Counter: count}}
	sniffed := buf.New()
	defer sniffed.Release()
	if err := reader.Cache(sniffed, time.Second); err != io.EOF {
		t.Fatalf("cache error = %v", err)
	}
	mb, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if mb.Len() != 4 || err != io.EOF || count.Load() != 4 {
		t.Fatalf("cached tail: bytes=%d count=%d err=%v", mb.Len(), count.Load(), err)
	}
}
