package rate

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common/buf"
)

type testReader struct{}

func (testReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, _ = b.Write([]byte("payload"))
	return buf.MultiBuffer{b}, io.EOF
}

type testWriter struct{ writes int }

func (w *testWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	w.writes++
	buf.ReleaseMulti(b)
	return nil
}

func TestRateLimitedTransfersCancelWithoutForwarding(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			bucket := ratelimit.NewBucket(time.Hour, 1)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if direction == "upload" {
				data, err := NewRateLimitReader(ctx, testReader{}, bucket).ReadMultiBuffer()
				if !errors.Is(err, context.DeadlineExceeded) || len(data) != 0 {
					t.Fatalf("upload wait: %v %v", data, err)
				}
			} else {
				writer := &testWriter{}
				data, _ := testReader{}.ReadMultiBuffer()
				err := NewRateLimitWriterContext(ctx, writer, bucket).WriteMultiBuffer(data)
				if !errors.Is(err, context.DeadlineExceeded) || writer.writes != 0 {
					t.Fatalf("download wait: %d %v", writer.writes, err)
				}
			}
		})
	}
}
