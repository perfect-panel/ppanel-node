package rate

import (
	"context"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	ctx     context.Context
	writer  buf.Writer
	limiter *ratelimit.Bucket
}

func NewRateLimitWriter(writer buf.Writer, limiter *ratelimit.Bucket) buf.Writer {
	return NewRateLimitWriterContext(context.Background(), writer, limiter)
}

func NewRateLimitWriterContext(ctx context.Context, writer buf.Writer, limiter *ratelimit.Bucket) buf.Writer {
	return &Writer{
		ctx:     ctx,
		writer:  writer,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := wait(w.ctx, w.limiter, int64(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

type Reader struct {
	ctx     context.Context
	reader  buf.Reader
	limiter *ratelimit.Bucket
}

func NewRateLimitReader(ctx context.Context, reader buf.Reader, limiter *ratelimit.Bucket) buf.Reader {
	return &Reader{ctx: ctx, reader: reader, limiter: limiter}
}
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	data, err := r.reader.ReadMultiBuffer()
	if waitErr := wait(r.ctx, r.limiter, int64(data.Len())); waitErr != nil {
		buf.ReleaseMulti(data)
		return nil, waitErr
	}
	return data, err
}
func (r *Reader) Interrupt() { common.Interrupt(r.reader) }

func wait(ctx context.Context, limiter *ratelimit.Bucket, n int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := limiter.Take(n)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
