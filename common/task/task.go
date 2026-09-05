package task

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/perfect-panel/ppanel-node/common/logx"
)

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func(context.Context) error
	ReloadCh chan struct{}
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
}

func (t *Task) Start(first bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		return nil
	}
	if t.Interval <= 0 || t.Execute == nil {
		return errors.New("invalid periodic task")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.cancel, t.done = cancel, done
	go func() {
		defer close(done)
		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		if first {
			t.execute(ctx)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				t.execute(ctx)
				timer.Reset(t.Interval)
			}
		}
	}()
	return nil
}

func (t *Task) execute(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, min(5*t.Interval, 5*time.Minute))
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- t.Execute(ctx) }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		if parent.Err() == nil && t.ReloadCh != nil {
			logx.Task(t.Name).Warn("任务执行超时，已投递重载信号")
			select {
			case t.ReloadCh <- struct{}{}:
			default:
			}
		}
		// A cancelled task must finish before its controller or core is closed.
		// Never overlap it with a new run or mutate a retired core in the background.
		err = <-done
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		logx.Task(t.Name).WithError(err).Error("任务执行失败")
	}
}

func (t *Task) Close() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	t.mu.Lock()
	if t.done == done {
		t.cancel, t.done = nil, nil
	}
	t.mu.Unlock()
}
