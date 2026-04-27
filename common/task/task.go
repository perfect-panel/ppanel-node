package task

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func(context.Context) error
	Access   sync.RWMutex
	Running  bool
	Stop     chan struct{}
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func (t *Task) Start(first bool) error {
	t.Access.Lock()
	if t.Running {
		t.Access.Unlock()
		return nil
	}
	t.Running = true
	t.Stop = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.wg.Add(1)
	t.Access.Unlock()
	go func() {
		defer t.wg.Done()
		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		if first {
			if err := t.ExecuteWithTimeout(ctx); err != nil {
				return
			}
		}

		for {
			timer.Reset(t.Interval)
			select {
			case <-timer.C:
				// continue
			case <-t.Stop:
				return
			case <-ctx.Done():
				return
			}

			if err := t.ExecuteWithTimeout(ctx); err != nil {
				log.Errorf("Task %s execution error: %v", t.Name, err)
				return
			}
		}
	}()

	return nil
}

func (t *Task) ExecuteWithTimeout(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, min(5*t.Interval, 5*time.Minute))
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- t.Execute(ctx)
	}()

	select {
	case <-ctx.Done():
		if errors.Is(parent.Err(), context.Canceled) {
			return nil
		}
		log.Errorf("Task %s execution timed out", t.Name)
		return nil
	case err := <-done:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
}

func (t *Task) safeStop() {
	t.Access.Lock()
	if t.Running {
		t.Running = false
		if t.cancel != nil {
			t.cancel()
		}
		close(t.Stop)
	}
	t.Access.Unlock()
}

func (t *Task) Close() {
	t.safeStop()
	t.wg.Wait()
	log.Warningf("Task %s stopped", t.Name)
}
