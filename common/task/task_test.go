package task

import (
	"context"
	"testing"
	"time"
)

func TestCloseCancelsAndWaitsForExecution(t *testing.T) {
	started, cancelled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	task := &Task{Interval: time.Hour, Execute: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-finish
		return ctx.Err()
	}}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	<-started
	closed := make(chan struct{})
	go func() { task.Close(); close(closed) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("execution not cancelled")
	}
	select {
	case <-closed:
		t.Fatal("Close returned while execution was still running")
	default:
	}
	close(finish)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	task.Close()
}
