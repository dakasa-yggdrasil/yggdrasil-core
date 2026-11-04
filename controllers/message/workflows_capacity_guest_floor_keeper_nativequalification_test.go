//go:build linux && nativequalification

package message

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOriginalFloorKeeperJoinsAdmittedProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticks := make(chan time.Time, 2)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	join := startOriginalFloorKeeper(ctx, ticks, func() {}, func(original context.Context) error {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			if original.Err() != nil {
				return original.Err()
			}
			return nil
		case <-original.Done():
			return original.Err()
		}
	})
	ticks <- time.Now()
	<-started
	done := make(chan error, 1)
	go func() { done <- join(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("returned before admitted probe closed: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	if ctx.Err() != nil {
		t.Fatal("normal join cancelled original context", ctx.Err())
	}
	ticks <- time.Now()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("original probe not joined")
	}
	if calls.Load() != 1 {
		t.Fatalf("new probe scheduled after join: %d", calls.Load())
	}
}

func TestOriginalFloorKeeperPropagatesProbeAndParentFailure(t *testing.T) {
	t.Run("probe_error", func(t *testing.T) {
		ticks := make(chan time.Time, 1)
		expected := errors.New("original probe failure")
		started := make(chan struct{})
		join := startOriginalFloorKeeper(context.Background(), ticks, func() {}, func(context.Context) error { close(started); return expected })
		ticks <- time.Now()
		<-started
		if err := join(context.Background()); !errors.Is(err, expected) {
			t.Fatal("probe error lost", err)
		}
	})
	t.Run("parent_cancel", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		ticks := make(chan time.Time, 1)
		started := make(chan struct{})
		join := startOriginalFloorKeeper(parent, ticks, func() {}, func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })
		ticks <- time.Now()
		<-started
		cancel()
		if err := join(context.Background()); !errors.Is(err, context.Canceled) {
			t.Fatal("parent cancellation lost", err)
		}
	})
}

func TestOriginalFloorKeeperRetirementDeadlineCancelsAndJoins(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticks := make(chan time.Time, 1)
	started, closed := make(chan struct{}), make(chan struct{})
	join := startOriginalFloorKeeper(parent, ticks, func() {}, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(closed)
		return ctx.Err()
	})
	ticks <- time.Now()
	<-started
	retirement, stop := context.WithTimeout(parent, 40*time.Millisecond)
	defer stop()
	if err := join(retirement); !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline did not stop original probe", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("probe was not joined")
	}
	if parent.Err() != nil {
		t.Fatal("retirement cancellation changed parent", parent.Err())
	}
}

func TestOriginalFloorKeeperConcurrentJoinOnce(t *testing.T) {
	ticks := make(chan time.Time)
	var stopped atomic.Int32
	join := startOriginalFloorKeeper(context.Background(), ticks, func() { stopped.Add(1) }, func(context.Context) error { t.Error("unexpected probe"); return nil })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := join(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if stopped.Load() != 1 {
		t.Fatal("ticker owner not joined exactly once", stopped.Load())
	}
}
