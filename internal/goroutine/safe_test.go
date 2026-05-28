package goroutine

import (
	"errors"
	"sync"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
)

// TestRunSafe_NoPanic — happy path executes fn exactly once and never
// touches the panic counter.
func TestRunSafe_NoPanic(t *testing.T) {
	metrics.ResetForTest()

	called := false
	runSafe("test_no_panic", func() { called = true })

	if !called {
		t.Fatal("fn was not executed")
	}
	if got := metrics.GoroutinePanicsSnapshot()["test_no_panic"]; got != 0 {
		t.Errorf("expected 0 panics, got %d", got)
	}
}

// TestRunSafe_RecoversAndCountsPanic — fn panics, runSafe recovers,
// counter bumps once, caller (the test) keeps running.
func TestRunSafe_RecoversAndCountsPanic(t *testing.T) {
	metrics.ResetForTest()

	runSafe("test_panic", func() {
		panic(errors.New("boom"))
	})

	if got := metrics.GoroutinePanicsSnapshot()["test_panic"]; got != 1 {
		t.Errorf("expected 1 panic, got %d", got)
	}
}

// TestRunSafe_MultiplePanics — counter accumulates across invocations
// keyed by the same name.
func TestRunSafe_MultiplePanics(t *testing.T) {
	metrics.ResetForTest()

	for range 3 {
		runSafe("test_multi_panic", func() {
			panic("kaboom")
		})
	}

	if got := metrics.GoroutinePanicsSnapshot()["test_multi_panic"]; got != 3 {
		t.Errorf("expected 3 panics, got %d", got)
	}
}

// TestRunSafe_DistinctNames — two SafeGo call-sites tracked separately.
func TestRunSafe_DistinctNames(t *testing.T) {
	metrics.ResetForTest()

	runSafe("path_a", func() { panic("a") })
	runSafe("path_b", func() { panic("b") })
	runSafe("path_b", func() { panic("b2") })

	snap := metrics.GoroutinePanicsSnapshot()
	if snap["path_a"] != 1 {
		t.Errorf("path_a: expected 1, got %d", snap["path_a"])
	}
	if snap["path_b"] != 2 {
		t.Errorf("path_b: expected 2, got %d", snap["path_b"])
	}
}

// TestSafeGo_Async — SafeGo really does launch a goroutine; the caller
// returns immediately.  We synchronise via a WaitGroup so the test
// terminates cleanly without flake.
func TestSafeGo_Async(t *testing.T) {
	metrics.ResetForTest()

	var wg sync.WaitGroup
	wg.Add(1)
	SafeGo("test_async", func() {
		defer wg.Done()
	})
	wg.Wait()
}
