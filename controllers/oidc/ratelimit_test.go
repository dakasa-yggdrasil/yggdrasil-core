package oidc

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	rl := NewMemoryRateLimit(60, time.Minute)
	for i := 0; i < 60; i++ {
		if !rl.Allow(context.Background(), "key1") {
			t.Fatalf("blocked at iteration %d under limit", i)
		}
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	rl := NewMemoryRateLimit(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow(context.Background(), "key2") {
			t.Fatalf("blocked at iteration %d under limit", i)
		}
	}
	if rl.Allow(context.Background(), "key2") {
		t.Fatal("expected block on 4th request, got allow")
	}
}

func TestRateLimit_DifferentKeysIndependent(t *testing.T) {
	rl := NewMemoryRateLimit(2, time.Minute)
	_ = rl.Allow(context.Background(), "a")
	_ = rl.Allow(context.Background(), "a")
	if rl.Allow(context.Background(), "a") {
		t.Fatal("key a should be blocked after 2 calls")
	}
	if !rl.Allow(context.Background(), "b") {
		t.Fatal("key b should still be allowed independently of a")
	}
}

func TestRateLimit_WindowResets(t *testing.T) {
	// Use a short window so the test runs quickly. Window expiry is
	// Now()-windowStart > window, so any sleep > 50ms suffices for a
	// 50ms window. We use 60ms to leave margin for scheduler jitter.
	rl := NewMemoryRateLimit(1, 50*time.Millisecond)
	if !rl.Allow(context.Background(), "k") {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow(context.Background(), "k") {
		t.Fatal("second call within window should be blocked")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow(context.Background(), "k") {
		t.Fatal("call after window expiry should be allowed")
	}
}

func TestRateLimit_ConcurrentSafe(t *testing.T) {
	// Hammer the limiter from many goroutines and assert the count of
	// allowed calls equals exactly the configured limit. This catches
	// races in the count++ branch.
	const limit = 100
	const goroutines = 20
	const callsPerGoroutine = 50
	rl := NewMemoryRateLimit(limit, time.Minute)

	var allowed int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				if rl.Allow(context.Background(), "shared") {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != limit {
		t.Errorf("concurrent allowed=%d, want exactly %d (race in count++ ?)", allowed, limit)
	}
}
