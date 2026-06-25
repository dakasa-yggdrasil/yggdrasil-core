package main

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForPostgres_SucceedsAfterRetries(t *testing.T) {
	var calls int32
	ping := func() error {
		if atomic.AddInt32(&calls, 1) < 3 {
			return errors.New("connection refused")
		}
		return nil
	}
	if err := waitForPostgres(ping, 2*time.Second, 1*time.Millisecond); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls < 3 {
		t.Fatalf("expected >=3 ping attempts, got %d", calls)
	}
}

func TestWaitForPostgres_TimesOut(t *testing.T) {
	ping := func() error { return errors.New("connection refused") }
	err := waitForPostgres(ping, 10*time.Millisecond, 1*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, errPostgresUnreachable) {
		t.Fatalf("expected errPostgresUnreachable, got %v", err)
	}
}
