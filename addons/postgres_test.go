package addons

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresStartupWaitsForTransientConnectivityWithinOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	attempts := 0
	err := pingPostgresStartup(ctx, func(actual context.Context) error {
		if actualDeadline, ok := actual.Deadline(); !ok || !actualDeadline.Equal(deadline) {
			t.Fatal("retry replaced the original startup deadline")
		}
		attempts++
		if attempts == 1 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("transient connectivity did not recover: attempts=%d err=%v", attempts, err)
	}
}

func TestPostgresStartupCannotExtendDeadlineOrAcceptCancelledSuccess(t *testing.T) {
	t.Run("unavailable_until_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		unavailable := errors.New("connection refused")
		err := pingPostgresStartup(ctx, func(context.Context) error { return unavailable })
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, unavailable) {
			t.Fatalf("startup did not preserve deadline and connection failure: %v", err)
		}
	})
	t.Run("already_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := pingPostgresStartup(ctx, func(context.Context) error {
			t.Fatal("ping executed after startup cancellation")
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled startup accepted: %v", err)
		}
	})
	t.Run("cancelled_during_successful_ping", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := pingPostgresStartup(ctx, func(context.Context) error { cancel(); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("late successful ping overrode cancellation: %v", err)
		}
	})
}
