//go:build linux && nativequalification

package message

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestQualificationRetirementClockWaitOriginalContext(t *testing.T) {
	start := time.Now()
	if err := waitQualificationRetirementClock(context.Background()); err != nil || time.Since(start) < 100*time.Millisecond {
		t.Fatal("original wait failed", err)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := waitQualificationRetirementClock(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired original context admitted", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := waitQualificationRetirementClock(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled original context admitted", err)
	}
	short, end := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer end()
	if err := waitQualificationRetirementClock(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("short original context renewed", err)
	}
}
