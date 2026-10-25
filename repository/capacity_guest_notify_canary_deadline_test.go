package repository

import (
	"testing"
	"time"
)

func TestGuestNotifyCanarySerializedDeadlineNeverExtendsOriginalBudget(t *testing.T) {
	originalLimit := time.Date(2026, 10, 25, 7, 41, 58, 562260000, time.UTC)
	contextBudget := 4980 * time.Millisecond
	issuedBase := originalLimit.Add(-contextBudget)
	for _, row := range []struct {
		name                  string
		wallDelta, leaseSlack time.Duration
	}{
		{"no_drift", 0, 0}, {"forward_one_ns", 1, 0}, {"backward_one_ns", -1, 0},
		{"shorter_lease_preserved", 1, time.Millisecond},
		{"forward_delta_exceeds_shorter_lease", 2 * time.Millisecond, time.Millisecond},
	} {
		t.Run(row.name, func(t *testing.T) {
			issued := issuedBase.Add(row.wallDelta)
			budget := contextBudget - row.leaseSlack
			candidate := issued.Add(budget).UTC()
			got := originalGuestCanarySerializedDeadline(issued, budget, originalLimit)
			if got.After(originalLimit) || got.After(candidate) || !got.After(issued) || got.Sub(issued) > budget {
				t.Fatal("deadline extends original context or conservative duration")
			}
			if !candidate.After(originalLimit) && !got.Equal(candidate) {
				t.Fatal("earlier lease deadline changed")
			}
		})
	}
}

func TestGuestNotifyCanarySerializedDeadlineRealClockProjection(t *testing.T) {
	for i := 0; i < 10000; i++ {
		limit := time.Now().Add(5 * time.Second)
		sampleStarted := time.Now()
		issued := time.Now()
		budget := min(5*time.Second, limit.Sub(issued), 300*time.Second-issued.Sub(sampleStarted))
		got := originalGuestCanarySerializedDeadline(issued, budget, limit)
		if got.After(limit.UTC()) || got.After(issued.Add(budget).UTC()) {
			t.Fatal("real clock projection extends original parent")
		}
	}
}
