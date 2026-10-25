package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
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
	t.Run("retirement_V2_real_child_keeps_parent_and_lease_budgets", func(t *testing.T) {
		parent, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		original, err := capacity.NewGuestRetirementV2OriginalOwner(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer original.Close()
		limit, ok := original.Context().Deadline()
		parentLimit, parentOK := parent.Deadline()
		if !ok || !parentOK || !limit.Equal(parentLimit) {
			t.Fatal("original child renewed its parent budget")
		}
		for _, leaseBudget := range []time.Duration{time.Second, time.Minute} {
			sampleStarted, issued := time.Now(), time.Now()
			budget := min(30*time.Second, limit.Sub(issued), leaseBudget-issued.Sub(sampleStarted))
			got := originalGuestCanarySerializedDeadline(issued, budget, limit)
			if got.After(limit.UTC()) || got.After(issued.Add(budget).UTC()) || got.Sub(issued.UTC()) > 30*time.Second || got.Sub(issued.UTC()) > leaseBudget {
				t.Fatal("V2 serialization extended owner, parent or lease")
			}
		}
		if _, _, _, err := original.NonceExchange(); err == nil {
			t.Fatal("deadline projection minted an original nonce exchange")
		}
	})
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
