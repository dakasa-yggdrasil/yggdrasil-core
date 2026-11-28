package repository

import (
	"testing"
	"time"
)

func TestNativeReadinessWindowCapsOriginalAuthorityAndExactNewRunBoundary(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 123456789, time.UTC)
	for _, row := range []struct {
		name                      string
		command, parent, physical time.Duration
		want                      time.Duration
	}{
		{"diagnostic_cap", time.Hour, time.Hour, time.Hour, 300 * time.Second},
		{"original_command", 210 * time.Second, time.Hour, time.Hour, 210 * time.Second},
		{"original_parent", time.Hour, 230 * time.Second, time.Hour, 230 * time.Second},
		{"physical_qualification", time.Hour, time.Hour, 250 * time.Second, 250 * time.Second},
		{"expired_command", -time.Second, time.Hour, time.Hour, -time.Second},
		{"all_original_bounds", 240 * time.Second, 220 * time.Second, 260 * time.Second, 220 * time.Second},
	} {
		t.Run(row.name, func(t *testing.T) {
			end := nativeReadinessRunEnd(now, now.Add(row.command), now.Add(row.parent), now.Add(row.physical))
			if !end.Equal(now.Add(row.want)) {
				t.Fatal("diagnostic cap changed an original authority boundary", end)
			}
		})
	}
	for _, remaining := range []time.Duration{179999 * time.Millisecond, 180*time.Second - time.Nanosecond, 180 * time.Second, 180*time.Second + time.Nanosecond} {
		if nativeReadinessNewRunHasBudget(now, now.Add(remaining)) != (remaining >= 180*time.Second) {
			t.Fatal("new run budget boundary drifted", remaining)
		}
	}
	end := nativeReadinessRunEnd(now, now.Add(240*time.Second), now.Add(250*time.Second), now.Add(time.Hour))
	if !nativeReadinessNewRunHasBudget(now, end) || nativeReadinessNewRunHasBudget(now.Add(61*time.Second), end) {
		t.Fatal("elapsed bootstrap/setup time was replaced by a new lifetime")
	}
	if nativeReadinessNewRunHasBudget(time.Time{}, now) {
		t.Fatal("missing original clock opened a diagnostic run")
	}
}
