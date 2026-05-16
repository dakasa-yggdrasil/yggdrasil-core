package reactors

import (
	"testing"
	"time"
)

func TestBackoffFor(t *testing.T) {
	tests := []struct {
		name      string
		attempt   int
		wantDur   time.Duration
		wantFinal bool
	}{
		{"attempt 1 → 1m", 1, time.Minute, false},
		{"attempt 2 → 5m", 2, 5 * time.Minute, false},
		{"attempt 3 → 15m", 3, 15 * time.Minute, false},
		{"attempt 4 → dead-letter", 4, 0, true},
		{"attempt 10 → dead-letter", 10, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dur, final := BackoffFor(tt.attempt)
			if dur != tt.wantDur {
				t.Errorf("got dur=%v want %v", dur, tt.wantDur)
			}
			if final != tt.wantFinal {
				t.Errorf("got final=%v want %v", final, tt.wantFinal)
			}
		})
	}
}
