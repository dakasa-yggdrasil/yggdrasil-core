package capacity

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
	"time"
)

func TestGuestNotifyFreshnessKeepsClockDomainsAndOriginalBudget(t *testing.T) {
	for _, kind := range []string{"original_off", "native_clock_ahead", "native_clock_behind", "core_pg_clock_ahead", "core_pg_clock_behind", "old_ledger", "ledger_clock_reversed", "bridge_exhausted", "missing_causal_class", "wrong_bound", "legacy_timestamp_only"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			commit := now.Add(-time.Hour)
			b := model.CapacityGuestNotifyBusinessObservation{CreationFreshnessClass: GuestNotifyCreationFreshnessClass, CreationUpperBoundSeconds: 5, NativeObserved: now}
			recorded, readNow, limit := now.Add(-time.Second), now, 30
			switch kind {
			case "native_clock_ahead":
				b.NativeObserved = now.Add(12 * time.Hour)
			case "native_clock_behind":
				b.NativeObserved = now.Add(-12 * time.Hour)
			case "core_pg_clock_ahead":
				recorded = recorded.Add(12 * time.Hour)
				readNow = readNow.Add(12 * time.Hour)
			case "core_pg_clock_behind":
				recorded = recorded.Add(-12 * time.Hour)
				readNow = readNow.Add(-12 * time.Hour)
			case "old_ledger":
				recorded = readNow.Add(-26 * time.Second)
			case "ledger_clock_reversed":
				recorded = readNow.Add(time.Nanosecond)
			case "bridge_exhausted":
				limit = 4
			case "missing_causal_class":
				b.CreationFreshnessClass = ""
			case "wrong_bound":
				b.CreationUpperBoundSeconds = 1
			case "legacy_timestamp_only":
				b.CreationFreshnessClass = ""
				b.OriginalCommit = &commit
				b.NativeCommitTimestampKnown = true
			}
			positive := kind == "original_off" || kind == "native_clock_ahead" || kind == "native_clock_behind" || kind == "core_pg_clock_ahead" || kind == "core_pg_clock_behind"
			if GuestNotifyBusinessStillFresh(b, recorded, readNow, limit) != positive {
				t.Fatal("different clock or old original creation renewed useful capacity")
			}
		})
	}
}
