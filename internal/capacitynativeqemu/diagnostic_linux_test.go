//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeTimeoutRetentionUsesOwnerBudget(t *testing.T) {
	r := &Realm{PrivateDirectory: t.TempDir()}
	if err := os.MkdirAll(SlotDirectory(r.PrivateDirectory, 1), 0700); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 3, 41, 24, 123456789, time.UTC)
	body := []byte(`{"code":"qualification_probe.authority_held","status":409,"title":"Guest retirement held","detail":"The original Guest retirement requires its enrolled authority and complete original results.","stage":"challenge_deadline","temporal":{"schema":"guest_probe_temporal_diagnostic_v1","trust":"request_times_unverified","reason":"deadline_reached","issued_at":"2026-10-21T03:41:23.123456789Z","deadline":"2026-10-21T03:41:24.123456789Z","validated_at":"2026-10-21T03:41:24.123456789Z","elapsed_since_issue_ns":1000000000,"remaining_ns":0,"deltas_clamped":false}}` + "\n")
	returned := capacity.GuestOriginalHTTPReturn{Status: 409, Body: body, ReadReturnedAt: at, CloseReturnedAt: at, OriginalContextFailed: true}
	originalErr := capacity.GuestQualificationHTTPRefusal(returned, errors.New("fixture"))
	predicate := capacity.GuestQualificationPredicate(originalErr)
	if err := r.publishProbeDiagnostic(context.Background(), 1, "normal", returned); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(SlotDirectory(r.PrivateDirectory, 1), "probe-http-normal.json")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(SlotDirectory(r.PrivateDirectory, 1), "probe-http-normal.json"))
	var diagnostic capacity.GuestProbeHTTPDiagnostic
	if err != nil || json.Unmarshal(raw, &diagnostic) != nil || diagnostic.Temporal == nil || diagnostic.Temporal.Reason != "deadline_reached" || !diagnostic.ContextFailed {
		t.Fatal("completed temporal diagnostic lost after child timeout", err)
	}
	owner, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.publishProbeDiagnostic(owner, 1, "recovery", returned); err == nil {
		t.Fatal("cancelled owner permitted write")
	}
	if capacity.GuestQualificationPredicate(originalErr) != predicate {
		t.Fatal("original error changed")
	}
}
func TestInstallationTerminalStateRetention(t *testing.T) {
	for _, state := range []string{"receipt_pending", "receipt_refused", "receipt_read_error", "confirmation_pending", "confirmation_refused", "confirmation_read_error", "read_ok"} {
		t.Run(state, func(t *testing.T) {
			r := &Realm{PrivateDirectory: t.TempDir()}
			if err := os.MkdirAll(SlotDirectory(r.PrivateDirectory, 1), 0700); err != nil {
				t.Fatal(err)
			}
			if err := r.InstallationReadState(context.Background(), 1, state); err != nil {
				t.Fatal(err)
			}
			if err := r.InstallationReadState(context.Background(), 1, "secret/private/error"); err == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
