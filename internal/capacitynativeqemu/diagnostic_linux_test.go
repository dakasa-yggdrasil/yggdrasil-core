//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeTimeoutRetentionUsesOwnerBudget(t *testing.T) {
	r := &Realm{PrivateDirectory: t.TempDir()}
	if err := os.MkdirAll(SlotDirectory(r.PrivateDirectory, 1), 0700); err != nil {
		t.Fatal(err)
	}
	returned := capacity.GuestOriginalHTTPReturn{OriginalContextFailed: true}
	originalErr := capacity.GuestQualificationHTTPRefusal(returned, errors.New("fixture"))
	predicate := capacity.GuestQualificationPredicate(originalErr)
	if err := r.publishProbeDiagnostic(context.Background(), 1, "normal", returned); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(SlotDirectory(r.PrivateDirectory, 1), "probe-http-normal.json")); err != nil {
		t.Fatal(err)
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
