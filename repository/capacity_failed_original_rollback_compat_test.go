package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Two actual source revisions share only this isolated full-schema database.
// It does not prove a production rollout, network drain, or provider effects.
func TestFailedOriginalAWSLegacyRollbackCompatibility(t *testing.T) {
	probe := os.Getenv("LEGACY_CORE_ROLLBACK_PROBE")
	if probe == "" {
		if os.Getenv("REQUIRE_LEGACY_CORE_ROLLBACK_PROBE") == "true" {
			t.Fatal("legacy executable required")
		}
		t.Skip("explicit two-source isolated rollback fixture only")
	}
	db := originalDispositionPG(t)
	f := enrolledFailedAWSOriginalPGFixture(t, db, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.store.CompleteFailedOriginalDisposition(ctx, owner, witnessedUnenrolledAWSObservation(t, owner.Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, probe, result.GrantID, f.jobID.String())
	cmd.Stdin = bytes.NewReader(policy)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("legacy binary failed: %v: %s", err, out)
	}
	if !bytes.Contains(out, []byte("LEGACY_READ_AND_REOPEN_REFUSAL_PASS")) {
		t.Fatalf("missing legacy evidence: %s", out)
	}
	var state string
	var ack sql.NullTime
	if err = db.QueryRowContext(ctx, `SELECT state,finalization_ack_at FROM capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); err != nil || state != "failed_disposed" || ack.Valid {
		t.Fatal("legacy changed dispatch", state, ack, err)
	}
}
