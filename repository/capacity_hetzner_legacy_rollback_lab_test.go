package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Source 32fe writes and re-reads this explicitly synthetic storage record in
// PG82. The actual 2de decoder receives those exact bytes and may only read a
// private file, never the DB. Neither record nor result implies real Guest or
// provider authority.
func TestLABFailedInstalledCoreBoundLegacyRollback(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	f := guestOriginalStorageRecords(t)
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
	r := FailedInstalledGuestDisposal{
		Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested",
		Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "legacy-readonly-fixture",
		PreregistrationID: f.pre.PreregistrationID, Issuer: "storage-test", ActualCoreSource: strings.Repeat("a", 40),
		ReplacementMode: FailedInstalledCoreReplacementMode, OriginalFailedIssuerCoreSource: strings.Repeat("b", 40),
		ReplacementCoreSource: strings.Repeat("a", 40), RetirementMode: failedInstalledV2Mode,
		OriginalRun: `{"status":"failed"}`, LastFailedRun: `{"status":"failed"}`,
		InstallationSHA256: strings.Repeat("b", 64), EnrollmentSHA256: strings.Repeat("c", 64),
		BlockedGuestSource: strings.Repeat("d", 40), BlockedProfileSHA256: strings.Repeat("e", 64), BusinessEffectsPreserved: true,
	}
	sha, err := insertFailedInstalledDisposalTx(ctx, tx, r)
	if err != nil {
		t.Fatal(err)
	}
	read, digest, err := loadFailedInstalledDisposalTx(ctx, tx, r.ID, "requested")
	if err != nil || sha != digest || read.ReplacementMode != r.ReplacementMode {
		t.Fatal("current source refused stored fixture", err)
	}
	var wire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_failed_installed_disposals WHERE id=$1 AND stage='requested'`, r.ID).Scan(&wire); err != nil {
		t.Fatal(err)
	}
	labAssertLegacyRefusesCoreBoundWire(t, wire)
	var after []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_failed_installed_disposals WHERE id=$1 AND stage='requested'`, r.ID).Scan(&after); err != nil || string(after) != string(wire) {
		t.Fatal("stored wire changed", err)
	}
	t.Log("LAB_HETZNER_PG82_CURRENT_READ_LEGACY_HOLD_ROLLBACK_PRESERVED")
}

// The binary must be built from pinned 2de with only its decoder test added.
func labAssertLegacyRefusesCoreBoundWire(t *testing.T, wire []byte) {
	t.Helper()
	legacy := os.Getenv("LAB_HETZNER_LEGACY_TEST_BIN")
	if legacy == "" {
		t.Fatal("the pinned 2de test binary is required")
	}
	path := filepath.Join(t.TempDir(), "pg-original-wire.json")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(legacy, "-test.run=^TestLABCoreBoundLegacyDecode$", "-test.v")
	cmd.Env = append(os.Environ(), "LAB_DISPOSAL_WIRE="+path)
	output, err := cmd.CombinedOutput()
	t.Logf("legacy exact source: %s", output)
	if err != nil || !strings.Contains(string(output), "LAB_CORE2DE_REAL_PG_WIRE_UNKNOWN_FIELDS_HELD_CONTROL_PASS") {
		t.Fatal("legacy decoder evidence missing", err)
	}
}
