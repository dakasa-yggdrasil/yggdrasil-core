//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Failure-only, read-only diagnostics in a disposable synthetic database.
func labHetznerAdmissionDiagnostic(t *testing.T, db *sql.DB, preID, lastRun string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Log("LAB_DIAG_TX", e)
		return
	}
	defer tx.Rollback()
	check := func(name string, e error) bool {
		if e != nil {
			t.Log("LAB_DIAG_"+name, e)
			return false
		}
		t.Log("LAB_DIAG_"+name, "PASS")
		return true
	}
	stored, e := loadGuestOriginalTx(ctx, tx, preID)
	if !check("PRE", e) {
		return
	}
	policy := model.Manifest{ID: uuid.MustParse(stored.pre.PolicyID), Kind: "capacity_policy"}
	var active bool
	e = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, policy.ID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active)
	if !check("POLICY_READ", e) {
		return
	}
	p, e := parseCapacityPolicy(policy)
	if !check("POLICY_PARSE", e) {
		return
	}
	if p.GuestRetirementBinding == nil {
		t.Log("LAB_DIAG_POLICY_BINDING_MISSING")
		return
	}
	t.Log("LAB_DIAG_POLICY_FLAGS", active, policy.Checksum == stored.pre.PolicyChecksum, reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding), capacity.GuestBindingAuthorityCurrent(p, stored.binding))
	old, e := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if !check("INTENT", e) {
		return
	}
	var now time.Time
	e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now)
	if !check("CLOCK", e) {
		return
	}
	t.Log("LAB_DIAG_INTENT_FLAGS", failedInstalledDisposalCandidate(old, p, policy, now), stored.pre.Generation == old.Generation, stored.pre.Slot == 1)
	e = loadGuestWitnessTx(ctx, tx, &stored)
	if !check("WITNESS", e) {
		return
	}
	receipt, _, e := loadGuestReceiptTx(ctx, tx, preID)
	if !check("RECEIPT", e) {
		return
	}
	_, e = loadGuestInstallationTx(ctx, tx, stored, receipt)
	if !check("INSTALLATION", e) {
		return
	}
	b, e := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
	if !check("BINDING", e) {
		return
	}
	if !check("INTEGRATION", checkMutationIntegration(ctx, tx, b)) {
		return
	}
	slot, exists, e := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, 1)
	if !check("SLOT", e) {
		return
	}
	t.Log("LAB_DIAG_SLOT_FLAGS", exists, !slot.Tombstone, slot.ResourceID == stored.witness.Tuple.ResourceID, slot.ResourceCreatedAt == stored.witness.Tuple.CreatedAt)
	var confirmed bool
	e = tx.QueryRowContext(ctx, `SELECT state='confirmed' AND grant_record->'grant'->>'capability'=grant_record->'binding'->>'ensure_capability' FROM public.capacity_mutation_grants WHERE id=$1`, stored.pre.OriginalCreateGrantID).Scan(&confirmed)
	if !check("GRANT_READ", e) {
		return
	}
	t.Log("LAB_DIAG_GRANT_CONFIRMED", confirmed)
	workflow := uuid.MustParse(stored.pre.WorkflowID)
	var wf model.Manifest
	wf.ID = workflow
	var wfActive bool
	e = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='workflow'`, workflow).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum, &wf.Spec, &wfActive)
	if !check("WORKFLOW", e) {
		return
	}
	t.Log("LAB_DIAG_WORKFLOW_FLAGS", wfActive, wf.Checksum == stored.pre.WorkflowChecksum)
	s := CapacityStore{DB: db, WorkflowID: workflow, guestReconcile: &guestReconcileSource{workflow: wf}}
	rows, e := tx.QueryContext(ctx, installedGuestOriginalFailedRunQuery, workflow, preID, now, uuid.Nil)
	if !check("RUN_QUERY", e) {
		return
	}
	var job, run string
	var originalRaw, result []byte
	count := 0
	for rows.Next() {
		count++
		e = rows.Scan(&job, &run, &originalRaw, &result)
		if e != nil {
			break
		}
	}
	e2 := rows.Err()
	_ = rows.Close()
	if !check("RUN_SCAN", e) {
		return
	}
	if !check("RUN_ROWS", e2) {
		return
	}
	t.Log("LAB_DIAG_RUN_COUNT", count)
	if count != 1 {
		return
	}
	t.Log("LAB_DIAG_ORIGINAL_FAILURE", originalInstalledFailureResult(result, stored.pre, workflow), failedInstalledOriginalCanaryFailure(result))
	if !check("ORIGINAL_DISPATCH", s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(run), result)) {
		return
	}
	originalCore, e := failedInstalledOriginalCanaryIssuerTx(ctx, tx, p, stored, receipt, run)
	if !check("CANARY_ISSUER", e) {
		return
	}
	t.Log("LAB_DIAG_CORE_ISSUER_SHAPE", len(originalCore) == 40, originalCore != capacity.CurrentGuestCoreSource())
	expectedRun := run
	originalFence := old.FencingToken
	if m := old.InstalledGuestReconcile; m != nil {
		expectedRun = m.NewRunID
		originalFence = m.OriginalFence
		var lastRaw, lastResult []byte
		e = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, expectedRun, workflow, now).Scan(&lastRaw, &lastResult)
		if !check("PREVIOUS_RUN", e) {
			return
		}
		t.Log("LAB_DIAG_PREVIOUS_FLAGS", failedInstalledResumeResult(lastResult, old.Generation, old.FencingToken))
		if !check("PREVIOUS_DISPATCH", s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(expectedRun), lastResult)) {
			return
		}
	}
	t.Log("LAB_DIAG_FINAL_FLAGS", expectedRun == lastRun, stored.pre.Fence == originalFence, failedInstalledRetirementMode(p, stored.binding), capacity.CurrentGuestCoreSource())
	var intended map[string]any
	_ = json.Unmarshal(originalRaw, &intended)
}
