package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This is a new, explicitly admitted operation after an expired intent that
// never acquired even a possible-send. It does not renew or replace that intent.
type FailedInstalledRetirementRecovery struct {
	Schema                string                               `json:"schema"`
	ID                    string                               `json:"id"`
	Stage                 string                               `json:"stage"`
	DisposalID            string                               `json:"disposal_id"`
	PreregistrationID     string                               `json:"preregistration_id"`
	ParentIntentID        string                               `json:"parent_intent_id"`
	ParentIntentSHA256    string                               `json:"parent_intent_sha256"`
	OriginalClaimSHA256   string                               `json:"original_claim_sha256"`
	Issuer                string                               `json:"issuer"`
	ActualCoreSource      string                               `json:"actual_core_source"`
	FailedRun             string                               `json:"failed_run"`
	OriginalClaimedIntent model.CapacityIntent                 `json:"original_claimed_intent"`
	ClaimedIntent         *model.CapacityIntent                `json:"claimed_intent,omitempty"`
	AdmissionSHA256       string                               `json:"admission_sha256,omitempty"`
	SuccessorIntent       *model.CapacityGuestRetirementIntent `json:"successor_intent,omitempty"`
}

func insertRetirementRecoveryTx(ctx context.Context, tx *sql.Tx, r FailedInstalledRetirementRecovery) (string, error) {
	wire, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	digest := capacity.BusinessCreationSHA256(wire)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_presend_retirement_recoveries(id,stage,disposal_id,preregistration_id,parent_intent_id,original_wire,original_record,record_sha256) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, r.ID, r.Stage, r.DisposalID, r.PreregistrationID, r.ParentIntentID, wire, string(wire), digest)
	return digest, err
}

func loadRetirementRecoveryTx(ctx context.Context, tx *sql.Tx, id, stage string) (FailedInstalledRetirementRecovery, string, error) {
	var r FailedInstalledRetirementRecovery
	var wire []byte
	var digest string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_presend_retirement_recoveries WHERE id=$1 AND stage=$2 FOR SHARE`, id, stage).Scan(&wire, &digest, &consistent)
	if err != nil {
		return r, "", err
	}
	if !consistent || capacity.BusinessCreationSHA256(wire) != digest || decodeRetirementRecovery(wire, &r) != nil || r.Schema != "failed_installed_never_sent_retirement_recovery_v1" || r.ID != id || r.Stage != stage {
		return r, "", ErrCapacityConflict
	}
	return r, digest, nil
}

func decodeRetirementRecovery(raw []byte, out *FailedInstalledRetirementRecovery) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	b, err := json.Marshal(out)
	if err != nil || !bytes.Equal(b, raw) {
		return ErrCapacityConflict
	}
	return nil
}

// The intent row is locked in the same mutation-scope transaction as every
// writer/authority callback. Existing atomic77 issuance is legitimate; any
// possible caller or Guest/runtime result makes this recovery ineligible.
func retirementNeverSentTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	var deadline time.Time
	var canonicalDeadline string
	if err := tx.QueryRowContext(ctx, `SELECT original_deadline,intent_record->>'original_deadline' FROM public.capacity_vm_retirement_intents WHERE id=$1 FOR UPDATE`, id).Scan(&deadline, &canonicalDeadline); err != nil {
		return err
	}
	original, err := time.Parse(time.RFC3339Nano, canonicalDeadline)
	if err != nil || deadline.After(now) || original.After(now) {
		return ErrCapacityConflict
	}
	var count int
	err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1)`, id).Scan(&count)
	if err != nil {
		return err
	}
	if count != 0 {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) failedRetirementRunTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, runID string, workflowID uuid.UUID, now time.Time) (string, error) {
	if !validCapacityExecutor(runID) || workflowID == uuid.Nil {
		return "", ErrCapacityConflict
	}
	var raw, result []byte
	if err := tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, runID, workflowID, now).Scan(&raw, &result); err != nil {
		return "", err
	}
	var run struct {
		Status string                        `json:"status"`
		Steps  []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(result, &run) != nil || run.Status != "failed" || len(run.Steps) != 7 {
		return "", ErrCapacityConflict
	}
	states := map[string]string{}
	for _, x := range run.Steps {
		states[x.ID] = x.Status
	}
	if states["plan-original-guest"] != "succeeded" || states["retire-original-guest"] != "failed" || states["provision-original-notify"] != "skipped" || states["refresh-original-membership"] != "skipped" || states["complete-original-provision"] != "skipped" || states["finish-original-retirement"] != "skipped" || states["complete-original-retirement"] != "skipped" {
		return "", ErrCapacityConflict
	}
	var wf model.Manifest
	wf.ID = workflowID
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1 AND kind='workflow' AND active FOR SHARE`, workflowID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum); err != nil {
		return "", err
	}
	owned := s
	owned.WorkflowID = workflowID
	owned.guestReconcile = &guestReconcileSource{workflow: wf}
	if err := owned.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(runID), result); err != nil {
		return "", err
	}
	return string(raw), nil
}

// GodMode handler supplies only the two IDs. Every fact below is backend-owned.
func (s CapacityStore) RequestFailedInstalledRetirementRecovery(ctx context.Context, preID, parentID, issuer string) (FailedInstalledRetirementRecovery, error) {
	var out FailedInstalledRetirementRecovery
	if s.DB == nil || !validCapacityExecutor(preID) || !validCapacityExecutor(parentID) || issuer == "" || len(issuer) > 256 {
		return out, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return out, err
	}
	// Resolve only immutable scope identifiers before taking any row lock.
	// All issue/caller paths take this scope mutex before their intent locks.
	var namespace, environment, domain, dimension string
	if err = tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1 AND r.preregistration_id=$2`, parentID, preID).Scan(&namespace, &environment, &domain, &dimension); err != nil {
		return out, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, namespace, model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension}); err != nil {
		return out, err
	}
	stored, err := loadGuestRetirementTx(ctx, tx, parentID)
	if err != nil || stored.Preregistration.PreregistrationID != preID {
		return out, ErrCapacityConflict
	}
	var policy model.Manifest
	policy.ID = uuid.MustParse(stored.Request.Intent.PolicyID)
	policy.Kind = "capacity_policy"
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active); err != nil || !active {
		return out, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return out, err
	}
	if namespace != policy.Metadata.Namespace || environment != p.Environment || domain != p.Domain || dimension != p.Dimension {
		return out, ErrCapacityConflict
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return out, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	now = now.UTC()
	m := current.FailedInstalledDisposal
	if m == nil || m.Stage != "claimed" || m.PreregistrationID != preID || m.RetirementRecoveryID != "" || m.RetirementRefusalRecoveryID != "" || current.LeaseExpiresAt == nil || current.LeaseExpiresAt.After(now) || current.FencingToken >= maxCapacityGeneration {
		return out, ErrCapacityConflict
	}
	r, claimSHA, err := loadFailedInstalledDisposalTx(ctx, tx, m.ID, "claimed")
	if err != nil || r.RetirementMode != failedInstalledLegacyV1Mode || r.ClaimedIntent == nil || !reflect.DeepEqual(*r.ClaimedIntent, current) || !failedInstalledLegacyJoin(r, stored, p) {
		return out, ErrCapacityConflict
	}
	if err = retirementNeverSentTx(ctx, tx, parentID, now); err != nil {
		return out, err
	}
	owned := s
	owned.WorkflowID = uuid.MustParse(stored.Request.Intent.WorkflowID)
	if err = owned.failedInstalledRecordedRunsTx(ctx, tx, policy, p, r, now); err != nil {
		return out, err
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, r, now, ""); err != nil {
		return out, err
	}
	run, err := owned.failedRetirementRunTx(ctx, tx, policy, p, m.RunID, owned.WorkflowID, now)
	if err != nil {
		return out, err
	}
	out = FailedInstalledRetirementRecovery{Schema: "failed_installed_never_sent_retirement_recovery_v1", ID: uuid.NewString(), Stage: "requested", DisposalID: m.ID, PreregistrationID: preID, ParentIntentID: parentID, ParentIntentSHA256: capacity.GuestRetirementSHA(stored.Request.Intent), OriginalClaimSHA256: claimSHA, Issuer: issuer, ActualCoreSource: capacity.CurrentGuestCoreSource(), FailedRun: run, OriginalClaimedIntent: current}
	if _, err = insertRetirementRecoveryTx(ctx, tx, out); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return FailedInstalledRetirementRecovery{}, err
	}
	return out, nil
}

// Called only by the existing scheduled plan under the already-held scope lock.
func (s CapacityStore) claimNeverSentRecoveryTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent, assessment model.CapacityAssessment, now time.Time) (model.CapacityIntent, string, bool, error) {
	var empty model.CapacityIntent
	m := old.FailedInstalledDisposal
	if m == nil || m.Stage != "claimed" || m.RetirementRecoveryID != "" || m.RetirementRefusalRecoveryID != "" {
		return empty, "", false, ErrCapacityConflict
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=$1 AND stage='requested'`, m.ID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, "", false, ErrCapacityConflict
	}
	if err != nil {
		return empty, "", false, err
	}
	r, admissionSHA, err := loadRetirementRecoveryTx(ctx, tx, id, "requested")
	if err != nil || !reflect.DeepEqual(r.OriginalClaimedIntent, old) || r.PreregistrationID != m.PreregistrationID || old.LeaseExpiresAt == nil || old.LeaseExpiresAt.After(now) || old.FencingToken >= maxCapacityGeneration || !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) || assessment.Snapshot.Units != 1 || assessment.Snapshot.Profile != old.Decision.Profile || !capacityProfileCurrent(p, old.Decision, now) || s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil) != nil {
		return empty, "", false, ErrCapacityConflict
	}
	parent, err := loadGuestRetirementTx(ctx, tx, r.ParentIntentID)
	if err != nil || capacity.GuestRetirementSHA(parent.Request.Intent) != r.ParentIntentSHA256 {
		return empty, "", false, ErrCapacityConflict
	}
	if err = retirementNeverSentTx(ctx, tx, r.ParentIntentID, now); err != nil {
		return empty, "", false, err
	}
	disposal, sha, err := loadFailedInstalledDisposalTx(ctx, tx, r.DisposalID, "claimed")
	if err != nil || sha != r.OriginalClaimSHA256 {
		return empty, "", false, ErrCapacityConflict
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, disposal, now, s.OriginalRunID.String()); err != nil {
		return empty, "", false, err
	}
	if err = s.failedInstalledRecordedRunsTx(ctx, tx, policy, p, disposal, now); err != nil {
		return empty, "", false, err
	}
	failed, err := s.failedRetirementRunTx(ctx, tx, policy, p, m.RunID, s.WorkflowID, now)
	if err != nil || failed != r.FailedRun {
		return empty, "", false, ErrCapacityConflict
	}
	next := old
	next.FencingToken++
	next.Assessment = assessment
	next.BaselineSnapshot = assessment.Snapshot
	next.LeaseOwner = uuid.NewString()
	next.LeaseExecutorID = s.ExecutorID
	expiry := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
	next.LeaseExpiresAt = &expiry
	next.UpdatedAt = now
	marker := *m
	marker.RunID = s.OriginalRunID.String()
	marker.Fence = next.FencingToken
	marker.RetirementRecoveryID = r.ID
	marker.RetirementRecoveryAdmissionSHA256 = admissionSHA
	next.FailedInstalledDisposal = &marker
	r.Stage = "claimed"
	r.AdmissionSHA256 = admissionSHA
	r.ClaimedIntent = &next
	if _, err = insertRetirementRecoveryTx(ctx, tx, r); err != nil {
		return empty, "", false, err
	}
	if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
		return empty, "", false, err
	}
	return next, m.PreregistrationID, true, nil
}

// Returns an explicitly derived effective claim, not a rewritten78 record.
// Quiescent/terminal appends carry this new79 claim and retain the original
// admission, original claim hash, failed run and expired parent in79.
func effectiveFailedInstalledClaimTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, current model.CapacityIntent) (FailedInstalledGuestDisposal, error) {
	m := current.FailedInstalledDisposal
	if m != nil && m.RetirementRefusalRecoveryID != "" {
		return effectivePrejournalRefusalClaimTx(ctx, tx, r, current)
	}
	if m == nil || m.RetirementRecoveryID == "" {
		return r, nil
	}
	x, _, err := loadRetirementRecoveryTx(ctx, tx, m.RetirementRecoveryID, "claimed")
	if err != nil || x.DisposalID != r.ID || x.PreregistrationID != r.PreregistrationID || x.ClaimedIntent == nil || !reflect.DeepEqual(*x.ClaimedIntent, current) || x.AdmissionSHA256 != m.RetirementRecoveryAdmissionSHA256 {
		return r, ErrCapacityConflict
	}
	base, sha, err := loadFailedInstalledDisposalTx(ctx, tx, r.ID, "claimed")
	if err != nil || sha != x.OriginalClaimSHA256 || base.ClaimedIntent == nil || !reflect.DeepEqual(*base.ClaimedIntent, x.OriginalClaimedIntent) {
		return r, ErrCapacityConflict
	}
	r.ClaimedIntent = x.ClaimedIntent
	return r, nil
}

func issueNeverSentSuccessorTx(ctx context.Context, tx *sql.Tx, current model.CapacityIntent, intent model.CapacityGuestRetirementIntent, now time.Time) error {
	m := current.FailedInstalledDisposal
	if m != nil && m.RetirementRefusalRecoveryID != "" {
		return issuePrejournalRefusalSuccessorTx(ctx, tx, current, intent, now)
	}
	if m == nil || m.RetirementRecoveryID == "" {
		return nil
	}
	r, _, err := loadRetirementRecoveryTx(ctx, tx, m.RetirementRecoveryID, "claimed")
	if err != nil || r.ClaimedIntent == nil || !reflect.DeepEqual(*r.ClaimedIntent, current) || intent.Fence != uint64(current.FencingToken) || intent.Generation != uint64(current.Generation) || intent.LeaseOwner != current.LeaseOwner {
		return ErrCapacityConflict
	}
	if err = retirementNeverSentTx(ctx, tx, r.ParentIntentID, now); err != nil {
		return err
	}
	r.Stage = "issued"
	r.SuccessorIntent = &intent
	_, err = insertRetirementRecoveryTx(ctx, tx, r)
	return err
}

func (s CapacityStore) ReadFailedInstalledRetirementRecoveries(ctx context.Context, preID string) ([]FailedInstalledRetirementRecovery, error) {
	if s.DB == nil || !validCapacityExecutor(preID) {
		return nil, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_presend_retirement_recoveries WHERE preregistration_id=$1 ORDER BY recorded_at,stage`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailedInstalledRetirementRecovery{}
	for rows.Next() {
		var wire []byte
		var digest string
		var r FailedInstalledRetirementRecovery
		if err = rows.Scan(&wire, &digest); err != nil {
			return nil, err
		}
		if len(out) >= 3 || capacity.BusinessCreationSHA256(wire) != digest || decodeRetirementRecovery(wire, &r) != nil {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
