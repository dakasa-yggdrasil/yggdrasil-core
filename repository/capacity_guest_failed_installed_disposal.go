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

// Only the single failed first native is in scope. This ledger never states
// that a possible publication had no business effect. Actual withdrawal,
// original writer drain and native absence are still required by V2.
type FailedInstalledGuestDisposal struct {
	RetirementMode           string                                              `json:"retirement_mode"`
	Schema                   string                                              `json:"schema"`
	ID                       string                                              `json:"id"`
	Stage                    string                                              `json:"stage"`
	Namespace                string                                              `json:"namespace"`
	Environment              string                                              `json:"environment"`
	Domain                   string                                              `json:"domain"`
	Dimension                string                                              `json:"dimension"`
	PreregistrationID        string                                              `json:"preregistration_id"`
	Issuer                   string                                              `json:"issuer"`
	ActualCoreSource         string                                              `json:"actual_core_source"`
	OriginalIntent           model.CapacityIntent                                `json:"original_intent"`
	OriginalRun              string                                              `json:"original_run"`
	LastFailedRun            string                                              `json:"last_failed_run"`
	InstallationSHA256       string                                              `json:"installation_sha256"`
	EnrollmentSHA256         string                                              `json:"enrollment_sha256"`
	BlockedGuestSource       string                                              `json:"blocked_guest_source"`
	BlockedProfileSHA256     string                                              `json:"blocked_profile_sha256"`
	UsefulCapacityBefore     int                                                 `json:"useful_capacity_before"`
	BusinessEffectsPreserved bool                                                `json:"business_effects_preserved"`
	AdmissionSHA256          string                                              `json:"admission_sha256,omitempty"`
	ClaimedIntent            *model.CapacityIntent                               `json:"claimed_intent,omitempty"`
	RetirementRequestID      string                                              `json:"retirement_request_id,omitempty"`
	TerminalIssuer           string                                              `json:"terminal_issuer,omitempty"`
	NativePoweroffSHA256     string                                              `json:"native_poweroff_sha256,omitempty"`
	ObservationSHA256        string                                              `json:"observation_sha256,omitempty"`
	Observation              *model.CapacityOriginalCreateDispositionObservation `json:"observation,omitempty"`
}

func failedInstalledDisposalCandidate(old model.CapacityIntent, p model.CapacityPolicySpec, policy model.Manifest, now time.Time) bool {
	return old.FailedInstalledDisposal == nil && !old.RecoveryOnly && !old.FloorDegraded &&
		(old.Phase == "preparing" || old.Phase == "prepared" || old.Phase == "canary") && old.PolicyID == policy.ID && old.PolicyChecksum == policy.Checksum &&
		old.Generation > 0 && old.FencingToken > 0 && old.FencingToken < maxCapacityGeneration && old.LeaseExpiresAt != nil && !old.LeaseExpiresAt.After(now) &&
		p.Floor == 1 && old.Decision.Units == 1 && old.Assessment.Snapshot.Units == 1 && p.GuestNotifyReconcileBinding != nil && p.GuestRetirementBinding != nil && p.GuestRetirementBinding.EvidenceClass == "owned_provisioner_original"
}

func insertFailedInstalledDisposalTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal) (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sha := capacity.BusinessCreationSHA256(raw)
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_failed_installed_disposals(id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`, r.ID, r.Stage, r.Namespace, r.Environment, r.Domain, r.Dimension, r.PreregistrationID, raw, string(raw), sha)
	return sha, err
}

func loadFailedInstalledDisposalTx(ctx context.Context, tx *sql.Tx, id, stage string) (FailedInstalledGuestDisposal, string, error) {
	var r FailedInstalledGuestDisposal
	var raw []byte
	var sha string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_failed_installed_disposals WHERE id=$1 AND stage=$2 FOR SHARE`, id, stage).Scan(&raw, &sha, &consistent)
	if err != nil {
		return r, "", err
	}
	if !consistent || capacity.BusinessCreationSHA256(raw) != sha || decodeFailedInstalledDisposal(raw, &r) != nil || r.Schema != "failed_installed_guest_disposal_v1" || r.ID != id || r.Stage != stage || r.UsefulCapacityBefore != 0 || !r.BusinessEffectsPreserved || (r.RetirementMode != failedInstalledV2Mode && r.RetirementMode != failedInstalledLegacyV1Mode) {
		return r, "", ErrCapacityConflict
	}
	return r, sha, nil
}

// Capacity credit is zero independently of an operator's requested action.
// Unknown/held publications and their effects are retained; only an accepted
// useful read or a prior useful phase makes this narrow disposal ineligible.
func failedInstalledZeroUsefulTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, now time.Time, exceptRun string) error {
	var useful, liveOther, active, openCanary, pending int
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_returns x ON x.challenge_id=c.id WHERE c.preregistration_id=$1 AND c.phase='read' AND x.outcome='accepted')+
 (SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND generation=$6 AND phase IN('promoted','reconciled','reconciled_partial')),
 (SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND resource_id<>'' AND slot<>1),
 (SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND run_id::text<>$7 AND (state IN('started','unknown') OR (state='returned' AND finalization_ack_at IS NULL))),
 (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1 AND original_deadline>$8),
 (SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL AND state IN('issued','redeemed','settled','compensating') AND NOT(grant_record ? 'authority_kind'))`, r.PreregistrationID, r.Namespace, r.Environment, r.Domain, r.Dimension, r.OriginalIntent.Generation, exceptRun, now).Scan(&useful, &liveOther, &active, &openCanary, &pending)
	if err != nil {
		return err
	}
	if useful != 0 || liveOther != 0 || active != 0 || openCanary != 0 || pending != 0 {
		return ErrCapacityConflict
	}
	return nil
}

// ACK and result identities are re-read; an admission cannot outlive a change
// in the acknowledged original or last failed readiness run it referenced.
func (s CapacityStore) failedInstalledRecordedRunsTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, r FailedInstalledGuestDisposal, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return err
	}
	owned := s
	var wf model.Manifest
	wf.ID = s.WorkflowID
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, s.WorkflowID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum); err != nil {
		return err
	}
	owned.guestReconcile = &guestReconcileSource{workflow: wf}
	for _, expected := range []string{r.OriginalRun, r.LastFailedRun} {
		var row struct {
			ID uuid.UUID `json:"id"`
		}
		if json.Unmarshal([]byte(expected), &row) != nil || row.ID == uuid.Nil {
			return ErrCapacityConflict
		}
		var wire, result []byte
		if err := tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, row.ID, s.WorkflowID, now).Scan(&wire, &result); err != nil || capacity.BusinessCreationSHA256(wire) != capacity.BusinessCreationSHA256([]byte(expected)) {
			return ErrCapacityConflict
		}
		if err := owned.installedGuestDispatchRunTx(ctx, tx, policy, p, row.ID, result); err != nil {
			return err
		}
	}
	return nil
}

// The request contains IDs only. Original policy, enrollment, lifetime, ACK,
// profile and the absence of useful-capacity credit are all rederived here.
func (s CapacityStore) RequestFailedInstalledGuestDisposal(ctx context.Context, preID, lastRunID, issuer string) (FailedInstalledGuestDisposal, error) {
	var out FailedInstalledGuestDisposal
	if s.DB == nil || !validCapacityExecutor(preID) || !validCapacityExecutor(lastRunID) || issuer == "" || len(issuer) > 256 {
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
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	var policy model.Manifest
	policy.ID, err = uuid.Parse(stored.pre.PolicyID)
	if err != nil {
		return out, ErrCapacityConflict
	}
	policy.Kind = "capacity_policy"
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active); err != nil {
		return out, err
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || !active || policy.Checksum != stored.pre.PolicyChecksum || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding) || !capacity.GuestBindingAuthorityCurrent(p, stored.binding) {
		return out, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil || !failedInstalledDisposalCandidate(old, p, policy, now) || stored.pre.Generation != old.Generation || stored.pre.Slot != 1 {
		return out, ErrCapacityConflict
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return out, err
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	installed, err := loadGuestInstallationTx(ctx, tx, stored, receipt)
	if err != nil {
		return out, err
	}
	b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
	if err != nil || checkMutationIntegration(ctx, tx, b) != nil {
		return out, ErrCapacityConflict
	}
	slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, 1)
	if err != nil || !exists || slot.Tombstone || slot.ResourceID != stored.witness.Tuple.ResourceID || slot.ResourceCreatedAt != stored.witness.Tuple.CreatedAt {
		return out, ErrCapacityConflict
	}
	var confirmed bool
	if err = tx.QueryRowContext(ctx, `SELECT state='confirmed' AND grant_record->'grant'->>'capability'=grant_record->'binding'->>'ensure_capability' FROM public.capacity_mutation_grants WHERE id=$1`, stored.pre.OriginalCreateGrantID).Scan(&confirmed); err != nil || !confirmed {
		return out, ErrCapacityConflict
	}
	s.WorkflowID, err = uuid.Parse(stored.pre.WorkflowID)
	if err != nil {
		return out, ErrCapacityConflict
	}
	var wf model.Manifest
	wf.ID = s.WorkflowID
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, s.WorkflowID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum, &wf.Spec, &active); err != nil || !active || wf.Checksum != stored.pre.WorkflowChecksum {
		return out, ErrCapacityConflict
	}
	s.guestReconcile = &guestReconcileSource{workflow: wf}
	rows, err := tx.QueryContext(ctx, installedGuestOriginalFailedRunQuery, s.WorkflowID, preID, now, uuid.Nil)
	if err != nil {
		return out, err
	}
	var job, run string
	var originalRaw, result []byte
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&job, &run, &originalRaw, &result); err != nil {
			break
		}
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if err != nil || rowErr != nil || closeErr != nil || count != 1 || !originalInstalledFailureResult(result, stored.pre, s.WorkflowID) || s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(run), result) != nil {
		return out, ErrCapacityConflict
	}
	lastRaw := originalRaw
	expectedRun := run
	originalFence := old.FencingToken
	if m := old.InstalledGuestReconcile; m != nil {
		if m.Schema != "installed_original_guest_readiness_reconcile_v1" || m.Attempt < 1 || m.Attempt > 3 || m.NewFence != old.FencingToken || m.OriginalGeneration != old.Generation || m.OriginalRunID != run || m.OriginalRunSHA256 != capacity.BusinessCreationSHA256(originalRaw) || m.PreregistrationID != preID || !m.OriginalFailurePreserved || m.OriginalQuiescenceOrNoEffectClaimed {
			return out, ErrCapacityConflict
		}
		originalFence = m.OriginalFence
		expectedRun = m.NewRunID
		if err = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, expectedRun, s.WorkflowID, now).Scan(&lastRaw, &result); err != nil || !failedInstalledResumeResult(result, old.Generation, old.FencingToken) || s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(expectedRun), result) != nil {
			return out, ErrCapacityConflict
		}
	}
	if lastRunID != expectedRun || stored.pre.Fence != originalFence {
		return out, ErrCapacityConflict
	}
	out = FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PreregistrationID: preID, Issuer: issuer, ActualCoreSource: capacity.CurrentGuestCoreSource(), OriginalIntent: old, OriginalRun: string(originalRaw), LastFailedRun: string(lastRaw), InstallationSHA256: capacity.GuestRetirementSHA(installed), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), BlockedGuestSource: stored.binding.GuestSourceCommit, BlockedProfileSHA256: stored.binding.ProfileManifestSHA256, BusinessEffectsPreserved: true, RetirementMode: failedInstalledRetirementMode(p, stored.binding)}
	if out.RetirementMode == "" {
		return FailedInstalledGuestDisposal{}, ErrCapacityConflict
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, out, now, ""); err != nil {
		return out, err
	}
	sha, err := insertFailedInstalledDisposalTx(ctx, tx, out)
	if err != nil {
		return out, err
	}
	next := old
	next.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{ID: out.ID, AdmissionSHA256: sha, PreregistrationID: preID, Stage: "requested"}
	if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return FailedInstalledGuestDisposal{}, err
	}
	return out, nil
}

func persistFailedInstalledDisposalIntentTx(ctx context.Context, tx *sql.Tx, old, next model.CapacityIntent) error {
	before, _ := json.Marshal(old)
	after, err := json.Marshal(next)
	if err != nil {
		return err
	}
	changed, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=clock_timestamp() WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND intent=$6::jsonb`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(after), string(before))
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, "failed-installed-disposal:"+next.FailedInstalledDisposal.ID+":"+next.FailedInstalledDisposal.Stage)
	return err
}

// Only the existing scheduled plan can claim the requested disposal. No API
// supplies a lease, reduced floor, provider grant or a synthetic assessment.
func (s CapacityStore) TryClaimFailedInstalledGuestDisposal(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (model.CapacityIntent, string, bool, error) {
	var empty model.CapacityIntent
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || s.OriginalRunID == uuid.Nil || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return empty, "", false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return empty, "", false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, "", false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return empty, "", false, err
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return empty, "", false, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return old, "", false, nil
	}
	if err != nil {
		return old, "", false, err
	}
	m := old.FailedInstalledDisposal
	if m != nil && m.Stage == "claimed" {
		if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
			return old, "", false, err
		}
		var now time.Time
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return old, "", false, err
		}
		next, preID, eligible, e := s.claimPrejournalRefusalRecoveryTx(ctx, tx, policy, p, old, assessment, now.UTC())
		if e == nil && !eligible {
			next, preID, eligible, e = s.claimNeverSentRecoveryTx(ctx, tx, policy, p, old, assessment, now.UTC())
		}
		if e != nil || !eligible {
			return old, "", false, e
		}
		if !guestReconcileLive(ctx) {
			return old, "", false, ErrCapacityLease
		}
		if e = tx.Commit(); e != nil {
			return old, "", false, e
		}
		return next, preID, true, nil
	}
	requested, stageErr := failedInstalledDisposalClaimRequested(m)
	if stageErr != nil || !requested {
		// Terminal accounting no longer owns the scheduler's plan. The next
		// ordinary Assess transaction still requires terminal native absence
		// and a different Source/profile approved by the complete registry.
		return old, "", false, stageErr
	}
	r, sha, err := loadFailedInstalledDisposalTx(ctx, tx, m.ID, "requested")
	if err != nil || sha != m.AdmissionSHA256 || r.PreregistrationID != m.PreregistrationID {
		return old, "", false, ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return old, "", false, err
	}
	unmarked := old
	unmarked.FailedInstalledDisposal = nil
	if !reflect.DeepEqual(unmarked, r.OriginalIntent) || !failedInstalledDisposalCandidate(unmarked, p, policy, now) || !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) || assessment.Snapshot.Units != 1 || assessment.Snapshot.Profile != old.Decision.Profile || !capacityProfileCurrent(p, old.Decision, now) || s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil) != nil {
		return old, "", false, ErrCapacityConflict
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, r, now, s.OriginalRunID.String()); err != nil {
		return old, "", false, err
	}
	if err = s.failedInstalledRecordedRunsTx(ctx, tx, policy, p, r, now); err != nil {
		return old, "", false, err
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now, true)
	if err != nil || len(members) != 1 || members[0].Slot != 1 || members[0].PreregistrationID != r.PreregistrationID {
		return old, "", false, ErrCapacityConflict
	}
	next := old
	next.Phase = "draining"
	next.FencingToken++
	next.Assessment = assessment
	next.BaselineSnapshot = assessment.Snapshot
	next.Decision.Action = "drain"
	next.Decision.Reason = "failed_installed_disposal"
	next.LeaseOwner = uuid.NewString()
	next.LeaseExecutorID = s.ExecutorID
	expiry := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
	next.LeaseExpiresAt = &expiry
	next.UpdatedAt = now
	next.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{ID: m.ID, AdmissionSHA256: sha, PreregistrationID: m.PreregistrationID, Stage: "claimed", RunID: s.OriginalRunID.String(), Fence: next.FencingToken}
	r.Stage = "claimed"
	r.AdmissionSHA256 = sha
	r.ClaimedIntent = &next
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		return old, "", false, err
	}
	if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
		return old, "", false, err
	}
	if !guestReconcileLive(ctx) {
		return old, "", false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return old, "", false, err
	}
	return next, m.PreregistrationID, true, nil
}

// All floor exceptions converge here. A marker or caller boolean alone cannot
// bypass an ordinary protected slot. The immutable claim, full original
// enrollment/installation and zero useful credit must still agree in this TX.
func (s CapacityStore) failedInstalledDisposalActiveTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, slot int, now time.Time) (bool, error) {
	m := current.FailedInstalledDisposal
	if m == nil {
		return false, nil
	}
	if m.Stage != "claimed" || slot != 1 || current.Generation < 1 || current.FencingToken != m.Fence || current.Decision.Reason != "failed_installed_disposal" || current.Decision.Action != "drain" || current.Decision.Units != 1 || (current.Phase != "draining" && current.Phase != "drained") || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum {
		return false, ErrCapacityConflict
	}
	// Adapter callbacks legitimately carry a minimal policy reference. Resolve
	// its original complete manifest before comparing the dispatch envelope;
	// never compare that immutable selector against empty projected metadata.
	var canonical model.Manifest
	canonical.ID, canonical.Kind = policy.ID, "capacity_policy"
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&canonical.Metadata.Namespace, &canonical.Metadata.Name, &canonical.Version, &canonical.Checksum, &canonical.Spec, &active); err != nil || !active || canonical.Checksum != policy.Checksum {
		return false, ErrCapacityConflict
	}
	canonicalPolicy, err := parseCapacityPolicy(canonical)
	if err != nil || !reflect.DeepEqual(canonicalPolicy, p) {
		return false, ErrCapacityConflict
	}
	policy = canonical
	r, _, err := loadFailedInstalledDisposalTx(ctx, tx, m.ID, "claimed")
	if err == nil {
		r, err = effectiveFailedInstalledClaimTx(ctx, tx, r, current)
	}
	if err != nil || r.AdmissionSHA256 != m.AdmissionSHA256 || r.PreregistrationID != m.PreregistrationID || r.ClaimedIntent == nil || !reflect.DeepEqual(*r.ClaimedIntent, current) {
		return false, ErrCapacityConflict
	}
	admission, sha, err := loadFailedInstalledDisposalTx(ctx, tx, m.ID, "requested")
	if err != nil || sha != m.AdmissionSHA256 || !reflect.DeepEqual(admission.OriginalIntent, r.OriginalIntent) {
		return false, ErrCapacityConflict
	}
	stored, err := loadGuestOriginalTx(ctx, tx, m.PreregistrationID)
	if err != nil || r.RetirementMode != failedInstalledRetirementMode(p, stored.binding) || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.Generation != current.Generation || stored.pre.Slot != 1 || p.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) {
		return false, ErrCapacityConflict
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return false, err
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, m.PreregistrationID)
	if err != nil {
		return false, err
	}
	installation, err := loadGuestInstallationTx(ctx, tx, stored, receipt)
	if err != nil || capacity.GuestRetirementSHA(installation) != r.InstallationSHA256 || capacity.GuestRetirementSHA(receipt.Enrollment) != r.EnrollmentSHA256 {
		return false, ErrCapacityConflict
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, r, now, m.RunID); err != nil {
		return false, err
	}
	// Authenticated Guest callback stores do not carry a workflow invocation.
	// Derive this historical selector from the exact preregistration, while a
	// real workflow caller must already match it. Never compare against nil.
	workflowID, parseErr := uuid.Parse(stored.pre.WorkflowID)
	if parseErr != nil || workflowID == uuid.Nil || s.WorkflowID != uuid.Nil && s.WorkflowID != workflowID {
		return false, ErrCapacityConflict
	}
	scoped := s
	scoped.WorkflowID = workflowID
	if err = scoped.failedInstalledRecordedRunsTx(ctx, tx, policy, p, r, now); err != nil {
		return false, err
	}
	return true, nil
}

// New Source is required, not a caller's replacement-ready assertion. The
// current compiled complete contract must approve the different Guest Source
// and profile before any subsequent native creation in this dimension.
func requireFailedInstalledReplacementTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec) error {
	if p.GuestNotifyReconcileBinding == nil {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT original_record->>'blocked_guest_source',original_record->>'blocked_profile_sha256',stage FROM public.capacity_guest_failed_installed_disposals WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND stage IN('requested','terminal') ORDER BY recorded_at,id`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	requested, terminal := 0, 0
	for rows.Next() {
		var source, profile, stage string
		if err = rows.Scan(&source, &profile, &stage); err != nil {
			return err
		}
		if stage == "requested" {
			requested++
		} else {
			terminal++
		}
		if !failedInstalledReplacementChanged(p.GuestRetirementBinding, source, profile) || !capacity.GuestBindingAuthorityCurrent(p, *p.GuestRetirementBinding) {
			return ErrCapacityConflict
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if requested != terminal {
		return ErrCapacityConflict
	}
	return nil
}

// The internal storage record embeds a sparse CapacityIntent, not a signed
// Guest protocol DTO. Preserve exact original run bytes as UTF-8 strings and
// reject unknown/missing fields with closed typed/canonical storage decoding.
func decodeFailedInstalledDisposal(raw []byte, out *FailedInstalledGuestDisposal) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrCapacityConflict
	}
	return nil
}

func failedInstalledReplacementChanged(binding *model.CapacityGuestRetirementBinding, source, profile string) bool {
	return binding != nil && binding.GuestSourceCommit != source && binding.ProfileManifestSHA256 != profile
}

// A completed disposal must release the scheduler to ordinary assessment,
// while a live/unknown disposal cannot be mistaken for another claim.
func failedInstalledDisposalClaimRequested(m *model.CapacityFailedInstalledDisposal) (bool, error) {
	if m == nil || m.Stage == "terminal" {
		return false, nil
	}
	if m.Stage == "requested" {
		return true, nil
	}
	return false, ErrCapacityConflict
}
