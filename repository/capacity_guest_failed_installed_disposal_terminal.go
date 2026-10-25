package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// No protected native destroy is sent through an ordinary provider contract.
// The existing Guest V2 chain and actual native poweroff read are required
// before an operator may perform an explicit exact-lifetime native cleanup.
func (s CapacityStore) PrepareFailedInstalledGuestNativeCleanup(ctx context.Context, policy model.Manifest, generation, fence int64, owner, retirementID string) (FailedInstalledGuestDisposal, bool, error) {
	var out FailedInstalledGuestDisposal
	handled := false
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if current.FailedInstalledDisposal == nil {
			return nil
		}
		handled = true
		if s.guestNotifyOrigin == nil || s.guestNotifyOrigin.source != capacity.CurrentGuestCoreSource() || s.guestNotifyOrigin.step.Use.Operation != "capacity.finish_original_guest_retirement" {
			return ErrCapacityConflict
		}
		valid, err := s.failedInstalledDisposalActiveTx(ctx, tx, policy, p, current, 1, now)
		if err != nil || !valid {
			return ErrCapacityConflict
		}
		stored, err := loadGuestRetirementV2Tx(ctx, tx, retirementID, true)
		if err != nil {
			return err
		}
		i := stored.Request.Intent
		if i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.WorkflowID != s.WorkflowID.String() || i.PreregistrationID != current.FailedInstalledDisposal.PreregistrationID || i.Generation != uint64(generation) || i.Fence != uint64(fence) || i.LeaseOwner != owner || stored.ExecutorID != s.ExecutorID || i.Slot != 1 {
			return ErrCapacityConflict
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil {
			return err
		}
		if err = guestNativePoweroffV2Tx(ctx, tx, stored, p, b, now); err != nil {
			return err
		}
		var nativeSHA string
		if err = tx.QueryRowContext(ctx, `SELECT observation_sha256 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1`, retirementID).Scan(&nativeSHA); err != nil {
			return err
		}
		r, _, err := loadFailedInstalledDisposalTx(ctx, tx, current.FailedInstalledDisposal.ID, "claimed")
		if err != nil {
			return err
		}
		r.Stage = "quiescent"
		r.RetirementRequestID = retirementID
		r.NativePoweroffSHA256 = nativeSHA
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
			return err
		}
		next := current
		marker := *current.FailedInstalledDisposal
		marker.Stage = "quiescent"
		next.FailedInstalledDisposal = &marker
		next.Phase = "failed_installed_cleanup_pending"
		next.LeaseOwner = ""
		next.LeaseExecutorID = ""
		next.LeaseExpiresAt = nil
		next.UpdatedAt = now
		if err = persistFailedInstalledDisposalIntentTx(ctx, tx, current, next); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, handled, err
}

// The same seven-step workflow closes its local retirement stage without
// promoting anything or sending a native DELETE. Future scheduled plans hold
// before collection/nonce creation while the explicit cleanup is pending.
func (s CapacityStore) FailedInstalledGuestDisposalWaiting(ctx context.Context, policy model.Manifest, requestID string) (FailedInstalledGuestDisposal, bool, error) {
	var out FailedInstalledGuestDisposal
	if s.DB == nil || s.guestReconcile == nil || !guestReconcileLive(ctx) {
		return out, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return out, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, false, err
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return out, false, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err == sql.ErrNoRows {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	return s.failedInstalledGuestDisposalWaitingTx(ctx, tx, current, requestID)
}

// The public owner has already authenticated the Source and taken the mutation
// scope/current-intent locks. This same decision is also exercised by PG tests.
func (s CapacityStore) failedInstalledGuestDisposalWaitingTx(ctx context.Context, tx *sql.Tx, current model.CapacityIntent, requestID string) (FailedInstalledGuestDisposal, bool, error) {
	var out FailedInstalledGuestDisposal
	var err error
	m := current.FailedInstalledDisposal
	if m == nil || m.Stage == "requested" || m.Stage == "terminal" {
		return out, false, nil
	}
	if m.Stage == "claimed" && s.guestReconcile.step.Use.Operation == capacity.PlanOriginalGuestOperation {
		var claimSHA string
		out, claimSHA, err = loadFailedInstalledDisposalTx(ctx, tx, m.ID, "claimed")
		if err != nil {
			return out, true, err
		}
		ready, err := requestedRetirementRecoveryMayReachClaimTx(ctx, tx, current, out, claimSHA)
		if err != nil {
			return out, true, err
		}
		// This only reaches collection and the unchanged claim authorization.
		// It does not acquire a new lease or issue any Guest authority.
		return out, !ready, nil
	}
	if m.Stage != "quiescent" {
		return out, false, ErrCapacityConflict
	}
	out, _, err = loadFailedInstalledDisposalTx(ctx, tx, m.ID, "quiescent")
	if err != nil {
		return out, false, err
	}
	if requestID != "" && out.RetirementRequestID != requestID {
		return out, false, ErrCapacityConflict
	}
	if _, _, _, err = loadFailedInstalledQuiescentTx(ctx, tx, out.PreregistrationID, out.ID, func() string {
		if s.guestReconcile.step.Use.Operation == capacity.CompleteOriginalGuestOperation && s.OriginalRunID.String() == m.RunID {
			return m.RunID
		}
		return ""
	}()); err != nil {
		return out, false, err
	}
	return out, true, nil
}

// A claimed disposal normally waits for explicit native cleanup. The sole
// exception is its separately admitted, not-yet-claimed79 recovery. Immutable
// original/current equality is required here; claimNeverSentRecoveryTx still
// rechecks every lease, run/ACK, no-send, profile and CAS condition later.
func requestedRetirementRecoveryMayReachClaimTx(ctx context.Context, tx *sql.Tx, current model.CapacityIntent, original FailedInstalledGuestDisposal, claimSHA string) (bool, error) {
	m := current.FailedInstalledDisposal
	if m == nil || m.Stage != "claimed" || m.RetirementRecoveryID != "" || m.RetirementRefusalRecoveryID != "" {
		return false, nil
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT r.id::text FROM public.capacity_guest_presend_retirement_recoveries r WHERE r.disposal_id=$1 AND r.stage='requested' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries x WHERE x.id=r.id AND x.stage IN('claimed','issued'))`, m.ID).Scan(&id)
	if err == sql.ErrNoRows {
		return requestedPrejournalRefusalMayReachClaimTx(ctx, tx, current, original, claimSHA)
	}
	if err != nil {
		return false, err
	}
	r, _, err := loadRetirementRecoveryTx(ctx, tx, id, "requested")
	if err != nil || r.DisposalID != m.ID || r.PreregistrationID != m.PreregistrationID || r.OriginalClaimSHA256 != claimSHA || original.ClaimedIntent == nil || !reflect.DeepEqual(*original.ClaimedIntent, current) || !reflect.DeepEqual(r.OriginalClaimedIntent, current) {
		return false, ErrCapacityConflict
	}
	return true, nil
}

// Independent of any expired Guest/lease deadline: these are historical
// authenticated quiescence/poweroff records, never new current15 credit.
func loadFailedInstalledQuiescentTx(ctx context.Context, tx *sql.Tx, preID, id, activeOriginalRun string) (FailedInstalledGuestDisposal, model.Manifest, model.CapacityPolicySpec, error) {
	var policy model.Manifest
	var p model.CapacityPolicySpec
	r, _, err := loadFailedInstalledDisposalTx(ctx, tx, id, "quiescent")
	if err != nil {
		return r, policy, p, err
	}
	if r.PreregistrationID != preID || r.ClaimedIntent == nil {
		return r, policy, p, ErrCapacityConflict
	}
	policy.ID = r.OriginalIntent.PolicyID
	policy.Kind = "capacity_policy"
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active); err != nil {
		return r, policy, p, err
	}
	p, err = parseCapacityPolicy(policy)
	if err != nil || !active || policy.Checksum != r.OriginalIntent.PolicyChecksum {
		return r, policy, p, ErrCapacityConflict
	}
	if err = lockMutationScope(ctx, tx, r.Namespace, p); err != nil {
		return r, policy, p, err
	}
	current, err := loadCapacityIntent(ctx, tx, r.Namespace, p, true)
	if err != nil {
		return r, policy, p, err
	}
	m := current.FailedInstalledDisposal
	if m == nil || m.ID != id || m.PreregistrationID != preID || m.Stage != "quiescent" || current.Phase != "failed_installed_cleanup_pending" || current.LeaseExpiresAt != nil || current.LeaseOwner != "" || current.LeaseExecutorID != "" || current.Generation != r.OriginalIntent.Generation || current.FencingToken != r.ClaimedIntent.FencingToken {
		return r, policy, p, ErrCapacityConflict
	}
	if r.RetirementMode == failedInstalledLegacyV1Mode {
		stored, e := loadGuestRetirementTx(ctx, tx, r.RetirementRequestID)
		if e != nil || !failedInstalledLegacyJoin(r, stored, p) {
			return r, policy, p, ErrCapacityConflict
		}
		if _, e = guestQuiescentProofTx(ctx, tx, stored); e != nil {
			return r, policy, p, e
		}
		digest, e := failedInstalledLegacyOffTx(ctx, tx, r, stored, p, false)
		if e != nil || digest != r.NativePoweroffSHA256 {
			return r, policy, p, ErrCapacityConflict
		}
	} else {
		stored, err := loadGuestRetirementV2Tx(ctx, tx, r.RetirementRequestID, true)
		if err != nil {
			return r, policy, p, err
		}
		i := stored.Request.Intent
		if i.PreregistrationID != preID || i.Tuple.Slot != 1 || i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.Generation != uint64(current.Generation) || i.Fence != uint64(current.FencingToken) || i.LeaseOwner != r.ClaimedIntent.LeaseOwner {
			return r, policy, p, ErrCapacityConflict
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return r, policy, p, err
		}
		var raw []byte
		var consistent bool
		if err = tx.QueryRowContext(ctx, `SELECT original_wire,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND observation_sha256=$2`, i.RequestID, r.NativePoweroffSHA256).Scan(&raw, &consistent); err != nil {
			return r, policy, p, err
		}
		var off GuestNativePoweroffReturnV2
		original, err := guestOriginalCreateReceiptV2Tx(ctx, tx, stored)
		b, e := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil || e != nil || !consistent || capacity.BusinessCreationSHA256(raw) != r.NativePoweroffSHA256 || capacity.DecodeGuestLifecycle(raw, &off) != nil || off.Challenge.IntentID != i.RequestID || off.Challenge.IntentSHA256 != capacity.GuestRetirementSHA(i) || off.Challenge.Tuple != i.Tuple || !guestNativePoweroffReadV2Content(off, p, b, original) {
			return r, policy, p, ErrCapacityConflict
		}
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return r, policy, p, err
	}
	if err = failedInstalledZeroUsefulTx(ctx, tx, r, now, activeOriginalRun); err != nil {
		return r, policy, p, err
	}
	return r, policy, p, nil
}

type FailedInstalledGuestAbsenceOwner struct {
	db                *sql.DB
	ctx               context.Context
	deadline          time.Time
	started           time.Time
	preID, id, issuer string
	candidate         []byte
	snapshot          string
	used              atomic.Bool
}

func (o *FailedInstalledGuestAbsenceOwner) Candidate() model.CapacityOriginalCreateDispositionCandidate {
	var c model.CapacityOriginalCreateDispositionCandidate
	if o != nil {
		_ = json.Unmarshal(o.candidate, &c)
	}
	return c
}

// This confirmed-create loader is distinct from the old uninstalled/settled
// failure lane. Only the existing closed native GET transport/decoder is reused.
func failedInstalledAbsenceCandidateTx(ctx context.Context, tx *sql.Tx, preID, id string) (model.CapacityOriginalCreateDispositionCandidate, string, error) {
	var c model.CapacityOriginalCreateDispositionCandidate
	r, policy, p, err := loadFailedInstalledQuiescentTx(ctx, tx, preID, id, "")
	if err != nil {
		return c, "", err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return c, "", err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return c, "", err
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
	if err != nil {
		return c, "", err
	}
	installed, err := loadGuestInstallationTx(ctx, tx, stored, receipt)
	if err != nil || capacity.GuestRetirementSHA(installed) != r.InstallationSHA256 || capacity.GuestRetirementSHA(receipt.Enrollment) != r.EnrollmentSHA256 {
		return c, "", ErrCapacityConflict
	}
	var raw []byte
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, stored.pre.OriginalCreateGrantID).Scan(&state, &raw); err != nil {
		return c, "", err
	}
	var created capacityMutationRecord
	if json.Unmarshal(raw, &created) != nil || state != "confirmed" || created.Grant.State != state || created.Settlement == nil || created.Proof == nil || created.Grant.Capability != created.Binding.EnsureCapability || created.Grant.GrantID != stored.pre.OriginalCreateGrantID || created.Grant.RequestSHA256 != stored.pre.OriginalCreateRequestSHA256 || created.Generation != stored.pre.Generation || created.FencingToken != stored.pre.Fence || created.PolicyID.String() != stored.pre.PolicyID || created.PolicyChecksum != stored.pre.PolicyChecksum || created.Settlement.ResourceID != stored.witness.Tuple.ResourceID || created.Settlement.ResourceCreatedAt != stored.witness.Tuple.CreatedAt || created.Settlement.Outcome != "accepted" || !created.Settlement.TransportCompleted || created.Settlement.OriginalProviderCreateReturn == nil || created.Settlement.OriginalProviderCreateReturn.AdapterSourceCommit != created.Binding.OriginalProviderSourceCommit {
		return c, "", ErrCapacityConflict
	}
	b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
	if err != nil || !reflect.DeepEqual(b, created.Binding) || checkMutationIntegration(ctx, tx, b) != nil {
		return c, "", ErrCapacityConflict
	}
	slot, exists, err := loadMutationSlot(ctx, tx, r.Namespace, p, b, 1)
	if err != nil || !exists || slot.Tombstone || slot.ResourceID != stored.witness.Tuple.ResourceID || slot.ResourceCreatedAt != stored.witness.Tuple.CreatedAt {
		return c, "", ErrCapacityConflict
	}
	x := created.Settlement
	c = model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: policy, Binding: b, Preregistration: stored.pre, Receipt: guestMutationReceiptV2(created), Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: x.AuxiliaryInventoryComplete, Profile: b.ProfileName, Slot: 1, GrantID: created.Grant.GrantID, AttemptID: created.AttemptID, RequestSHA256: created.Grant.RequestSHA256, ExpectedResourceID: x.ResourceID, ExpectedResourceCreatedAt: x.ResourceCreatedAt, OriginalAdapterSourceCommit: b.OriginalProviderSourceCommit, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, x.AuxiliaryResources...)}, OriginalGrantSHA256: capacity.BusinessCreationSHA256(raw), Generation: r.OriginalIntent.Generation, FencingToken: r.ClaimedIntent.FencingToken}
	if !x.AuxiliaryInventoryComplete {
		c.Request.OriginalCreateActionID = x.ActionID
	}
	digest := capacity.GuestRetirementSHA(struct {
		Record    FailedInstalledGuestDisposal
		Slot      capacityResourceSlot
		Candidate model.CapacityOriginalCreateDispositionCandidate
	}{r, slot, c})
	return c, digest, nil
}

func (s CapacityStore) BeginFailedInstalledGuestAbsence(ctx context.Context, preID, id, issuer string) (*FailedInstalledGuestAbsenceOwner, error) {
	if ctx == nil {
		return nil, ErrCapacityConflict
	}
	deadline, ok := ctx.Deadline()
	if s.DB == nil || issuer == "" || len(issuer) > 256 || !validCapacityExecutor(preID) || !validCapacityExecutor(id) || !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	c, snapshot, err := failedInstalledAbsenceCandidateTx(ctx, tx, preID, id)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &FailedInstalledGuestAbsenceOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), preID: preID, id: id, issuer: issuer, candidate: raw, snapshot: snapshot}, nil
}

func (s CapacityStore) CompleteFailedInstalledGuestAbsence(ctx context.Context, o *FailedInstalledGuestAbsenceOwner, observed model.CapacityOriginalCreateDispositionObservation) (FailedInstalledGuestDisposal, error) {
	var out FailedInstalledGuestDisposal
	if o == nil || o.db != s.DB || ctx != o.ctx || ctx.Err() != nil || !time.Now().Before(o.deadline) || !o.used.CompareAndSwap(false, true) {
		return out, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	c, snapshot, err := failedInstalledAbsenceCandidateTx(ctx, tx, o.preID, o.id)
	if err != nil || snapshot != o.snapshot {
		return out, ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	// Read content is shared; no settled/no-installation state is imported.
	if err = validateEnrolledFailedOriginalObservation(c, observed, o.started, time.Now().UTC(), 30*time.Second); err != nil {
		return out, err
	}
	out, _, err = loadFailedInstalledDisposalTx(ctx, tx, o.id, "quiescent")
	if err != nil {
		return out, err
	}
	out.Stage = "terminal"
	out.TerminalIssuer = o.issuer
	out.Observation = &observed
	out.ObservationSHA256 = capacity.GuestRetirementSHA(observed)
	if _, err = insertFailedInstalledDisposalTx(ctx, tx, out); err != nil {
		return out, err
	}
	p, err := parseCapacityPolicy(c.OriginalPolicy)
	if err != nil {
		return out, err
	}
	current, err := loadCapacityIntent(ctx, tx, out.Namespace, p, true)
	if err != nil {
		return out, err
	}
	slot, exists, err := loadMutationSlot(ctx, tx, out.Namespace, p, c.Binding, 1)
	if err != nil || !exists || slot.ResourceID != c.Request.ExpectedResourceID || slot.ResourceCreatedAt != c.Request.ExpectedResourceCreatedAt {
		return out, ErrCapacityConflict
	}
	slot.ResourceID = ""
	slot.Tombstone = true
	slot.ObservedAt = now
	slot.ReceiptRef = "failed-installed-native-absence:" + out.ID + ":" + out.ObservationSHA256
	if err = saveMutationSlot(ctx, tx, out.Namespace, p, c.Binding, 1, slot); err != nil {
		return out, err
	}
	next := current
	marker := *current.FailedInstalledDisposal
	marker.Stage = "terminal"
	next.FailedInstalledDisposal = &marker
	next.Phase = "disposed_failed_installed"
	next.Decision.Action = "hold"
	next.Decision.Units = 0
	next.Decision.Reason = "failed_installed_native_disposal_completed_replacement_required"
	next.Assessment.Snapshot.Units = 0
	next.Assessment.Snapshot.ObservedAt = now
	next.Assessment.Snapshot.ResourceVersion = "failed-installed-native-absence:" + out.ObservationSHA256
	next.UpdatedAt = now
	if err = persistFailedInstalledDisposalIntentTx(ctx, tx, current, next); err != nil {
		return out, err
	}
	if ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return out, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return FailedInstalledGuestDisposal{}, err
	}
	return out, nil
}

func (s CapacityStore) ReadFailedInstalledGuestDisposal(ctx context.Context, preID string) ([]FailedInstalledGuestDisposal, error) {
	if s.DB == nil || !validCapacityExecutor(preID) {
		return nil, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT original_wire,record_sha256 FROM public.capacity_guest_failed_installed_disposals WHERE preregistration_id=$1 ORDER BY recorded_at,stage`, preID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FailedInstalledGuestDisposal{}
	for rows.Next() {
		var raw []byte
		var sha string
		var r FailedInstalledGuestDisposal
		if err = rows.Scan(&raw, &sha); err != nil {
			return nil, err
		}
		if capacity.BusinessCreationSHA256(raw) != sha || decodeFailedInstalledDisposal(raw, &r) != nil {
			return nil, ErrCapacityConflict
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, sql.ErrNoRows
	}
	return out, nil
}
