package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type guestReconcileSource struct {
	step                    model.WorkflowStepSpec
	workflow                model.Manifest
	source, mode, requestID string
	inventory               model.CapacityVMFleetInventory
}

// Source installation is inside the actual generic workflow executor. This is
// not a callback registration, API input, configurable URL or proof factory.
func (s CapacityStore) WithOriginalGuestReconcile(workflow model.Manifest, step model.WorkflowStepSpec, actualSource, mode, requestID string, inventory model.CapacityVMFleetInventory) CapacityStore {
	s.guestReconcile = &guestReconcileSource{step: step, workflow: workflow, source: actualSource, mode: mode, requestID: requestID, inventory: inventory}
	return s
}

func guestReconcileLive(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Now().Before(deadline)
}

// PG lease time stays a duration. Subtract the WHOLE original query/transaction
// round trip, then let the same Core invocation capture one local monotonic
// deadline. No Core wall/PG absolute comparison, renewal or later remint.
func (s CapacityStore) OriginalGuestReconcileLeaseDeadline(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (time.Time, error) {
	if s.DB == nil || s.guestReconcile == nil || !guestReconcileLive(ctx) {
		return time.Time{}, ErrCapacityLease
	}
	started := time.Now()
	var budget time.Duration
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if e := s.guestReconcileSourceTx(ctx, tx, policy, p); e != nil {
			return e
		}
		if current.LeaseExpiresAt == nil {
			return ErrCapacityLease
		}
		budget = current.LeaseExpiresAt.Sub(now)
		return nil
	})
	returned := time.Now()
	budget -= returned.Sub(started)
	if err != nil || budget <= 0 || !guestReconcileLive(ctx) {
		return time.Time{}, ErrCapacityLease
	}
	return returned.Add(budget), nil
}

func (s CapacityStore) guestReconcileSourceTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec) error {
	o := s.guestReconcile
	if o == nil || !guestReconcileLive(ctx) || s.WorkflowID != o.workflow.ID || o.source != capacity.CurrentGuestCoreSource() || p.GuestNotifyReconcileBinding == nil || capacity.ValidateGuestNotifyReconcileBinding(p) != nil || p.GuestRetirementBinding.CoreAuthoritySourceCommit != o.source || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, p.Profiles[0].Provider) {
		return ErrCapacityConflict
	}
	var policyID, policySHA string
	var policyActive bool
	if tx.QueryRowContext(ctx, `SELECT id::text,checksum,active FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&policyID, &policySHA, &policyActive) != nil || policyID != policy.ID.String() || policySHA != policy.Checksum || !policyActive {
		return ErrCapacityConflict
	}
	var current model.Manifest
	if tx.QueryRowContext(ctx, `SELECT id,checksum,active,spec FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2 ORDER BY version DESC,id DESC LIMIT 1 FOR SHARE`, p.Workflow.Namespace, p.Workflow.Name).Scan(&current.ID, &current.Checksum, &current.Metadata.Active, &current.Spec) != nil || current.ID != o.workflow.ID || current.Checksum != o.workflow.Checksum || !current.Metadata.Active {
		return ErrCapacityConflict
	}
	var spec model.WorkflowManifestSpec
	if json.Unmarshal(current.Spec, &spec) != nil || capacity.ValidateOriginalGuestReconcileGraph(spec, policy, p) != nil {
		return ErrCapacityConflict
	}
	found := false
	for _, step := range spec.Steps {
		found = found || reflect.DeepEqual(step, o.step)
	}
	if !found || o.step.Use.Kind != "yggdrasil" || o.step.Use.Operation != capacity.PlanOriginalGuestOperation && o.step.Use.Operation != capacity.CompleteOriginalGuestOperation {
		return ErrCapacityConflict
	}
	return checkMutationIntegration(ctx, tx, p.MutationBindings[0])
}

func (s CapacityStore) guestReconcileMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, now time.Time, refresh bool) ([]GuestNotifyFloorMember, error) {
	if err := s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return nil, err
	}
	b := p.MutationBindings[0]
	inv := s.guestReconcile.inventory
	proofs, err := capacity.VMInventoryProofs(p, b, inv, "", 0, now, "original-guest-reconcile:"+policy.ID.String())
	if err != nil {
		return nil, err
	}
	bySlot := map[int]model.CapacityMutationProof{}
	for _, proof := range proofs {
		bySlot[proof.Slot] = proof
	}
	out := []GuestNotifyFloorMember{}
	for _, member := range p.GuestRetirementBinding.Members {
		slot, exists, e := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot)
		if e != nil {
			return nil, e
		}
		proof, live := bySlot[member.Slot]
		if !live {
			if exists && slot.ResourceID != "" && !slot.Tombstone {
				return nil, ErrCapacityConflict
			}
			continue
		}
		// Native presence cannot adopt an unrecorded or replacement lifetime.
		if !exists || slot.Tombstone || slot.ResourceID != proof.ResourceID || slot.ResourceCreatedAt != proof.ResourceCreatedAt || slot.DesiredSpecSHA256 != proof.RequestSHA256 || slot.BindingName != b.Name || slot.ProfileName != b.ProfileName {
			return nil, ErrCapacityConflict
		}
		receipt, e := guestNotifyMemberReceiptTx(ctx, tx, policy, p, member, slot)
		if e != nil {
			return nil, e
		}
		if refresh {
			if !guestReconcileLive(ctx) {
				return nil, ErrCapacityLease
			}
			slot.ObservedAt, slot.ReceiptRef = proof.ObservedAt, proof.ReceiptRef
			if e = saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot, slot); e != nil {
				return nil, e
			}
		}
		out = append(out, GuestNotifyFloorMember{Slot: member.Slot, PreregistrationID: receipt.PreregistrationID})
	}
	if len(out) != len(proofs) {
		return nil, ErrCapacityConflict
	}
	return out, nil
}

// Re-observe ONLY the exact already-enrolled native tuples. Empty membership
// is legitimate at first creation. This method cannot add or adopt a slot.
func (s CapacityStore) OriginalGuestReconcileMembers(ctx context.Context, policy model.Manifest) ([]GuestNotifyFloorMember, bool, error) {
	if s.DB == nil || s.guestReconcile == nil || !guestReconcileLive(ctx) {
		return nil, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return nil, false, err
	}
	var active bool
	var checksum string
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT active,checksum FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&active, &checksum) != nil || !active || checksum != policy.Checksum {
		return nil, false, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, false, err
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return nil, false, err
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled','compensating')`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending); err != nil {
		return nil, false, err
	}
	// Unknown/redeemed originals retain authority. No inventory adoption,
	// observation refresh, new send, timeout-based replay or implicit cleanup.
	if pending != 0 {
		return nil, true, nil
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now.UTC(), true)
	if err != nil || !guestReconcileLive(ctx) {
		return nil, false, ErrCapacityConflict
	}
	err = tx.Commit()
	if err != nil || !guestReconcileLive(ctx) {
		return nil, false, ErrCapacityLease
	}
	return members, false, nil
}

// Persist actual pressure windows while preserving a terminal, unleased
// useful epoch on HOLD. Generic Assess retains its historical semantics.
// Turning a stable epoch into phase=hold would otherwise disable the existing
// maintenance protocol precisely when ordinary demand remains within bounds.
func (s CapacityStore) AssessOriginalGuest(ctx context.Context, policy model.Manifest, a model.CapacityAssessment) (model.CapacityIntent, error) {
	if s.DB == nil || s.guestReconcile == nil || !guestReconcileLive(ctx) {
		return model.CapacityIntent{}, ErrCapacityConflict
	}
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old != nil && pendingCapacityPhase(old.Phase) && old.Phase != "proposed" {
			return *old, "", nil
		}
		clock := model.CapacityClockState{}
		generation, fence := int64(0), int64(0)
		if old != nil {
			generation, fence = old.Generation, old.FencingToken
			clock.LastActionAt = old.Decision.Clock.LastActionAt
			if old.PolicyChecksum == policy.Checksum && sameCapacityResourceIdentity(old.Assessment.Snapshot, a.Snapshot) {
				clock = old.Decision.Clock
			}
		}
		decision, err := capacity.Assess(p, a, clock, now)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		decision.ExecutionPermitted = decision.ExecutionPermitted && s.ExecutionEnabled
		phase := "hold"
		if decision.Action != "hold" {
			if old == nil || old.Phase != "proposed" || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Decision.Action != decision.Action || old.Decision.Profile != decision.Profile || old.Decision.Units != decision.Units {
				if generation >= maxCapacityGeneration {
					return model.CapacityIntent{}, "", ErrCapacityConflict
				}
				generation++
			}
			phase = "proposed"
		} else if old != nil && guestNotifyStableEpoch(*old) && old.PolicyID == policy.ID && old.PolicyChecksum == policy.Checksum && sameCapacityResourceIdentity(old.Assessment.Snapshot, a.Snapshot) && old.Decision.Units == a.Snapshot.Units && old.Decision.Profile == a.Snapshot.Profile {
			phase = old.Phase
		}
		return model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: generation, FencingToken: fence, Phase: phase, Decision: decision, Assessment: a, UpdatedAt: now}, "", nil
	})
}

// This source-only phase API deliberately has no healthy/inflight/proof input.
// It retains the common transaction's native mutation and useful-membership
// gates; source raw originals are checked below before any phase persistence.
func (s CapacityStore) AdvanceOriginalGuest(ctx context.Context, policy model.Manifest, generation, fence int64, owner, phase string, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	if s.DB == nil || s.guestReconcile == nil || !guestReconcileLive(ctx) {
		return model.CapacityIntent{}, ErrCapacityConflict
	}
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.CompleteOriginalGuestOperation || !guestReconcileLive(ctx) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if err := s.checkLease(p, policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !capacityTransitionAllowed(old.Phase, phase) || !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) || assessment.Snapshot.Units != old.Decision.Units || assessment.Snapshot.Profile != old.Decision.Profile || !capacityProfileCurrent(p, old.Decision, now) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if err := capacity.ValidateAssessment(p, assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		next := *old
		next.Phase, next.Assessment, next.UpdatedAt = phase, assessment, now
		if phase == "promoted" {
			next.LeaseOwner, next.LeaseExecutorID, next.LeaseExpiresAt = "", "", nil
			next.Decision.Clock.LastActionAt = now
			next.Decision.Clock.UpSince, next.Decision.Clock.DownSince = time.Time{}, time.Time{}
		}
		return next, "original-guest-reconcile:" + s.WorkflowID.String() + ":" + phase, nil
	})
}

func (s CapacityStore) guestReconcilePhaseTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old, next model.CapacityIntent, now time.Time) error {
	if err := s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return err
	}
	if s.guestReconcile.mode == "refresh" || s.guestReconcile.mode != "provision" && s.guestReconcile.mode != "retire" || capacityIntentReduction(old) != (s.guestReconcile.mode == "retire") {
		return ErrCapacityConflict
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now, true)
	if err != nil || len(members) != next.Decision.Units {
		return ErrCapacityConflict
	}
	snapshot, err := capacity.GuestReconcileSnapshot(policy, p, s.guestReconcile.inventory, now)
	if err != nil || !reflect.DeepEqual(snapshot, next.Assessment.Snapshot) {
		return ErrCapacityConflict
	}
	var pending int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled','compensating')`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending) != nil || pending != 0 {
		return ErrCapacityConflict
	}
	if s.guestReconcile.mode == "retire" {
		stored, err := loadGuestRetirementV2Tx(ctx, tx, s.guestReconcile.requestID, true)
		if err != nil {
			return err
		}
		i := stored.Request.Intent
		if i.PolicyID != policy.ID.String() || i.PolicyChecksum != policy.Checksum || i.WorkflowID != s.WorkflowID.String() || i.Generation != uint64(old.Generation) || i.Fence != uint64(old.FencingToken) || i.LeaseOwner != old.LeaseOwner || stored.ExecutorID != s.ExecutorID {
			return ErrCapacityConflict
		}
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err != nil {
			return err
		}
		var raw []byte
		if tx.QueryRowContext(ctx, `SELECT g.grant_record FROM public.capacity_vm_retirement_delete_bindings d JOIN public.capacity_mutation_grants g ON g.id=d.destroy_grant_id WHERE d.intent_id=$1 AND g.state='confirmed'`, i.RequestID).Scan(&raw) != nil {
			return ErrCapacityConflict
		}
		var original capacityMutationRecord
		if json.Unmarshal(raw, &original) != nil || original.Grant.ExpectedResourceID != i.Tuple.ResourceID || original.Grant.ExpectedResourceCreatedAt != i.Tuple.CreatedAt || original.Grant.Slot != i.Slot {
			return ErrCapacityConflict
		}
		if _, err = guestDestroyEligibilityRecordV2ForGrantTx(ctx, tx, original); err != nil {
			return err
		}
		var digest string
		var at time.Time
		var consistent bool
		if tx.QueryRowContext(ctx, `SELECT original_wire,observation_sha256,recorded_at,original_observation_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 ORDER BY recorded_at DESC,id DESC LIMIT 1`, original.Grant.GrantID).Scan(&raw, &digest, &at, &consistent) != nil || !consistent || !capacity.Fresh(at, now, p.MaxEvidenceAgeSeconds) {
			return ErrCapacityConflict
		}
		var absence GuestNativeAbsenceReturnV2
		if capacity.DecodeGuestLifecycle(raw, &absence) != nil || capacity.GuestRetirementSHA(absence) != digest {
			return ErrCapacityConflict
		}
		if _, err = guestNativeAbsenceContentV2(absence, p, original); err != nil {
			return err
		}
	}
	if !guestReconcileLive(ctx) {
		return ErrCapacityLease
	}
	return nil
}
