package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type GuestRetirementOriginal struct {
	Preregistration model.CapacityGuestOriginalProvisioningPreregistration
	Binding         model.CapacityGuestRetirementBinding
	Member          model.CapacityGuestRetirementMemberBinding
	Receipt         model.CapacityGuestOriginalProvisioningReceipt
	Request         model.CapacityGuestRetirementRequest
	RegistrationSHA string
	WitnessSHA      string
	ExecutorID      string
}

func (s CapacityStore) WithOriginalGuestRetirement(step model.WorkflowStepSpec, actualSource string) CapacityStore {
	s.guestRetirementOrigin = &guestOriginalProvisioningContext{step: step, source: actualSource}
	return s
}

func (s CapacityStore) guestCreateRedemptionTx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord, now time.Time) error {
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, original.Grant.GrantID).Scan(&id); err != nil {
		return ErrCapacityConflict
	}
	stored, err := loadGuestOriginalTx(ctx, tx, id)
	if err != nil || stored.pre.OriginalCreateRequestSHA256 != original.Grant.RequestSHA256 || stored.pre.Generation != original.Generation || stored.pre.Fence != original.FencingToken || stored.pre.ExecutorID != original.ExecutorID {
		return ErrCapacityConflict
	}
	_, _, err = s.guestCurrentTx(ctx, tx, stored, now, true)
	return err
}

// The retirement has its own ORIGINAL context and current epoch; an already
// enrolled runtime does not regain provisioning permission on lease renewal.
func (s CapacityStore) IssueGuestRetirement(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preregistrationID, nonce string, key ed25519.PrivateKey) (model.CapacityGuestRetirementRequest, error) {
	var result model.CapacityGuestRetirementRequest
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		stored, err := loadGuestOriginalTx(ctx, tx, preregistrationID)
		origin := s.guestRetirementOrigin
		if err != nil || origin == nil || origin.source != capacity.CurrentGuestCoreSource() || origin.source != stored.binding.CoreAuthoritySourceCommit || origin.step.Use.Kind != "yggdrasil" || origin.step.Use.Operation != capacity.RetireOriginalGuestOperation || origin.step.TimeoutSeconds < 1 || origin.step.TimeoutSeconds > 86400 || origin.step.Retry.MaxAttempts > 1 || origin.step.ForEach != nil || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding) || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.WorkflowID != s.WorkflowID.String() || !capacityIntentReduction(current) || (current.Phase != "draining" && current.Phase != "drained") {
			return ErrCapacityConflict
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preregistrationID)
		if err != nil || capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, receipt.Enrollment, now) != nil || !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) || !capacity.ValidDigest(nonce) {
			return ErrCapacityConflict
		}
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || current.LeaseExpiresAt == nil || !deadline.After(now) {
			return ErrCapacityLease
		}
		contextDeadline := deadline
		deadline, err = capacity.GuestOriginalRetirementDeadline(ctx, now, *current.LeaseExpiresAt)
		if err != nil {
			return ErrCapacityLease
		}
		b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
		if err != nil || checkMutationIntegration(ctx, tx, b) != nil || s.guestRetirementFloorTx(ctx, tx, policy.Metadata.Namespace, p, current, b, stored.pre.Slot, now) != nil {
			return ErrCapacityConflict
		}
		var workflowChecksum string
		var workflowRaw []byte
		if err = tx.QueryRowContext(ctx, `SELECT checksum,spec FROM public.manifests WHERE id=$1 AND active FOR SHARE`, s.WorkflowID).Scan(&workflowChecksum, &workflowRaw); err != nil {
			return err
		}
		var workflow model.WorkflowManifestSpec
		if json.Unmarshal(workflowRaw, &workflow) != nil || workflow.Authorization == nil {
			return ErrCapacityMutationAuthorization
		}
		matched := false
		for _, step := range workflow.Steps {
			matched = matched || reflect.DeepEqual(step, origin.step)
		}
		if !matched {
			return ErrCapacityMutationAuthorization
		}
		intent := model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, BindingName: stored.member.Name, Slot: stored.pre.Slot, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), NonceSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), Tuple: receipt.Enrollment.Statement.Tuple, Actor: receipt.Enrollment.Statement.Actor, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String(), WorkflowChecksum: workflowChecksum, Generation: uint64(generation), Fence: uint64(fence), LeaseOwner: owner, WithdrawOperationID: uuid.NewString(), DrainOperationID: uuid.NewString(), OriginalDeadline: deadline, IssuedAt: now}
		// These source-generated semantic request identities are carried into
		// the exact original writer control frames and owning return records.
		intent.WithdrawRequestSHA256 = capacity.GuestRetirementSHA([]string{"original_guest_withdraw_v1", intent.RequestID, intent.WithdrawOperationID, intent.EnrollmentSHA256, receipt.Enrollment.Statement.WriterRosterSHA256})
		intent.DrainRequestSHA256 = capacity.GuestRetirementSHA([]string{"original_guest_drain_v1", intent.RequestID, intent.DrainOperationID, intent.EnrollmentSHA256, receipt.Enrollment.Statement.WriterRosterSHA256})
		result = model.CapacityGuestRetirementRequest{Intent: intent, Nonce: nonce}
		result.Signature, err = capacity.GuestLifecycleSignature(key, intent)
		if err != nil || capacity.GuestRetirementRequest(result, receipt.Enrollment, now, true) != nil {
			return ErrCapacityConflict
		}
		durable := result
		durable.Nonce = ""
		wire, err := json.Marshal(durable)
		if err != nil {
			return err
		}
		intentWire, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at,original_wire) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, intent.RequestID, preregistrationID, intent.AttemptID, intent.NonceSHA256, capacity.GuestRetirementSHA(intent), intentWire, deadline, now, wire)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_retirement_contexts(intent_id,executor_id,original_step_id,original_step_timeout_seconds,original_context_deadline,core_actual_source_commit,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, intent.RequestID, s.ExecutorID, origin.step.ID, origin.step.TimeoutSeconds, contextDeadline, origin.source, now)
		}
		return err
	})
	return result, err
}

func loadGuestRetirementTx(ctx context.Context, tx *sql.Tx, id string) (GuestRetirementOriginal, error) {
	var result GuestRetirementOriginal
	if !validCapacityExecutor(id) {
		return result, ErrCapacityMutationAuthorization
	}
	var preregistrationID, digest string
	var wire []byte
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT preregistration_id::text,original_wire,intent_sha256,intent_record=convert_from(original_wire,'UTF8')::jsonb->'intent' AND original_deadline=(intent_record->>'original_deadline')::timestamptz AND created_at=(intent_record->>'issued_at')::timestamptz AND id::text=intent_record->>'request_id' AND attempt_id::text=intent_record->>'attempt_id' AND nonce_sha256=intent_record->>'nonce_sha256' FROM public.capacity_vm_retirement_intents WHERE id=$1 FOR SHARE`, id).Scan(&preregistrationID, &wire, &digest, &consistent)
	if err != nil {
		return result, err
	}
	if !consistent || capacity.DecodeGuestLifecycle(wire, &result.Request) != nil || result.Request.Nonce != "" || capacity.GuestRetirementSHA(result.Request.Intent) != digest {
		return result, ErrCapacityConflict
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preregistrationID)
	if err != nil {
		return result, err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return result, err
	}
	result.Preregistration, result.Binding, result.Member = stored.pre, stored.binding, stored.member
	result.WitnessSHA = capacity.GuestRetirementSHA(stored.witness)
	result.Receipt, result.RegistrationSHA, err = loadGuestReceiptTx(ctx, tx, preregistrationID)
	if err != nil || capacity.GuestRetirementRequest(result.Request, result.Receipt.Enrollment, result.Request.Intent.IssuedAt, false) != nil {
		return result, ErrCapacityConflict
	}
	var actualSource string
	if err = tx.QueryRowContext(ctx, `SELECT executor_id::text,core_actual_source_commit FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, id).Scan(&result.ExecutorID, &actualSource); err != nil || actualSource != result.Binding.CoreAuthoritySourceCommit {
		return result, ErrCapacityConflict
	}
	return result, nil
}

func (s CapacityStore) guestRetirementTransaction(ctx context.Context, id string, fn func(*sql.Tx, GuestRetirementOriginal, time.Time) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var namespace, environment, domain, dimension string
	if err = tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1`, id).Scan(&namespace, &environment, &domain, &dimension); err != nil {
		return err
	}
	if err = lockMutationScope(ctx, tx, namespace, model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension}); err != nil {
		return err
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, stored, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s CapacityStore) guestRetirementCurrentTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal, now time.Time, liveOriginal bool) (model.Manifest, model.CapacityPolicySpec, model.CapacityIntent, error) {
	i := stored.Request.Intent
	var policy model.Manifest
	var p model.CapacityPolicySpec
	var current model.CapacityIntent
	var active bool
	policy.ID, _ = uuid.Parse(i.PolicyID)
	policy.Kind = "capacity_policy"
	err := tx.QueryRowContext(ctx, `SELECT namespace,name,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, policy.ID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Checksum, &policy.Spec, &active)
	if err != nil {
		return policy, p, current, err
	}
	p, err = parseCapacityPolicy(policy)
	if err != nil || !active || policy.Checksum != i.PolicyChecksum || stored.Binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.Binding) || (liveOriginal && !now.Before(i.OriginalDeadline)) {
		return policy, p, current, ErrCapacityConflict
	}
	var checksum string
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, i.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&checksum, &active); err != nil || !active || checksum != i.WorkflowChecksum {
		return policy, p, current, ErrCapacityConflict
	}
	current, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return policy, p, current, err
	}
	owned := s
	// This original retirement is bound to the CURRENT owning capacity epoch.
	owned.ExecutorID = stored.ExecutorID
	if err = owned.checkLease(p, policy, &current, int64(i.Generation), int64(i.Fence), i.LeaseOwner, now); err != nil || !capacityIntentReduction(current) || (current.Phase != "draining" && current.Phase != "drained") {
		return policy, p, current, ErrCapacityConflict
	}
	b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
	if err != nil || checkMutationIntegration(ctx, tx, b) != nil || !capacityProfileCurrent(p, current.Decision, now) || s.guestRetirementFloorTx(ctx, tx, policy.Metadata.Namespace, p, current, b, i.Slot, now) != nil {
		return policy, p, current, ErrCapacityConflict
	}
	if guestNativeUsefulFloorTx(ctx, tx, stored, now) != nil {
		return policy, p, current, ErrCapacityConflict
	}
	return policy, p, current, nil
}

// This preserves the existing physical floor/lease gates. It never labels a
// slot count as serving/useful capacity or replaces the original writer drain.
func (s CapacityStore) guestRetirementFloorTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, current model.CapacityIntent, b model.CapacityMutationBinding, slot int, now time.Time) error {
	if slot <= b.ProtectedSlots || !capacityIntentReduction(current) || current.Decision.Units < p.Floor {
		return ErrCapacityConflict
	}
	var live, fresh, pending int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE (slot_record->>'observed_at')::timestamptz BETWEEN $5 AND $6) FROM public.capacity_resource_slots WHERE NOT (slot_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, namespace, p.Environment, p.Domain, p.Dimension, now.Add(-time.Duration(p.MaxEvidenceAgeSeconds)*time.Second), now.Add(5*time.Second)).Scan(&live, &fresh); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT (grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'capability'=$5 AND COALESCE(grant_record->'grant'->>'compensation_of','')='' AND slot<>$6`, namespace, p.Environment, p.Domain, p.Dimension, b.DestroyCapability, slot).Scan(&pending); err != nil {
		return err
	}
	if live != fresh || live-pending-1 < p.Floor || live-pending-1 < current.Decision.Units {
		return ErrCapacityConflict
	}
	return nil
}

// A durable possible-send is reserved before the caller's sole POST. Its
// original HTTP result/Read/Close is recorded separately; timeout is not retry.
func (s CapacityStore) ReserveGuestCaller(ctx context.Context, request model.CapacityGuestRetirementRequest) error {
	return s.guestRetirementTransaction(ctx, request.Intent.RequestID, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if stored.Request.Intent != request.Intent || stored.Request.Signature != request.Signature || capacity.GuestRetirementRequest(request, stored.Receipt.Enrollment, now, true) != nil {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,$4,$5,$6)`, request.Intent.RequestID, request.Intent.AttemptID, capacity.GuestRetirementSHA(request), stored.Member.ActorClientPrincipal, now, request.Intent.OriginalDeadline)
		return err
	})
}

// Authenticated GET recovery exposes no plaintext nonce and no permission to
// submit another original POST or refresh a callback deadline.
func (s CapacityStore) GuestRetirementOriginal(ctx context.Context, principal, id, intentSHA string) (GuestRetirementOriginal, error) {
	var result GuestRetirementOriginal
	err := s.guestRetirementTransaction(ctx, id, func(_ *sql.Tx, stored GuestRetirementOriginal, _ time.Time) error {
		if principal != stored.Member.ActorClientPrincipal || intentSHA != capacity.GuestRetirementSHA(stored.Request.Intent) {
			return ErrCapacityMutationAuthorization
		}
		result = stored
		return nil
	})
	return result, err
}

func (s CapacityStore) RecordGuestObservation(ctx context.Context, id string, observed model.CapacityGuestRetirementObservation) error {
	return s.guestRetirementTransaction(ctx, id, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if !capacity.GuestRetirementObservedReturnAuthentic(observed, stored.Receipt.Enrollment, stored.Request.Intent, now) {
			return ErrCapacityConflict
		}
		var oldWire []byte
		var lastSequence int
		err := tx.QueryRowContext(ctx, `SELECT sequence,original_wire FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence DESC LIMIT 1 FOR SHARE`, id).Scan(&lastSequence, &oldWire)
		if errors.Is(err, sql.ErrNoRows) {
			if observed.Record.Sequence != 1 {
				return ErrCapacityConflict
			}
		} else if err != nil {
			return err
		} else {
			var old model.CapacityGuestRetirementObservation
			if capacity.DecodeGuestLifecycle(oldWire, &old) != nil {
				return ErrCapacityConflict
			}
			if lastSequence == observed.Record.Sequence && old.RecordSHA256 == observed.RecordSHA256 {
				return nil // Readback of the same immutable source record.
			}
			if !capacity.GuestRetirementRecordSuccessor(old.Record, observed.Record) {
				return ErrCapacityConflict
			}
		}
		wire, err := json.Marshal(observed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, id, observed.Record.Sequence, observed.Record.State, observed.Record.PreviousSHA256, observed.RecordSHA256, string(wire), now, wire)
		return err
	})
}

func guestQuiescentProofTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal) (model.CapacityGuestRetirementObservation, error) {
	var result model.CapacityGuestRetirementObservation
	rows, err := tx.QueryContext(ctx, `SELECT original_wire FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, stored.Request.Intent.RequestID)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return result, err
		}
		var observed model.CapacityGuestRetirementObservation
		if capacity.DecodeGuestLifecycle(raw, &observed) != nil || capacity.GuestRetirementObservation(observed, stored.Receipt.Enrollment, stored.Request.Intent, observed.ObservedAt, false) != nil || observed.Record.Sequence != count+1 || (count > 0 && !capacity.GuestRetirementRecordSuccessor(result.Record, observed.Record)) {
			return result, ErrCapacityConflict
		}
		result, count = observed, count+1
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if err = rows.Close(); err != nil {
		return result, err
	}
	if count != 4 || result.Record.State != "poweroff_command_returned" {
		return result, ErrCapacityConflict
	}
	var callerWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, stored.Request.Intent.RequestID).Scan(&callerWire); err != nil {
		return result, ErrCapacityConflict
	}
	var caller GuestOriginalCallerReturn
	var originalReply model.CapacityGuestRetirementObservation
	if capacity.DecodeGuestLifecycle(callerWire, &caller) != nil || !GuestOriginalCallerBodyFactsValid(caller) || caller.ResponseBodyScope != capacity.GuestOriginalBodyCompleteRead || caller.RequestID != stored.Request.Intent.RequestID || caller.AttemptID != stored.Request.Intent.AttemptID || !caller.OriginalDeadline.Equal(stored.Request.Intent.OriginalDeadline) || !caller.BodyPersisted || caller.ReceivedBodyBytes != len(caller.Body) || caller.PreflightFailed || caller.DoFailed || caller.ReadFailed || caller.CloseFailed || caller.OriginalContextFailed || caller.Status != 200 || caller.DoStartedAt.Before(caller.StartedAt) || caller.DoReturnedAt.Before(caller.DoStartedAt) || caller.ReadReturnedAt.Before(caller.DoReturnedAt) || caller.CloseReturnedAt.Before(caller.ReadReturnedAt) || caller.DriverReturnedAt.Before(caller.CloseReturnedAt) || !caller.DriverReturnedAt.Before(caller.OriginalDeadline) || caller.ResponseSHA256 != capacity.BusinessCreationSHA256(caller.Body) || capacity.DecodeGuestLifecycle(caller.Body, &originalReply) != nil || capacity.GuestRetirementObservation(originalReply, stored.Receipt.Enrollment, stored.Request.Intent, originalReply.ObservedAt, false) != nil || originalReply.RecordSHA256 != result.RecordSHA256 || !caller.CloseReturnedAt.After(result.Record.RecordedAt) {
		return result, ErrCapacityConflict
	}
	return result, nil
}

func (s CapacityStore) RecordGuestNativePoweroff(ctx context.Context, id string, plan model.CapacityVMFleetPlan) error {
	return s.guestRetirementTransaction(ctx, id, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		_, p, _, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, false)
		if err != nil {
			return err
		}
		quiescent, err := guestQuiescentProofTx(ctx, tx, stored)
		if err != nil {
			return err
		}
		b, err := capacity.VMObservationBinding(p, stored.Binding.MutationBindingName)
		if err != nil || plan.Server == nil || plan.Server.Status != "off" || plan.Server.ID != stored.Request.Intent.Tuple.ResourceID || plan.Server.CreatedAt != stored.Request.Intent.Tuple.CreatedAt {
			return ErrCapacityConflict
		}
		observed, err := time.Parse(time.RFC3339Nano, plan.Server.ObservedAt)
		if err != nil || observed.Before(quiescent.Record.PoweroffOperation.WaitReturnedAt) || !capacity.Fresh(observed, now, stored.Binding.MaxEvidenceAgeSeconds) {
			return ErrCapacityConflict
		}
		var grantWire []byte
		if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, stored.Preregistration.OriginalCreateGrantID).Scan(&grantWire); err != nil {
			return err
		}
		var original capacityMutationRecord
		if json.Unmarshal(grantWire, &original) != nil || original.Settlement == nil {
			return ErrCapacityConflict
		}
		r := model.CapacityMutationReceipt{Grant: original.Grant, AttemptID: original.AttemptID, Outcome: original.Settlement.Outcome, TransportCompleted: original.Settlement.TransportCompleted, ResourceID: original.Settlement.ResourceID, ResourceCreatedAt: original.Settlement.ResourceCreatedAt}
		if _, err = capacity.VMServerPlanProof(p, b, plan, r, "observed", now, "guest-original-native-poweroff:"+id); err != nil {
			return err
		}
		wire, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT (intent_id,observation_sha256) DO NOTHING`, uuid.New(), id, capacity.GuestRetirementSHA(plan), wire, string(wire), now)
		return err
	})
}

func (s CapacityStore) guestDestroyEligibilityTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, b model.CapacityMutationBinding, slot int, resourceID, created string, now time.Time, destroyGrantID string) error {
	if p.GuestRetirementBinding == nil || p.GuestRetirementBinding.MutationBindingName != b.Name || capacity.ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil {
		return ErrCapacityConflict
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT r.id::text FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=r.preregistration_id WHERE e.enrollment_record->'statement'->'tuple'->>'resource_id'=$1 AND e.enrollment_record->'statement'->'tuple'->>'resource_created_at'=$2 AND r.intent_record->>'policy_id'=$3 AND r.intent_record->>'policy_checksum'=$4 AND r.intent_record->>'generation'=$5 AND r.intent_record->>'fence'=$6 AND r.intent_record->>'lease_owner'=$7`, resourceID, created, policy.ID.String(), policy.Checksum, fmt.Sprint(current.Generation), fmt.Sprint(current.FencingToken), current.LeaseOwner).Scan(&id); err != nil {
		return ErrCapacityConflict
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil || stored.Request.Intent.Slot != slot || stored.Request.Intent.Tuple.InstanceID != b.IntegrationInstanceID || stored.Request.Intent.Tuple.ScopeChecksum != b.ScopeChecksum || stored.Request.Intent.WorkflowID != s.WorkflowID.String() {
		return ErrCapacityConflict
	}
	if _, _, _, err = s.guestRetirementCurrentTx(ctx, tx, stored, now, false); err != nil {
		return err
	}
	if _, err = guestQuiescentProofTx(ctx, tx, stored); err != nil {
		return err
	}
	var wire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 ORDER BY recorded_at DESC LIMIT 1`, id).Scan(&wire); err != nil {
		return ErrCapacityConflict
	}
	var plan model.CapacityVMFleetPlan
	if stored.Binding.EvidenceClass == "native_qemu_qualification" {
		if !guestNativeQEMUStoredOff(ctx, tx, stored, wire, now) {
			return ErrCapacityConflict
		}
	} else {
		if capacity.DecodeVMObservation(json.RawMessage(wire), &plan) != nil || plan.Server == nil || plan.Server.Status != "off" || plan.Server.ID != resourceID || plan.Server.CreatedAt != created {
			return ErrCapacityConflict
		}
		at, err := time.Parse(time.RFC3339Nano, plan.Server.ObservedAt)
		if err != nil || !capacity.Fresh(at, now, stored.Binding.MaxEvidenceAgeSeconds) {
			return ErrCapacityConflict
		}
	}
	if destroyGrantID != "" {
		var linked string
		if err = tx.QueryRowContext(ctx, `SELECT intent_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1`, destroyGrantID).Scan(&linked); err != nil || linked != id {
			return ErrCapacityConflict
		}
	}
	return nil
}

func (s CapacityStore) bindGuestDestroyTx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord, now time.Time) error {
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_retirement_intents WHERE intent_record->'tuple'->>'resource_id'=$1 AND intent_record->'tuple'->>'resource_created_at'=$2 AND intent_record->>'policy_id'=$3 AND intent_record->>'generation'=$4 AND intent_record->>'fence'=$5`, original.Grant.ExpectedResourceID, original.Grant.ExpectedResourceCreatedAt, original.PolicyID.String(), fmt.Sprint(original.Generation), fmt.Sprint(original.FencingToken)).Scan(&id); err != nil {
		return ErrCapacityConflict
	}
	stored, err := loadGuestRetirementTx(ctx, tx, id)
	if err != nil {
		return err
	}
	proof, err := guestQuiescentProofTx(ctx, tx, stored)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_delete_bindings(destroy_grant_id,intent_id,eligibility_sha256,original_eligibility_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, original.Grant.GrantID, id, capacity.GuestRetirementSHA(proof), string(wire), now, wire)
	return err
}
