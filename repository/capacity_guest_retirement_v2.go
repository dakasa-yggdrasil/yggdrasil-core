package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"reflect"
	"time"
)

const guestRetirementV2NonceKind = "production_clock_nonce_v2"

type GuestRetirementOriginalV2 struct {
	Preregistration model.CapacityGuestOriginalProvisioningPreregistration
	Binding         model.CapacityGuestRetirementBinding
	Member          model.CapacityGuestRetirementMemberBinding
	Receipt         model.CapacityGuestOriginalProvisioningReceipt
	Preflight       model.CapacityGuestRetirementRequestV2
	Request         model.CapacityGuestRetirementRequestV2
	RegistrationSHA string
	WitnessSHA      string
	ExecutorID      string
	RequestSHA256   string
}

// A real original nonce return is the first external journal row. Guest signed
// sequence1..4 and PreviousSHA stay untouched; DB indices alone are shifted+1.
type guestRetirementV2NonceReturn struct {
	Schema                     string                                 `json:"schema"`
	PreflightSHA256            string                                 `json:"preflight_sha256"`
	FinalRequest               model.CapacityGuestRetirementRequestV2 `json:"final_request"`
	FinalOriginalRequestSHA256 string                                 `json:"final_original_request_sha256"`
	Original                   capacity.GuestOriginalHTTPReturn       `json:"original_http_return"`
	OriginalOwnerElapsedNS     int64                                  `json:"original_owner_elapsed_ns"`
}

func (s CapacityStore) IssueGuestRetirementV2(original *capacity.GuestRetirementV2OriginalOwner, policy model.Manifest, generation, fence int64, owner, preregistrationID, nonce string, key ed25519.PrivateKey) (model.CapacityGuestRetirementRequestV2, error) {
	var result model.CapacityGuestRetirementRequestV2
	if original == nil {
		return result, ErrCapacityConflict
	}
	ctx := original.Context()
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		stored, err := loadGuestOriginalTx(ctx, tx, preregistrationID)
		origin := s.guestRetirementOrigin
		if err != nil || origin == nil || origin.source != capacity.CurrentGuestCoreSource() || !capacity.GuestBindingAuthorityCurrent(p, stored.binding) || origin.step.Use.Kind != "yggdrasil" || origin.step.Use.Operation != capacity.RetireOriginalGuestOperation || origin.step.TimeoutSeconds < 1 || origin.step.TimeoutSeconds > 86400 || origin.step.Retry.MaxAttempts > 1 || origin.step.ForEach != nil || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding) || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.WorkflowID != s.WorkflowID.String() || !capacityIntentReduction(current) || (current.Phase != "draining" && current.Phase != "drained") {
			return ErrCapacityConflict
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preregistrationID)
		if err != nil || capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, receipt.Enrollment, receipt.Enrollment.Statement.IssuedAt) != nil || (receipt.Enrollment.Statement.Tuple.Provider != "aws" && receipt.Enrollment.Statement.Tuple.Provider != "hetzner") || !capacity.GuestOriginalProfileEnabled(p, stored.binding, receipt.Enrollment.Statement.Tuple.Provider) || p.GuestNotifyCanaryBinding == nil || !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) || !capacity.ValidDigest(nonce) {
			return ErrCapacityConflict
		}
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || current.LeaseExpiresAt == nil {
			return ErrCapacityLease
		}
		contextDeadline := deadline
		sampleStarted := time.Now()
		var leaseNow time.Time
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&leaseNow); err != nil {
			return err
		}
		issued := time.Now()
		budget := min(30*time.Second, contextDeadline.Sub(issued), current.LeaseExpiresAt.Sub(leaseNow)-issued.Sub(sampleStarted))
		if budget <= 0 {
			return ErrCapacityLease
		}
		deadline = issued.Add(budget).UTC()
		issued = issued.UTC()

		b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
		if err != nil || checkMutationIntegration(ctx, tx, b) != nil || s.guestRetirementFloorTx(ctx, tx, policy.Metadata.Namespace, p, current, b, stored.pre.Slot, now) != nil {
			return ErrCapacityConflict
		}
		if s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, stored.pre.Slot, now, "before_retirement_floor", "") != nil {
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
		base := model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementV2IntentSchema, Purpose: capacity.GuestRetirementV2Purpose, BindingName: stored.member.Name, Slot: stored.pre.Slot, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), NonceSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), Tuple: receipt.Enrollment.Statement.Tuple, Actor: receipt.Enrollment.Statement.Actor, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String(), WorkflowChecksum: workflowChecksum, Generation: uint64(generation), Fence: uint64(fence), LeaseOwner: owner, WithdrawOperationID: uuid.NewString(), DrainOperationID: uuid.NewString(), OriginalDeadline: deadline, IssuedAt: issued}
		intent := model.CapacityGuestRetirementIntentV2{CapacityGuestRetirementIntent: base, PreregistrationID: preregistrationID, ProfileManifestSHA256: stored.binding.ProfileManifestSHA256, CoreSourceCommit: stored.binding.CoreAuthoritySourceCommit, Runtime: receipt.Enrollment.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), receipt.Enrollment.Statement.Writers...), WriterRosterSHA256: receipt.Enrollment.Statement.WriterRosterSHA256}
		// These source-generated semantic request identities are carried into
		// the exact original writer control frames and owning return records.
		intent.WithdrawRequestSHA256 = capacity.GuestRetirementSHA([]string{"original_guest_withdraw_v1", intent.RequestID, intent.WithdrawOperationID, intent.EnrollmentSHA256, receipt.Enrollment.Statement.WriterRosterSHA256})
		intent.DrainRequestSHA256 = capacity.GuestRetirementSHA([]string{"original_guest_drain_v1", intent.RequestID, intent.DrainOperationID, intent.EnrollmentSHA256, receipt.Enrollment.Statement.WriterRosterSHA256})
		result = model.CapacityGuestRetirementRequestV2{Intent: intent, Nonce: nonce}
		result.Signature, err = capacity.GuestLifecycleSignature(key, intent)
		if err != nil || capacity.ValidateGuestRetirementV2Preflight(result, receipt.Enrollment, time.Now().UTC()) != nil {
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
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at,original_wire) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, intent.RequestID, preregistrationID, intent.AttemptID, intent.NonceSHA256, capacity.GuestRetirementSHA(intent), intentWire, deadline, issued, wire)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_retirement_contexts(intent_id,executor_id,original_step_id,original_step_timeout_seconds,original_context_deadline,core_actual_source_commit,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, intent.RequestID, s.ExecutorID, origin.step.ID, origin.step.TimeoutSeconds, contextDeadline, origin.source, issued)
		}
		if err == nil {
			err = s.recordGuestAuthorityIssueTx(ctx, tx, policy, p, stored.binding, "retirement_intent", intent.RequestID, capacity.GuestRetirementSHA(intent))
		}
		return err
	})
	return result, err
}

func loadGuestRetirementV2Tx(ctx context.Context, tx *sql.Tx, id string, finalized bool) (GuestRetirementOriginalV2, error) {
	var out GuestRetirementOriginalV2
	if !validCapacityExecutor(id) {
		return out, ErrCapacityMutationAuthorization
	}
	var preID, digest string
	var wire []byte
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT preregistration_id::text,original_wire,intent_sha256,intent_record=convert_from(original_wire,'UTF8')::jsonb->'intent' AND original_deadline=(intent_record->>'original_deadline')::timestamptz AND created_at=(intent_record->>'issued_at')::timestamptz AND id::text=intent_record->>'request_id' AND attempt_id::text=intent_record->>'attempt_id' AND nonce_sha256=intent_record->>'nonce_sha256' FROM public.capacity_vm_retirement_intents WHERE id=$1 FOR SHARE`, id).Scan(&preID, &wire, &digest, &consistent)
	if err != nil {
		return out, err
	}
	if !consistent || capacity.DecodeGuestLifecycle(wire, &out.Preflight) != nil || out.Preflight.Nonce != "" || capacity.GuestRetirementSHA(out.Preflight.Intent) != digest || out.Preflight.Intent.Schema != capacity.GuestRetirementV2IntentSchema || out.Preflight.Intent.PreregistrationID != preID {
		return out, ErrCapacityConflict
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return out, err
	}
	out.Preregistration, out.Binding, out.Member = stored.pre, stored.binding, stored.member
	out.WitnessSHA = capacity.GuestRetirementSHA(stored.witness)
	out.Receipt, out.RegistrationSHA, err = loadGuestReceiptTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	if _, err = loadGuestInstallationTx(ctx, tx, stored, out.Receipt); err != nil {
		return out, err
	}
	if !capacity.GuestRetirementV2PreflightContent(out.Preflight, out.Receipt.Enrollment) || out.Preflight.Intent.ProfileManifestSHA256 != out.Binding.ProfileManifestSHA256 || out.Preflight.Intent.CoreSourceCommit != out.Binding.CoreAuthoritySourceCommit {
		return out, ErrCapacityConflict
	}
	var source string
	if err = tx.QueryRowContext(ctx, `SELECT executor_id::text,core_actual_source_commit FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, id).Scan(&out.ExecutorID, &source); err != nil || verifyGuestAuthorityIssuerTx(ctx, tx, "retirement_intent", id, source, out.Binding) != nil {
		return out, ErrCapacityConflict
	}
	out.Request = out.Preflight
	if !finalized {
		return out, nil
	}
	var kind, previous, returnSHA string
	if err = tx.QueryRowContext(ctx, `SELECT kind,previous_sha256,return_sha256,original_wire,original_return_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 AND sequence=1`, id).Scan(&kind, &previous, &returnSHA, &wire, &consistent); err != nil {
		return out, err
	}
	var nonce guestRetirementV2NonceReturn
	if !consistent || kind != guestRetirementV2NonceKind || previous != "" || capacity.DecodeGuestLifecycle(wire, &nonce) != nil || capacity.GuestRetirementSHA(nonce) != returnSHA || !guestRetirementV2NonceJoin(nonce, out) {
		return out, ErrCapacityConflict
	}
	out.Request = nonce.FinalRequest
	out.RequestSHA256 = nonce.FinalOriginalRequestSHA256
	return out, nil
}

func guestRetirementV2NonceJoin(n guestRetirementV2NonceReturn, s GuestRetirementOriginalV2) bool {
	i := n.FinalRequest.Intent
	if n.Schema != "original_core_guest_retirement_nonce_return_v2" || n.FinalRequest.Nonce != "" || !capacity.ValidDigest(n.FinalOriginalRequestSHA256) || n.PreflightSHA256 != capacity.GuestRetirementSHA(s.Preflight.Intent) || capacity.GuestRetirementV2PreflightSHA(i) != n.PreflightSHA256 || n.OriginalOwnerElapsedNS <= 0 || n.OriginalOwnerElapsedNS > int64(30*time.Second) || i.GuestNonce.IssuedMonotonicNS <= 0 || i.GuestNonce.ExpiresMonotonicNS <= i.GuestNonce.IssuedMonotonicNS || n.OriginalOwnerElapsedNS >= i.GuestNonce.ExpiresMonotonicNS-i.GuestNonce.IssuedMonotonicNS || i.GuestExpiresMonotonicNS != i.GuestNonce.ExpiresMonotonicNS-n.OriginalOwnerElapsedNS || capacity.ValidateGuestRetirementV2Request(n.FinalRequest, s.Receipt.Enrollment, i.IssuedAt, false) != nil || n.Original.StartedAt.Before(i.IssuedAt) || !n.Original.DriverReturnedAt.Before(i.OriginalDeadline) {
		return false
	}
	var observed model.CapacityGuestRetirementNonceV2
	return capacity.GuestOriginalHTTPDecode(n.Original, &observed) == nil && reflect.DeepEqual(observed, i.GuestNonce)
}

func (s CapacityStore) guestRetirementV2Transaction(ctx context.Context, id string, finalized bool, fn func(*sql.Tx, GuestRetirementOriginalV2, time.Time) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ns, env, domain, dimension string
	if err = tx.QueryRowContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE r.id=$1`, id).Scan(&ns, &env, &domain, &dimension); err != nil {
		return err
	}
	if err = lockMutationScope(ctx, tx, ns, model.CapacityPolicySpec{Environment: env, Domain: domain, Dimension: dimension}); err != nil {
		return err
	}
	stored, err := loadGuestRetirementV2Tx(ctx, tx, id, finalized)
	if err != nil {
		return err
	}
	var nowPG time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&nowPG); err != nil {
		return err
	}
	if err = fn(tx, stored, nowPG.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s CapacityStore) FinalizeGuestRetirementV2Nonce(original *capacity.GuestRetirementV2OriginalOwner) error {
	request, returned, elapsed, err := original.NonceExchange()
	if err != nil {
		return err
	}
	return s.guestRetirementV2Transaction(original.Context(), request.Intent.RequestID, false, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		if stored.ExecutorID != s.ExecutorID || capacity.ValidateGuestRetirementV2Request(request, stored.Receipt.Enrollment, time.Now().UTC(), true) != nil {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementV2CurrentTx(original.Context(), tx, stored, nowPG, true); err != nil {
			return err
		}
		fullSHA := capacity.GuestRetirementSHA(request)
		request.Nonce = ""
		record := guestRetirementV2NonceReturn{Schema: "original_core_guest_retirement_nonce_return_v2", PreflightSHA256: capacity.GuestRetirementSHA(stored.Preflight.Intent), FinalRequest: request, FinalOriginalRequestSHA256: fullSHA, Original: returned, OriginalOwnerElapsedNS: int64(elapsed)}
		if !guestRetirementV2NonceJoin(record, stored) {
			return ErrCapacityConflict
		}
		wire, err := json.Marshal(record)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(original.Context(), `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,1,$2,'',$3,$4::jsonb,$5,$6)`, request.Intent.RequestID, guestRetirementV2NonceKind, capacity.GuestRetirementSHA(record), string(wire), nowPG, wire)
		return err
	})
}

func (s CapacityStore) guestRetirementV2CurrentTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2, now time.Time, liveOriginal bool) (model.Manifest, model.CapacityPolicySpec, model.CapacityIntent, error) {
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
	if err != nil || !active || policy.Checksum != i.PolicyChecksum || stored.Binding.EvidenceClass != "owned_provisioner_original" || !capacity.GuestOriginalProfileEnabled(p, stored.Binding, i.Tuple.Provider) || p.GuestNotifyCanaryBinding == nil || !capacity.GuestBindingAuthorityCurrent(p, stored.Binding) || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.Binding) || (liveOriginal && !time.Now().Before(i.OriginalDeadline)) {
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
	if s.guestNotifyRetirementFloorTx(ctx, tx, policy, p, current, i.Slot, now, "", "") != nil {
		return policy, p, current, ErrCapacityConflict
	}
	return policy, p, current, nil
}
