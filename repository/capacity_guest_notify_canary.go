package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestNotifyCanaryOperation = "capacity.qualify_original_guest_notify"

func (s CapacityStore) WithOriginalGuestNotifyCanary(step model.WorkflowStepSpec, source string) CapacityStore {
	s.guestNotifyOrigin = &guestOriginalProvisioningContext{step: step, source: source}
	return s
}

// No transaction performs provider/broker/Guest I/O. The existing active
// policy/workflow/source/profile/lease and installed ORIGINAL enrollment must
// independently authorize each actual signed one-use challenge.
func (s CapacityStore) guestNotifyStoredTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, preID string) (guestOriginalStored, model.CapacityGuestOriginalProvisioningReceipt, error) {
	var empty model.CapacityGuestOriginalProvisioningReceipt
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return stored, empty, err
	}
	origin := s.guestNotifyOrigin
	reconcile := origin != nil && origin.step.Use.Operation == capacity.CompleteOriginalGuestOperation && s.guestReconcile != nil && reflect.DeepEqual(origin.step, s.guestReconcile.step) && s.guestReconcileSourceTx(ctx, tx, policy, p) == nil
	if origin == nil || origin.source != capacity.CurrentGuestCoreSource() || !capacity.GuestBindingAuthorityCurrent(p, stored.binding) || origin.step.Use.Kind != "yggdrasil" || (!reconcile && origin.step.Use.Operation != GuestNotifyCanaryOperation && origin.step.Use.Operation != GuestNotifyMaintenanceOperation && origin.step.Use.Operation != capacity.RetireOriginalGuestOperation && origin.step.Use.Operation != "capacity.finish_original_guest_retirement") || origin.step.TimeoutSeconds < 1 || origin.step.TimeoutSeconds > 86400 || origin.step.Retry.MaxAttempts > 1 || origin.step.ForEach != nil || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.WorkflowID != s.WorkflowID.String() || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding) || p.GuestNotifyCanaryBinding == nil || capacity.ValidateGuestNotifyCanaryBinding(p) != nil {
		return stored, empty, ErrCapacityConflict
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return stored, empty, err
	}
	provider := stored.witness.Tuple.Provider
	if provider != "aws" && provider != "hetzner" || !capacity.GuestOriginalProfileEnabled(p, stored.binding, provider) {
		return stored, empty, ErrCapacityConflict
	}
	var raw []byte
	var checksum string
	if err = tx.QueryRowContext(ctx, `SELECT spec,checksum FROM public.manifests WHERE id=$1 AND kind='workflow' AND active FOR SHARE`, s.WorkflowID).Scan(&raw, &checksum); err != nil {
		return stored, empty, err
	}
	workflow, err := manifest.ParseWorkflowSpec(raw)
	matched := false
	if err == nil && workflow.Authorization != nil {
		for _, step := range workflow.Steps {
			matched = matched || reflect.DeepEqual(step, origin.step)
		}
	}
	if !matched || checksum != stored.pre.WorkflowChecksum {
		return stored, empty, ErrCapacityConflict
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
	if err != nil {
		return stored, empty, err
	}
	if _, err = loadGuestInstallationTx(ctx, tx, stored, receipt); err != nil {
		return stored, empty, err
	}
	// The installed immutable enrollment is historical signed content. Its
	// original admission was checked independently; today's nonce and original
	// transport, rather than an inter-machine timestamp, own this read's age.
	if !guestNotifyHistoricalEnrollmentMatches(p, stored, receipt) {
		return stored, empty, ErrCapacityConflict
	}
	b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
	if err != nil {
		return stored, empty, err
	}
	if checkMutationIntegration(ctx, tx, b) != nil {
		return stored, empty, ErrCapacityConflict
	}
	slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, stored.member.Slot)
	if err != nil || !exists || slot.Tombstone || slot.ResourceID != stored.witness.Tuple.ResourceID || slot.ResourceCreatedAt != stored.witness.Tuple.CreatedAt {
		return stored, empty, ErrCapacityConflict
	}
	return stored, receipt, nil
}

// Historical signed enrollment is bound to its immutable protocol authority.
// The private current issuer build is checked independently above; changing
// that issuer must never require rewriting the installed signed enrollment.
func guestNotifyHistoricalEnrollmentMatches(p model.CapacityPolicySpec, stored guestOriginalStored, receipt model.CapacityGuestOriginalProvisioningReceipt) bool {
	return receipt.Enrollment.Statement.Tuple == stored.witness.Tuple && receipt.Enrollment.Statement.CoreAuthoritySourceCommit == stored.binding.CoreAuthoritySourceCommit && capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, receipt.Enrollment, receipt.Enrollment.Statement.IssuedAt) == nil
}

func (s CapacityStore) IssueGuestNotifyCanaryPublication(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID, usage string, key ed25519.PrivateKey) (model.CapacityGuestNotifyCanaryChallenge, error) {
	return s.issueGuestNotifyCanary(ctx, policy, generation, fence, owner, preID, usage, "", key)
}
func (s CapacityStore) IssueGuestNotifyCanaryRead(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID, usage, recordChallengeID string, key ed25519.PrivateKey) (model.CapacityGuestNotifyCanaryChallenge, error) {
	if !validCapacityExecutor(recordChallengeID) {
		return model.CapacityGuestNotifyCanaryChallenge{}, ErrCapacityConflict
	}
	return s.issueGuestNotifyCanary(ctx, policy, generation, fence, owner, preID, usage, recordChallengeID, key)
}
func (s CapacityStore) issueGuestNotifyCanary(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID, usage, recordID string, key ed25519.PrivateKey) (model.CapacityGuestNotifyCanaryChallenge, error) {
	var result model.CapacityGuestNotifyCanaryChallenge
	err := s.guestNotifyTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		maintenance := s.guestNotifyMaintenanceOrigin()
		if s.guestNotifyOrigin == nil || current.RecoveryOnly || !capacity.GuestNotifyCanaryUsage(usage) || (usage == "steady_useful_membership") != maintenance || !maintenance && !capacityProfileCurrent(p, current.Decision, now) {
			return ErrCapacityConflict
		}
		stored, receipt, err := s.guestNotifyStoredTx(ctx, tx, policy, p, preID)
		if err != nil {
			return err
		}
		if !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) {
			return ErrCapacityConflict
		}
		limit, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || current.LeaseExpiresAt == nil && !maintenance {
			return ErrCapacityConflict
		}
		id := uuid.NewString()
		if current.InstalledGuestReconcile != nil {
			for _, prior := range current.InstalledGuestReconcile.PreviousCanaries {
				if prior.ChallengeID == id {
					return ErrCapacityConflict
				}
			}
		}
		var parent model.CapacityGuestNotifyCanaryChallenge
		phase, schema, purpose := "read", capacity.GuestNotifyCanaryChallengeSchema, capacity.GuestNotifyCanaryReadPurpose
		if recordID == "" {
			phase, schema, purpose = "publish", capacity.GuestNotifyCanaryPublicationChallengeSchema, capacity.GuestNotifyCanaryPublicationPurpose
			recordID = id
			var count int
			var latest sql.NullTime
			if err = tx.QueryRowContext(ctx, `SELECT count(*),max(recorded_at) FROM public.capacity_guest_notify_canary_challenges WHERE preregistration_id=$1 AND phase='publish' AND recorded_at>$2`, preID, now.Add(-time.Hour)).Scan(&count, &latest); err != nil {
				return err
			}
			if count >= p.GuestNotifyCanaryBinding.MaximumPublicationsPerHour || latest.Valid && now.Sub(latest.Time) < time.Duration(p.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds)*time.Second {
				return ErrCapacityConflict
			}
		} else {
			var parentWire []byte
			var parentExecutor string
			if err = tx.QueryRowContext(ctx, `SELECT c.original_wire,c.executor_id FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.id=$1 AND c.preregistration_id=$2 AND c.phase='publish' AND r.outcome='accepted'`, recordID, preID).Scan(&parentWire, &parentExecutor); err != nil {
				return err
			}
			if parentExecutor != s.ExecutorID || capacity.DecodeGuestLifecycle(parentWire, &parent) != nil || !capacity.GuestNotifyCanaryPublication(parent) || parent.PolicyID != policy.ID.String() || parent.PolicyChecksum != policy.Checksum || parent.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || parent.Tuple != receipt.Enrollment.Statement.Tuple {
				return ErrCapacityConflict
			}
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		// PG owns its lease clock; the caller owns its original Core context.
		// Exchange remaining durations only. Subtract the WHOLE native sample
		// round trip, conservatively including either network direction.
		sampleStarted := time.Now()
		var leaseNow time.Time
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&leaseNow); err != nil {
			return err
		}
		issued := time.Now()
		budget := min(5*time.Second, limit.Sub(issued))
		if parent.ChallengeID != "" {
			budget = min(budget, parent.OriginalDeadline.Sub(issued))
		}
		if current.LeaseExpiresAt != nil {
			budget = min(budget, current.LeaseExpiresAt.Sub(leaseNow)-issued.Sub(sampleStarted))
		}
		deadline := originalGuestCanarySerializedDeadline(issued, budget, limit)
		issued = issued.UTC()
		if budget <= 0 {
			return ErrCapacityConflict
		}
		result = model.CapacityGuestNotifyCanaryChallenge{Schema: schema, Purpose: purpose, ChallengeID: id, NonceSHA256: hex.EncodeToString(nonce[:]), UsageClass: usage, RecordChallengeID: recordID, BindingName: stored.member.Name, Slot: stored.member.Slot, PreregistrationID: preID, PreregistrationNonceSHA256: stored.pre.NonceSHA256, OriginalRegistrationSHA256: receipt.OriginalProvisioningSHA256, OriginalCreateWitnessSHA256: capacity.GuestRetirementSHA(stored.witness), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), ProfileManifestSHA256: stored.binding.ProfileManifestSHA256, Tuple: receipt.Enrollment.Statement.Tuple, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String(), WorkflowChecksum: stored.pre.WorkflowChecksum, Generation: uint64(generation), Fence: uint64(fence), LeaseOwner: owner, CoreSourceCommit: stored.binding.CoreAuthoritySourceCommit, IssuedAt: issued, OriginalDeadline: deadline}
		result.Signature, err = capacity.GuestLifecycleSignature(key, result)
		if err != nil || (parent.ChallengeID != "" && !capacity.GuestNotifyCausalPair(parent, result)) || capacity.ValidateGuestNotifyCanaryPreflight(result, receipt.Enrollment, time.Now().UTC()) != nil {
			return ErrCapacityConflict
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)`, id, preID, recordID, phase, policy.ID, s.WorkflowID, generation, fence, s.ExecutorID, owner, capacity.GuestRetirementSHA(result), result.NonceSHA256, wire, string(wire), deadline, now)
		if err == nil {
			err = s.recordGuestAuthorityIssueTx(ctx, tx, policy, p, stored.binding, "canary_challenge", id, capacity.GuestRetirementSHA(result))
		}
		return err
	})
	return result, err
}

func loadGuestNotifyPreflightTx(ctx context.Context, tx *sql.Tx, id string) (model.CapacityGuestNotifyCanaryChallenge, error) {
	var result model.CapacityGuestNotifyCanaryChallenge
	var wire []byte
	var digest string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,challenge_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb AND id::text=original_record->>'challenge_id' AND preregistration_id::text=original_record->>'preregistration_id' AND record_challenge_id::text=original_record->>'record_challenge_id' AND policy_id::text=original_record->>'policy_id' AND workflow_id::text=original_record->>'workflow_id' AND generation=(original_record->>'generation')::bigint AND fence=(original_record->>'fence')::bigint AND lease_owner=original_record->>'lease_owner' AND nonce_sha256=original_record->>'nonce_sha256' FROM public.capacity_guest_notify_canary_challenges WHERE id=$1`, id).Scan(&wire, &digest, &consistent)
	if err != nil {
		return result, err
	}
	if !consistent || capacity.DecodeGuestLifecycle(wire, &result) != nil || capacity.GuestRetirementSHA(result) != digest {
		return result, ErrCapacityConflict
	}
	return result, nil
}

// The immutable possible-send record is committed before the one actual HTTP
// call. A duplicate request refuses; it never returns another permission.
func (s CapacityStore) ReserveGuestNotifyCanarySend(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, c model.CapacityGuestNotifyCanaryChallenge) error {
	return s.guestNotifyTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		stored, receipt, err := s.guestNotifyStoredTx(ctx, tx, policy, p, c.PreregistrationID)
		if err != nil {
			return err
		}
		_ = stored
		original, err := loadGuestNotifyChallengeTx(ctx, tx, c.ChallengeID)
		if err != nil || !reflect.DeepEqual(original, c) || c.Generation != uint64(generation) || c.Fence != uint64(fence) || c.LeaseOwner != owner || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || c.WorkflowID != s.WorkflowID.String() || current.RecoveryOnly || capacity.ValidateGuestNotifyCanaryChallenge(c, receipt.Enrollment, time.Now().UTC()) != nil {
			return ErrCapacityConflict
		}
		body, err := json.Marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: c})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at)VALUES($1,$2,$3,$4,$5)`, c.ChallengeID, capacity.BusinessCreationSHA256(body), time.Now().UTC(), c.OriginalDeadline, now)
		return err
	})
}

// Keep the signed deadline inside BOTH conservative duration budgets and the
// original context wall deadline. time.Now's realtime/monotonic samples may
// differ by nanoseconds across reads; stripping monotonic state can otherwise
// put an equal-duration UTC projection after its original parent deadline.
func originalGuestCanarySerializedDeadline(issued time.Time, budget time.Duration, originalLimit time.Time) time.Time {
	deadline := issued.Add(budget).UTC()
	limit := originalLimit.UTC()
	if deadline.After(limit) {
		deadline = limit
	}
	return deadline
}
