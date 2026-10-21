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

type guestNotifyUsefulMemberProof struct {
	business           model.CapacityGuestNotifyBusinessObservation
	recordedPG         time.Time
	nativeSlotObserved time.Time
}

// Revalidate the complete authenticated original, not its cached derived JSON.
// Freshness is the authenticated original five-second creation window plus
// Core PG ledger age. No later GET promotes an old native creation.
func loadFreshGuestNotifyBusinessTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, preID string, receipt model.CapacityGuestOriginalProvisioningReceipt, now time.Time, usage string, afterPG time.Time) (guestNotifyUsefulMemberProof, error) {
	var empty guestNotifyUsefulMemberProof
	var id, executor string
	var issuedPG time.Time
	if err := tx.QueryRowContext(ctx, `SELECT c.id::text,c.executor_id,c.recorded_at FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.preregistration_id=$1 AND c.phase='read' AND r.outcome='accepted' AND c.policy_id=$2 AND c.generation=$3 AND c.fence=$4 AND ($5='' OR c.lease_owner=$5) AND ($6='' OR c.original_record->>'usage_class'=$6) ORDER BY r.recorded_at DESC,c.id DESC LIMIT 1`, preID, policy.ID, current.Generation, current.FencingToken, current.LeaseOwner, usage).Scan(&id, &executor, &issuedPG); err != nil {
		return empty, err
	}
	c, err := loadGuestNotifyChallengeTx(ctx, tx, id)
	if err != nil || c.PreregistrationID != preID || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || c.Tuple != receipt.Enrollment.Statement.Tuple || c.CoreSourceCommit != capacity.CurrentGuestCoreSource() || !afterPG.IsZero() && !issuedPG.After(afterPG) || usage != "" && c.UsageClass != usage || current.LeaseOwner == "" && (!guestNotifyStableEpoch(current) || c.UsageClass != "steady_useful_membership" || c.LeaseOwner != GuestNotifyMaintenanceOwner(executor)) {
		return empty, ErrCapacityConflict
	}
	var wire, transport []byte
	var digest string
	var recorded time.Time
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,original_transport,return_sha256,recorded_at FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=$1 AND outcome='accepted'`, id).Scan(&wire, &transport, &digest, &recorded); err != nil {
		return empty, err
	}
	var returned capacity.GuestOriginalHTTPReturn
	var reply model.CapacityGuestNotifyCanaryRead
	if json.Unmarshal(transport, &returned) != nil || capacity.BusinessCreationSHA256(wire) != digest || !guestNotifyHTTPWithin(c, returned) {
		return empty, ErrCapacityConflict
	}
	returned.Body = wire
	if capacity.GuestOriginalHTTPDecode(returned, &reply) != nil || capacity.ValidateGuestNotifyCanaryEnvelope(c, receipt.Enrollment, reply, returned.DriverReturnedAt) != nil {
		return empty, ErrCapacityConflict
	}
	publication, pubChallenge, err := loadGuestNotifyPublicationTx(ctx, tx, c, receipt.Enrollment, p)
	if err != nil {
		return empty, err
	}
	business, err := capacity.JoinGuestNotifyBusiness(p, c, receipt.Enrollment, reply, publication, pubChallenge, returned.DriverReturnedAt)
	if err != nil {
		return empty, ErrCapacityConflict
	}
	return guestNotifyUsefulMemberProof{business: business, recordedPG: recorded}, nil
}

func guestNotifyMemberReceiptTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, member model.CapacityGuestRetirementMemberBinding, slot capacityResourceSlot) (model.CapacityGuestOriginalProvisioningReceipt, error) {
	var empty model.CapacityGuestOriginalProvisioningReceipt
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT e.preregistration_id::text FROM public.capacity_vm_original_enrollments e JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=e.preregistration_id WHERE p.preregistration_record->>'policy_id'=$1 AND p.preregistration_record->>'policy_checksum'=$2 AND (p.preregistration_record->>'slot')::integer=$3 AND e.enrollment_record->'statement'->'tuple'->>'resource_id'=$4 AND e.enrollment_record->'statement'->'tuple'->>'resource_created_at'=$5`, policy.ID.String(), policy.Checksum, member.Slot, slot.ResourceID, slot.ResourceCreatedAt).Scan(&id); err != nil {
		return empty, err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, id)
	if err != nil || p.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) || stored.member != member || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() {
		return empty, ErrCapacityConflict
	}
	receipt, _, err := loadGuestReceiptTx(ctx, tx, id)
	if err != nil {
		return empty, err
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return empty, err
	}
	if _, err = loadGuestInstallationTx(ctx, tx, stored, receipt); err != nil {
		return empty, err
	}
	if receipt.Enrollment.Statement.Tuple != stored.witness.Tuple || receipt.Enrollment.Statement.Tuple.ResourceID != slot.ResourceID || receipt.Enrollment.Statement.Tuple.CreatedAt != slot.ResourceCreatedAt || capacity.GuestRetirementEnrollment(p, stored.binding, member, receipt.Enrollment, receipt.Enrollment.Statement.IssuedAt) != nil {
		return empty, ErrCapacityConflict
	}
	return receipt, nil
}

// The independent existing native slot floor is preserved by callers. This
// counts ONLY surviving physical members with a fresh same-original useful
// business creation, excluding the target and every other pending destroy.
func (s CapacityStore) guestNotifyUsefulMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, excludedSlot int, now time.Time, usage string, afterPG time.Time) (int, error) {
	if p.GuestNotifyCanaryBinding == nil || capacity.ValidateGuestNotifyCanaryBinding(p) != nil || p.GuestRetirementBinding == nil {
		return 0, ErrCapacityConflict
	}
	r := *p.GuestRetirementBinding
	b, err := capacity.VMObservationBinding(p, r.MutationBindingName)
	if err != nil || checkMutationIntegration(ctx, tx, b) != nil {
		return 0, ErrCapacityConflict
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	if !capacity.GuestOriginalProfileEnabled(p, r, provider) {
		return 0, ErrCapacityConflict
	}
	proofs := []guestNotifyUsefulMemberProof{}
	for _, member := range r.Members {
		if member.Slot == excludedSlot {
			continue
		}
		slot, exists, e := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot)
		if e != nil {
			return 0, e
		}
		if !exists || slot.Tombstone || slot.ResourceID == "" {
			continue
		}

		var pending int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT(grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=$5 AND state IN ('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, member.Slot, b.DestroyCapability).Scan(&pending); e != nil {
			return 0, e
		}
		if pending != 0 {
			continue
		}
		receipt, e := guestNotifyMemberReceiptTx(ctx, tx, policy, p, member, slot)
		if e != nil {
			return 0, e
		}
		proof, e := loadFreshGuestNotifyBusinessTx(ctx, tx, policy, p, current, receipt.PreregistrationID, receipt, now, usage, afterPG)
		if e != nil {
			return 0, e
		}
		proof.nativeSlotObserved = slot.ObservedAt
		proofs = append(proofs, proof)
	}
	var freshPG time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&freshPG); err != nil {
		return 0, err
	}
	for _, proof := range proofs {
		if !capacity.Fresh(proof.nativeSlotObserved, freshPG, p.MaxEvidenceAgeSeconds) || !capacity.GuestNotifyBusinessStillFresh(proof.business, proof.recordedPG, freshPG, p.MaxEvidenceAgeSeconds) {
			return 0, ErrCapacityConflict
		}
	}
	return len(proofs), nil
}
