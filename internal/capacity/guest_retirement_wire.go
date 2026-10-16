package capacity

import (
	"crypto/sha256"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Core owns this provider-neutral wire consumer. Enrollment comes only from
// the original provisioning ledger; a caller cannot enroll its own VM by
// supplying a signed observation or an existing bootstrap reader binding.
func GuestRetirementEnrollment(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, e model.CapacityGuestRetirementEnrollment, now time.Time) error {
	refuse := fmt.Errorf("original complete Guest enrollment refused")
	if ValidateGuestRetirementBinding(p, &binding) != nil {
		return refuse
	}
	s := e.Statement
	known := false
	for _, approved := range binding.Members {
		known = known || approved == member
	}
	if !known || s.Schema != GuestRetirementSchema || s.Purpose != GuestRetirementPurpose || s.BindingName != member.Name || s.SourceClass != binding.EvidenceClass || s.ProvisionerSourceCommit != binding.ProvisionerSourceCommit || !ValidDigest(s.OriginalNativeResultSHA256) || !guestRetirementNativeTuple(p, binding, member, s.Tuple) || !GuestRetirementLifetime(s.Actor) || !GuestRetirementLifetime(s.Runtime) || s.Actor.BootID != s.Runtime.BootID || s.Actor.SourceCommit != binding.GuestSourceCommit || s.Actor.BinarySHA256 != binding.ProfileManifest.ActorBinarySHA256 || s.Runtime.SourceCommit != binding.ProfileManifest.OwnerSourceCommit || s.Runtime.BinarySHA256 != binding.ProfileManifest.OwnerBinarySHA256 || s.CoreAuthoritySourceCommit != binding.CoreAuthoritySourceCommit || s.RuntimeCommandSHA256 != binding.ProfileManifest.RuntimeClientCommandSHA256 || s.PoweroffCommandSHA256 != binding.ProfileManifest.PoweroffCommandSHA256 || len(s.Writers) != len(binding.ProfileManifest.Writers) || GuestRetirementSHA(s.Writers) != s.WriterRosterSHA256 || s.IssuedAt.IsZero() || s.IssuedAt.After(now) || !guestRetirementPublicKey(s.ObservationPublicKey) || !guestRetirementPublicKey(s.CoreIntentPublicKey) || s.ObservationPublicKey == s.CoreIntentPublicKey {
		return refuse
	}
	seenPID := map[int]bool{}
	for n, w := range s.Writers {
		approved := binding.ProfileManifest.Writers[n]
		if w.ID != approved.ID || !GuestRetirementLifetime(w.Lifetime) || seenPID[w.Lifetime.PID] || w.Lifetime.BootID != s.Actor.BootID || w.Lifetime.SourceCommit != approved.SourceCommit || w.Lifetime.BinarySHA256 != approved.BinarySHA256 {
			return refuse
		}
		seenPID[w.Lifetime.PID] = true
	}
	if !guestRetirementVerify(binding.EnrollmentIssuerPublicKey, e.Signature, s) {
		return refuse
	}
	return nil
}

func guestRetirementNativeTuple(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, tuple model.CapacityGuestNativeTuple) bool {
	b, err := VMObservationBinding(p, binding.MutationBindingName)
	if err != nil {
		return false
	}
	slot, err := vmApprovedSlot(b, member.Slot)
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	created, timeErr := time.Parse(time.RFC3339Nano, tuple.CreatedAt)
	return err == nil && provider != "" && tuple.Provider == provider && tuple.InstanceID == b.IntegrationInstanceID && tuple.InstanceChecksum == b.IntegrationChecksum && tuple.TypeID == b.IntegrationTypeID && tuple.TypeChecksum == b.IntegrationTypeChecksum && tuple.ScopeChecksum == b.ScopeChecksum && tuple.ProfileChecksum == slot.DesiredSpec.ProfileChecksum && tuple.Profile == b.ProfileName && tuple.Slot == member.Slot && guestText(tuple.ResourceID, 128) && timeErr == nil && !created.IsZero() && created.UTC().Format(time.RFC3339Nano) == tuple.CreatedAt
}

// Observe uses the original signed intent and nonce hash after restart/lost
// mint. It grants no Reserve, SDK send or refreshed deadline. Writes separately
// require the private nonce and still-live immutable original deadline.
func GuestRetirementRequest(r model.CapacityGuestRetirementRequest, e model.CapacityGuestRetirementEnrollment, now time.Time, write bool) error {
	i := r.Intent
	if i.Schema != GuestRetirementSchema || i.Purpose != GuestRetirementPurpose || i.BindingName != e.Statement.BindingName || i.Slot != i.Tuple.Slot || !guestUUID(i.RequestID) || !guestUUID(i.AttemptID) || !ValidDigest(i.NonceSHA256) || i.EnrollmentSHA256 != GuestRetirementSHA(e) || i.Tuple != e.Statement.Tuple || i.Actor != e.Statement.Actor || !guestUUID(i.PolicyID) || !ValidDigest(i.PolicyChecksum) || !guestUUID(i.WorkflowID) || !ValidDigest(i.WorkflowChecksum) || i.Generation == 0 || i.Generation > math.MaxInt64 || i.Fence == 0 || i.Fence > math.MaxInt64 || !guestUUID(i.LeaseOwner) || !guestUUID(i.WithdrawOperationID) || !ValidDigest(i.WithdrawRequestSHA256) || !guestUUID(i.DrainOperationID) || !ValidDigest(i.DrainRequestSHA256) || i.IssuedAt.IsZero() || i.IssuedAt.After(now) || i.OriginalDeadline.IsZero() || !i.OriginalDeadline.After(i.IssuedAt) || !guestRetirementVerify(e.Statement.CoreIntentPublicKey, r.Signature, i) {
		return fmt.Errorf("original signed Guest intent refused")
	}
	if r.Nonce != "" || write {
		sum := sha256.Sum256([]byte(r.Nonce))
		if !ValidDigest(r.Nonce) || fmt.Sprintf("%x", sum[:]) != i.NonceSHA256 {
			return fmt.Errorf("original private Guest nonce refused")
		}
	}
	if write && !now.Before(i.OriginalDeadline) {
		return fmt.Errorf("original Guest write deadline expired")
	}
	return nil
}

// Validate facts at the retained ORIGINAL recorded-at time. A recent GET may
// recover a late historical record but cannot move its old operation deadline.
func GuestRetirementRuntimeReturn(r model.CapacityGuestRetirementRuntimeReturn, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntent, originalRecordedAt time.Time) error {
	refuse := fmt.Errorf("original Guest runtime return refused")
	if r.Schema != GuestRetirementSchema || r.IntentSHA256 != GuestRetirementSHA(i) || r.AttemptID != i.AttemptID || r.Runtime != e.Statement.Runtime || r.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || r.WithdrawRequestSHA256 != i.WithdrawRequestSHA256 || r.DrainRequestSHA256 != i.DrainRequestSHA256 || r.UnknownWriters == nil || len(r.UnknownWriters) != 0 || len(r.Writers) != len(e.Statement.Writers) || r.ReturnedAt.IsZero() || r.ReturnedAt.After(originalRecordedAt) || !originalRecordedAt.Before(i.OriginalDeadline) {
		return refuse
	}
	if !guestRetirementOriginalOperation(r.Withdraw, i.WithdrawOperationID, i.WithdrawRequestSHA256, r.ReturnedAt) || !guestRetirementOriginalOperation(r.Drain, i.DrainOperationID, i.DrainRequestSHA256, r.ReturnedAt) || r.Drain.StartedAt.Before(r.Withdraw.OriginalReturnedAt) || !GuestRetirementProtectedCensus(r.CensusBefore, e, r.ReturnedAt, true) || !GuestRetirementProtectedCensus(r.CensusAfter, e, r.ReturnedAt, false) || r.CensusBefore.ObservedAt.After(r.Withdraw.StartedAt) || r.CensusAfter.ObservedAt.Before(r.Drain.OriginalReturnedAt) {
		return refuse
	}
	for n, w := range r.Writers {
		if !reflect.DeepEqual(w.Writer, e.Statement.Writers[n]) || w.Outcome != "joined" || !ValidDigest(w.OriginalResultSHA256) || w.AdmissionClosedAt.IsZero() || w.AdmissionClosedAt.After(r.CensusBefore.ObservedAt) || w.AdmissionClosedAt.After(r.Withdraw.StartedAt) || w.OriginalWithdrawReturnedAt.Before(r.Withdraw.StartedAt) || w.OriginalWithdrawReturnedAt.After(r.Withdraw.OriginalReturnedAt) || w.OriginalWorkersJoinedAt.Before(r.Drain.StartedAt) || w.OriginalConnectionsJoinedAt.Before(r.Drain.StartedAt) || w.OriginalWorkersJoinedAt.After(r.Drain.OriginalReturnedAt) || w.OriginalConnectionsJoinedAt.After(r.Drain.OriginalReturnedAt) {
			return refuse
		}
	}
	return nil
}

func guestRetirementOriginalOperation(o model.CapacityGuestRetirementOriginalOperation, id, requestSHA string, returned time.Time) bool {
	return o.OperationID == id && o.RequestSHA256 == requestSHA && ValidDigest(o.ResultSHA256) && !o.StartedAt.IsZero() && !o.OriginalReturnedAt.Before(o.StartedAt) && !o.OriginalReturnedAt.After(returned) && o.Outcome == "returned"
}
