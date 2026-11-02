package capacity

import (
	"crypto/sha256"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"math"
	"reflect"
	"time"
)

const GuestRetirementV2IntentSchema = "original_guest_production_retirement_intent_v2"
const GuestRetirementV2Purpose = "original_production_guest_retirement"
const GuestRetirementV2NonceSchema = "original_guest_production_retirement_nonce_v2"
const GuestRetirementV2ClockSchema = "original_guest_production_retirement_clock_v2"
const GuestRetirementV2RuntimeSchema = "original_guest_production_retirement_runtime_return_v2"
const GuestRetirementV2RecordSchema = "original_guest_production_retirement_record_v2"
const GuestRetirementV2ObservationSchema = "original_guest_production_retirement_observation_v2"
const GuestRetirementV2AuthoritySchema = "original_guest_production_retirement_authority_v2"

func GuestRetirementV2PreflightSHA(i model.CapacityGuestRetirementIntentV2) string {
	i.GuestNonce = model.CapacityGuestRetirementNonceV2{}
	i.GuestExpiresMonotonicNS = 0
	return GuestRetirementSHA(i)
}

// Historical signature/content validation only; it grants no live write.
func GuestRetirementV2PreflightContent(r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment) bool {
	return r.Intent.GuestNonce == (model.CapacityGuestRetirementNonceV2{}) && r.Intent.GuestExpiresMonotonicNS == 0 && validateGuestRetirementV2Base(r, e, r.Intent.IssuedAt, false) == nil
}

func ValidateGuestRetirementV2Preflight(r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment, nowCore time.Time) error {
	if r.Intent.GuestNonce != (model.CapacityGuestRetirementNonceV2{}) || r.Intent.GuestExpiresMonotonicNS != 0 {
		return fmt.Errorf("empty original local Guest retirement nonce required")
	}
	return validateGuestRetirementV2Base(r, e, nowCore, true)
}

func ValidateGuestRetirementV2Nonce(i model.CapacityGuestRetirementIntentV2, e model.CapacityGuestRetirementEnrollment) error {
	n := i.GuestNonce
	signature := n.Signature
	n.Signature = ""
	duration := i.OriginalDeadline.Sub(i.IssuedAt)
	if n.Schema != GuestRetirementV2NonceSchema || n.RequestID != i.RequestID || n.AttemptID != i.AttemptID || n.PreflightSHA256 != GuestRetirementV2PreflightSHA(i) || n.EnrollmentSHA256 != i.EnrollmentSHA256 || n.Actor != e.Statement.Actor || n.Runtime != e.Statement.Runtime || n.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || !ValidDigest(n.NonceSHA256) || n.IssuedMonotonicNS <= 0 || n.ExpiresMonotonicNS <= n.IssuedMonotonicNS || duration <= 0 || duration > 30*time.Second || n.ExpiresMonotonicNS-n.IssuedMonotonicNS != int64(duration) || i.GuestExpiresMonotonicNS <= n.IssuedMonotonicNS || i.GuestExpiresMonotonicNS > n.ExpiresMonotonicNS || !guestRetirementVerify(e.Statement.ObservationPublicKey, signature, n) {
		return fmt.Errorf("authentic original local Guest retirement nonce required")
	}
	return nil
}

// Core wall time is checked only on Core. Guest verifies signed content and its
// own kernel expiry independently; neither a GET nor a retained result renews it.
func ValidateGuestRetirementV2Request(r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment, nowCore time.Time, write bool) error {
	if err := validateGuestRetirementV2Base(r, e, nowCore, write); err != nil {
		return err
	}
	return ValidateGuestRetirementV2Nonce(r.Intent, e)
}

func guestRetirementV2Clock(c model.CapacityGuestRetirementClockV2, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntentV2, complete bool) bool {
	if c.Schema != GuestRetirementV2ClockSchema || c.BootID != e.Statement.Actor.BootID || c.GuestNonceSHA256 != GuestRetirementSHA(i.GuestNonce) || c.ExpiresMonotonicNS != i.GuestExpiresMonotonicNS || c.StartedMonotonicNS < i.GuestNonce.IssuedMonotonicNS || c.StartedMonotonicNS >= c.ExpiresMonotonicNS || c.ReturnedMonotonicNS < c.StartedMonotonicNS || c.GuestLocalStartedAt.IsZero() || !c.GuestLocalDeadline.Equal(c.GuestLocalStartedAt.Add(time.Duration(c.ExpiresMonotonicNS-c.StartedMonotonicNS))) {
		return false
	}
	return !complete || c.ReturnedMonotonicNS < c.ExpiresMonotonicNS
}

func validateGuestRetirementV2Base(r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment, now time.Time, write bool) error {
	i := r.Intent
	if i.Schema != GuestRetirementV2IntentSchema || (i.Tuple.Provider != "aws" && i.Tuple.Provider != "hetzner") || !guestUUID(i.PreregistrationID) || !ValidDigest(i.ProfileManifestSHA256) || !businessSource.MatchString(i.CoreSourceCommit) || i.CoreSourceCommit != e.Statement.CoreAuthoritySourceCommit || i.Runtime != e.Statement.Runtime || !reflect.DeepEqual(i.Writers, e.Statement.Writers) || i.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || i.WriterRosterSHA256 != GuestRetirementSHA(i.Writers) || i.Purpose != GuestRetirementV2Purpose || i.BindingName != e.Statement.BindingName || i.Slot != i.Tuple.Slot || !guestUUID(i.RequestID) || !guestUUID(i.AttemptID) || !ValidDigest(i.NonceSHA256) || i.EnrollmentSHA256 != GuestRetirementSHA(e) || i.Tuple != e.Statement.Tuple || i.Actor != e.Statement.Actor || !guestUUID(i.PolicyID) || !ValidDigest(i.PolicyChecksum) || !guestUUID(i.WorkflowID) || !ValidDigest(i.WorkflowChecksum) || i.Generation == 0 || i.Generation > math.MaxInt64 || i.Fence == 0 || i.Fence > math.MaxInt64 || !guestUUID(i.LeaseOwner) || !guestUUID(i.WithdrawOperationID) || !ValidDigest(i.WithdrawRequestSHA256) || !guestUUID(i.DrainOperationID) || !ValidDigest(i.DrainRequestSHA256) || i.IssuedAt.IsZero() || i.IssuedAt.After(now) || i.OriginalDeadline.IsZero() || !i.OriginalDeadline.After(i.IssuedAt) || i.OriginalDeadline.Sub(i.IssuedAt) > 30*time.Second || !guestRetirementVerify(e.Statement.CoreIntentPublicKey, r.Signature, i) {
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
func GuestRetirementV2RuntimeReturn(r model.CapacityGuestRetirementRuntimeReturnV2, e model.CapacityGuestRetirementEnrollment, i model.CapacityGuestRetirementIntentV2, originalRecordedAt time.Time) error {
	refuse := fmt.Errorf("original Guest runtime return refused")
	if r.Schema != GuestRetirementV2RuntimeSchema || r.IntentSHA256 != GuestRetirementSHA(i) || r.AttemptID != i.AttemptID || r.Runtime != e.Statement.Runtime || r.WriterRosterSHA256 != e.Statement.WriterRosterSHA256 || r.WithdrawRequestSHA256 != i.WithdrawRequestSHA256 || r.DrainRequestSHA256 != i.DrainRequestSHA256 || r.UnknownWriters == nil || len(r.UnknownWriters) != 0 || len(r.Writers) != len(e.Statement.Writers) || r.ReturnedAt.IsZero() || r.ReturnedAt.After(originalRecordedAt) || !r.ReturnedAt.Before(r.Clock.GuestLocalDeadline) || !guestRetirementV2Clock(r.Clock, e, i, true) {
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
