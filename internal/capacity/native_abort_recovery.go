package capacity

import (
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const NativePreRegistrationAbortRecoverySchema = "native_pre_registration_abort_unredeemed_recovery_v1"

func ValidateNativeAbortRecoveryBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortRecoveryBinding) error {
	if b.Schema != NativePreRegistrationAbortRecoverySchema || ValidateNativeAbortBinding(policy, p, b.Native) != nil || !NativeProcessNonce(b.ParentCommandID) || b.ParentCommandID == b.Native.PodUID || b.ParentFencingToken < 1 || b.ExpectedIntentFencingToken < b.ParentFencingToken || b.ExpectedIntentFencingToken >= 9007199254740991 || b.ParentExpiresAt.IsZero() {
		return fmt.Errorf("fixed expired unredeemed native abort parent required")
	}
	return nil
}

func ValidateNativeAbortRecoveryProof(policy model.Manifest, p model.CapacityPolicySpec, proof model.CapacityNativeAbortRecoveryProof, now time.Time) error {
	b, l := proof.Binding, proof.Lineage
	history := model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, ArchivedCommands: 1}
	if ValidateNativeAbortRecoveryBinding(policy, p, b) != nil || proof.Schema != NativePreRegistrationAbortRecoverySchema || proof.History != history || proof.ScopeUnsettledCommands != 0 || proof.FencingToken != b.ExpectedIntentFencingToken+1 || proof.AuthoredAt.IsZero() || !Fresh(proof.AuthoredAt, now, p.MaxEvidenceAgeSeconds) || proof.AuthoredAt.Before(proof.Observation.ObservedAt) || !b.ParentExpiresAt.Before(proof.AuthoredAt) || l.ParentCommandID != b.ParentCommandID || l.ParentSequence != 1 || l.PriorState != "uncertain" || l.AdministrativeState != "refused_no_redemption" || l.ParentFencingToken != b.ParentFencingToken || !l.ParentExpiresAt.Equal(b.ParentExpiresAt) || !l.DispositionAt.Equal(proof.AuthoredAt) || ValidateNativeAbortObservation(p, b.Native, proof.Observation, now, true) != nil {
		return fmt.Errorf("server-owned single-parent native abort recovery proof required")
	}
	return nil
}
