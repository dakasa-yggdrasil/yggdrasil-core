//go:build linux && nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

func guestPostlossObservationAllowed(b model.CapacityGuestRetirementBinding, w model.CapacityGuestOriginalCreateWitness) bool {
	o := w.SourceObservation
	return o != nil && b.EvidenceClass == "native_qemu_qualification" && b.ProfileManifest.Profile == "qualification-original-echo-writer-v1" && b.CoreAuthoritySourceCommit == CurrentGuestCoreSource() && w.Tuple.Provider == "native-qemu" && GuestPostlossQualificationSlot(o.Case) != 0 && w.Tuple.Slot == GuestPostlossQualificationSlot(o.Case) && o.Schema == "canonical_postloss_observed_create_v1" && o.Scope == "SOURCE_ONLY_OBSERVED_SAME_CREATE_NOT_ACCEPTED_TRANSPORT" && o.OriginalOutcome == "uncertain" && o.OwningReplySHA256 == BusinessCreationSHA256(nil) && ValidDigest(o.OwningReplyReadSHA256) && ValidDigest(o.IndependentNativeReadSHA256) && ValidDigest(o.OriginalCreatorSHA256) && !o.ProductionQualified
}
