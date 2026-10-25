package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

const GuestQualificationProfile = "qualification-original-echo-writer-v1"
const GuestQualificationWriter = "qualification-original-echo-writer"

// The event provider's fixed hyphenated native spelling is admitted only in
// this separately compiled source realm; generic provider syntax is unchanged.
func GuestOriginalNativeQEMUProviderEnabled(provider string) bool {
	return guestOriginalExecutionClass == "native_qemu_qualification" && provider == "native-qemu"
}

// Production admission is an exact compiled source approval. Qualification
// keeps its separate fixed subset and cannot populate production approvals.
func GuestOriginalProfileEnabled(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, actualProvider string) bool {
	if guestOriginalExecutionClass != "native_qemu_qualification" {
		return guestOriginalProductionProfileEnabled(p, binding, actualProvider)
	}
	profile := binding.ProfileManifest
	if guestOriginalExecutionClass != "native_qemu_qualification" || actualProvider != "native-qemu" || binding.EvidenceClass != "native_qemu_qualification" || profile.CoverageClass != "native_qualification_subset" || profile.Profile != GuestQualificationProfile || profile.ProductionCatalogSHA256 != "" || profile.OwnerImageDigest != "" || len(profile.Writers) != 1 {
		return false
	}
	matched := false
	for _, approved := range p.Profiles {
		matched = matched || approved.Name == profile.Profile && approved.Provider == actualProvider
	}
	w := profile.Writers[0]
	return matched && w.ID == GuestQualificationWriter && w.CgroupRelativePath == "." && w.ImageDigest == "" && w.SourceImageReceiptSHA256 == "" && w.SourceCommit == profile.OwnerSourceCommit && w.BinarySHA256 == profile.OwnerBinarySHA256 && w.CommandSHA256 == GuestRetirementSHA(struct {
		Executable  string   `json:"executable"`
		Args        []string `json:"args"`
		SourceClass string   `json:"source_class"`
	}{"/usr/local/libexec/yggdrasil-guest-protected-runtime-owner", []string{"--qualification-original-writer"}, "native_qemu_qualification"}) && w.HandleContractSHA256 == GuestRetirementSHA(struct{ Writer, Workers, Connections, Withdraw string }{GuestQualificationWriter, "original-child-Wait+stderr-EOF-Close", "original-stdout-EOF-Close+stdin-Close", "same-original-child-operation-bound-ACK"})
}
