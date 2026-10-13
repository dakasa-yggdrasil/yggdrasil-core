package capacity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const GuestRetirementSchema = "original_guest_retirement_v1"
const GuestRetirementPurpose = "retire_vm_slot"
const GuestProtectedProfileSchema = "original_guest_protected_profile_v1"
const GuestOriginalProvisioningSchema = "original_guest_protected_provisioning_v1"
const GuestProtectedCgroup = "/sys/fs/cgroup/yggdrasil-protected-writers"

// These hashes cover the declared canonical typed bytes, never a caller's
// stringified map, transport credentials, regenerated body or inferred result.
func GuestRetirementSHA(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func guestRetirementPublicKey(encoded string) bool {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(raw) == ed25519.PublicKeySize && base64.StdEncoding.EncodeToString(raw) == encoded
}

func guestRetirementVerify(key, signature string, v any) bool {
	public, keyErr := base64.StdEncoding.DecodeString(key)
	sig, sigErr := base64.StdEncoding.DecodeString(signature)
	raw, err := json.Marshal(v)
	return keyErr == nil && sigErr == nil && err == nil && len(public) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(public), raw, sig)
}

func GuestRetirementLifetime(l model.CapacityGuestRetirementLifetime) bool {
	invocation, err := hex.DecodeString(l.ServiceInvocationID)
	return guestUUID(l.BootID) && ValidDigest(l.ProcessNonceSHA256) && l.PID > 0 && l.StartTicks > 0 && businessSource.MatchString(l.SourceCommit) && ValidDigest(l.BinarySHA256) && err == nil && len(invocation) == 16 && hex.EncodeToString(invocation) == l.ServiceInvocationID
}

func guestRetirementSecretRef(ref string) bool {
	return guestText(ref, 4096) && strings.HasPrefix(ref, "secret://") && strings.HasSuffix(ref, "#value") && strings.Count(ref, "#") == 1
}

// A present binding validates the full immutable source profile and exact
// separate private transports. Absence can never grant a new VM DELETE: the
// repository issuance/redemption guards independently require this binding.
func ValidateGuestRetirementBinding(p model.CapacityPolicySpec, r *model.CapacityGuestRetirementBinding) error {
	refuse := fmt.Errorf("complete source-owned Guest retirement binding required")
	if r == nil || r.Mode != GuestRetirementSchema || (r.EvidenceClass != "owned_provisioner_original" && r.EvidenceClass != "native_qemu_qualification") || !businessSource.MatchString(r.ProvisionerSourceCommit) || !businessSource.MatchString(r.GuestSourceCommit) || !businessSource.MatchString(r.CoreAuthoritySourceCommit) || !guestRetirementPublicKey(r.ProvisionerPublicKey) || !guestRetirementPublicKey(r.EnrollmentIssuerPublicKey) || r.ProvisionerPublicKey == r.EnrollmentIssuerPublicKey || !guestRetirementSecretRef(r.EnrollmentSigningKeyRef) || !guestRetirementSecretRef(r.IntentSigningKeyRef) || r.EnrollmentSigningKeyRef == r.IntentSigningKeyRef || r.MaxEvidenceAgeSeconds < 1 || r.MaxEvidenceAgeSeconds > min(30, p.MaxEvidenceAgeSeconds) || !ValidDigest(r.ProfileManifestSHA256) || GuestRetirementSHA(r.ProfileManifest) != r.ProfileManifestSHA256 {
		return refuse
	}
	b, err := VMObservationBinding(p, r.MutationBindingName)
	if err != nil {
		return refuse
	}
	profile := r.ProfileManifest
	if profile.Schema != GuestProtectedProfileSchema || profile.Profile != b.ProfileName || profile.MutationBinding != b.Name || !ValidDigest(profile.BootstrapSHA256) || !businessSource.MatchString(profile.BootstrapOwnerSourceCommit) || !ValidDigest(profile.BootstrapOwnerBinarySHA256) || !ValidDigest(profile.BootstrapReaderBinarySHA256) || !ValidDigest(profile.BootstrapPayloadSHA256) || profile.OriginalProvisioningBudgetSeconds < 1 || profile.OriginalProvisioningBudgetSeconds > 86400 || !guestText(profile.OriginalProvisioningStepID, 64) || !businessSource.MatchString(profile.OwnerSourceCommit) || !ValidDigest(profile.OwnerBinarySHA256) || !guestProfileCoverage(profile, r.EvidenceClass) || profile.ProtectedCgroup != GuestProtectedCgroup || profile.ActorSourceCommit != r.GuestSourceCommit || !ValidDigest(profile.ActorBinarySHA256) || !ValidDigest(profile.RuntimeClientCommandSHA256) || !ValidDigest(profile.PoweroffCommandSHA256) || len(profile.Writers) < 1 || len(profile.Writers) > 64 {
		return refuse
	}
	seen := map[string]bool{}
	for _, w := range profile.Writers {
		if !guestText(w.ID, 64) || seen[w.ID] || !businessSource.MatchString(w.SourceCommit) || !ValidDigest(w.BinarySHA256) || !ValidDigest(w.CommandSHA256) || !ValidDigest(w.HandleContractSHA256) || (profile.CoverageClass == "native_qualification_subset" && w.CgroupRelativePath != ".") || (profile.CoverageClass != "native_qualification_subset" && w.CgroupRelativePath != w.ID) || !guestWriterImageProvenance(profile, w) {
			return refuse
		}
		seen[w.ID] = true
	}
	if len(r.Members) < 1 || len(r.Members) > b.MaxSlots {
		return refuse
	}
	lastSlot := 0
	seenNames := map[string]bool{}
	for _, m := range r.Members {
		slot, err := vmApprovedSlot(b, m.Slot)
		u, urlErr := url.Parse(m.Origin)
		if err != nil || m.Slot <= lastSlot || slot.DesiredSpec.BootstrapSHA256 != profile.BootstrapSHA256 || !guestText(m.Name, 64) || seenNames[m.Name] || urlErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !guestRetirementSecretRef(m.ServerCARef) || !guestRetirementSecretRef(m.ClientCertificateRef) || !guestRetirementSecretRef(m.ClientKeyRef) || !guestText(m.ActorClientPrincipal, 128) || !guestText(m.ProvisionerClientPrincipal, 128) || m.ProvisionerClientPrincipal == m.ActorClientPrincipal || m.ServerCARef == m.ClientKeyRef || m.ClientCertificateRef == m.ClientKeyRef {
			return refuse
		}
		seenNames[m.Name] = true
		lastSlot = m.Slot
	}
	return nil
}

// Census is joined to the ORIGINAL enrolled full source roster. An empty or
// partial census is not the original pre-admission placement proof; unknown
// PIDs/start ticks remain HOLD even when a signed envelope says otherwise.
func GuestRetirementProtectedCensus(c model.CapacityGuestRetirementProtectedCensus, e model.CapacityGuestRetirementEnrollment, returned time.Time, all bool) bool {
	if c.Schema != "guest_retirement_protected_cgroup_v1" || c.Scope != "fixed_protected_cgroup_v2" || c.SourceCommit != e.Statement.Runtime.SourceCommit || c.Processes == nil || !ValidDigest(c.RawCensusSHA256) || c.ObservedAt.IsZero() || c.ObservedAt.After(returned) {
		return false
	}
	known := map[int]uint64{}
	for _, w := range e.Statement.Writers {
		if !GuestRetirementLifetime(w.Lifetime) || known[w.Lifetime.PID] != 0 {
			return false
		}
		known[w.Lifetime.PID] = w.Lifetime.StartTicks
	}
	seen := map[int]bool{}
	for _, native := range c.Processes {
		if native.PID < 1 || native.StartTicks == 0 || seen[native.PID] || known[native.PID] != native.StartTicks {
			return false
		}
		seen[native.PID] = true
	}
	return len(known) > 0 && (!all || len(seen) == len(known))
}

// Qualification binaries are host processes, not invented OCI images. The
// complete production roster requires the source compiler's actual catalog
// and immutable per-writer source/image and handle contracts. This remains a
// declared prerequisite until the owning native qualification closes it.
func guestProfileCoverage(p model.CapacityGuestProtectedProfileManifest, evidenceClass string) bool {
	if evidenceClass == "native_qemu_qualification" {
		return p.CoverageClass == "native_qualification_subset" && p.ProductionCatalogSHA256 == "" && p.OwnerImageDigest == ""
	}
	return evidenceClass == "owned_provisioner_original" && p.CoverageClass == "complete_production_roster" && ValidDigest(p.ProductionCatalogSHA256) && strings.HasPrefix(p.OwnerImageDigest, "sha256:") && ValidDigest(strings.TrimPrefix(p.OwnerImageDigest, "sha256:"))
}
func guestWriterImageProvenance(p model.CapacityGuestProtectedProfileManifest, w model.CapacityGuestProtectedWriterDefinition) bool {
	if p.CoverageClass == "native_qualification_subset" {
		return w.ImageDigest == "" && w.SourceImageReceiptSHA256 == ""
	}
	return strings.HasPrefix(w.ImageDigest, "sha256:") && ValidDigest(strings.TrimPrefix(w.ImageDigest, "sha256:")) && ValidDigest(w.SourceImageReceiptSHA256)
}
