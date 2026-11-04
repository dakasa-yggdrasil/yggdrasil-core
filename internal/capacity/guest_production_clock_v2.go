package capacity

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const GuestProfileAuthorityV2Schema = "original_guest_profile_authority_v2"
const GuestProvisioningClockV2Schema = "original_guest_provisioning_clock_v2"
const GuestProvisioningV2Schema = "original_guest_protected_provisioning_v2"
const GuestInstallationV2Schema = "guest_original_installation_v2"
const GuestInstallationClockV2Schema = "original_guest_installation_clock_v2"
const GuestProductionProvisioningLimit = 420 * time.Second

// All *_monotonic_ns fields in this explicit production schema are samples of
// one Guest Linux CLOCK_BOOTTIME, including suspend. No Core/Guest wall subtraction.
func GuestConservativeProductionExpiry(acquisitionExpiry, requestStart, remaining int64) (int64, error) {
	if acquisitionExpiry <= 0 || requestStart <= 0 || remaining <= 0 || remaining > int64(GuestProductionProvisioningLimit) || requestStart > math.MaxInt64-remaining {
		return 0, fmt.Errorf("original production expiry refused")
	}
	expiry := requestStart + remaining
	if acquisitionExpiry < expiry {
		expiry = acquisitionExpiry
	}
	if expiry <= requestStart {
		return 0, fmt.Errorf("original production expiry exhausted")
	}
	return expiry, nil
}

// now is the original Core PostgreSQL domain. The authority carries its own
// signed PG sample so Guest never compares it with its wall or boot clock.
func GuestOriginalProfileAuthorityV2(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, a model.CapacityGuestOriginalProfileAuthorityV2, coreKey string, now time.Time) error {
	r, w, m := a.Preregistration, a.CreateWitness, a.Profile
	if a.Schema != GuestProfileAuthorityV2Schema || a.BindingName != member.Name || a.Slot != member.Slot || !guestUUID(a.GuestBootID) || !ValidDigest(a.RequestNonceSHA256) || binding.EvidenceClass != "owned_provisioner_original" || m.CoverageClass != "complete_production_roster" || (w.Tuple.Provider != "aws" && w.Tuple.Provider != "hetzner") || !reflect.DeepEqual(m, binding.ProfileManifest) || a.RemainingNS <= 0 || a.RemainingNS > int64(GuestProductionProvisioningLimit) || a.ObservedAt.IsZero() || a.ObservedAt.After(now) || a.ObservedAt.Before(w.ObservedAt) || !a.ObservedAt.Before(r.OriginalDeadline) || r.OriginalDeadline.Sub(a.ObservedAt) != time.Duration(a.RemainingNS) || time.Duration(a.RemainingNS) > time.Duration(m.OriginalProvisioningBudgetSeconds)*time.Second || r.BindingName != member.Name || r.Slot != member.Slot || w.Tuple.Slot != member.Slot || r.ProfileManifestSHA256 != binding.ProfileManifestSHA256 || GuestOriginalCreateWitness(p, binding, member, r, w, coreKey, a.ObservedAt) != nil {
		return fmt.Errorf("original production profile authority refused")
	}
	signature := a.Signature
	a.Signature = ""
	if !guestRetirementVerify(coreKey, signature, a) {
		return fmt.Errorf("original production profile authority signature refused")
	}
	return nil
}

func GuestProductionClockStoredMatches(c *model.CapacityGuestProductionProvisioningClockV2, pre model.CapacityGuestOriginalProvisioningPreregistration, witness model.CapacityGuestOriginalCreateWitness, profile model.CapacityGuestProtectedProfileManifest) bool {
	return c != nil && reflect.DeepEqual(c.Authority.Preregistration, pre) && reflect.DeepEqual(c.Authority.CreateWitness, witness) && reflect.DeepEqual(c.Authority.Profile, profile)
}

func GuestProductionProvisioningClockV2(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, member model.CapacityGuestRetirementMemberBinding, c model.CapacityGuestProductionProvisioningClockV2, coreKey string, now time.Time) error {
	expiry, err := GuestConservativeProductionExpiry(c.AcquisitionExpiresMonotonicNS, c.OriginalReadStartedMonotonicNS, c.Authority.RemainingNS)
	if c.Schema != GuestProvisioningClockV2Schema || GuestOriginalProfileAuthorityV2(p, binding, member, c.Authority, coreKey, now) != nil || c.BootstrapOwnerPID < 1 || c.BootstrapOwnerStartTicks == 0 || c.AcquisitionStartedMonotonicNS <= 0 || c.AcquisitionExpiresMonotonicNS <= c.AcquisitionStartedMonotonicNS || c.AcquisitionExpiresMonotonicNS-c.AcquisitionStartedMonotonicNS > int64(GuestProductionProvisioningLimit) || c.OriginalReadStartedMonotonicNS < c.AcquisitionStartedMonotonicNS || c.OriginalReadReturnedMonotonicNS < c.OriginalReadStartedMonotonicNS || c.OriginalReadReturnedMonotonicNS-c.OriginalReadStartedMonotonicNS > int64(5*time.Second) || err != nil || c.AcceptedExpiresMonotonicNS != expiry || c.OriginalReadReturnedMonotonicNS >= expiry || c.OriginalReadStartedAt.IsZero() || c.OriginalReadReturnedAt.Before(c.OriginalReadStartedAt) || c.OriginalResultReturnedMonotonicNS < c.OriginalReadReturnedMonotonicNS || c.OriginalResultReturnedMonotonicNS >= expiry {
		return fmt.Errorf("one original production boot clock required")
	}
	return nil
}

// The digest is Core-signed only after the complete original registration proof
// has passed under current PG authority. It marks Guest IssuedAt as Guest content;
// unmarked qualification/legacy enrollment retains its original wall checks.
func guestProductionEnrollmentClockMarked(binding model.CapacityGuestRetirementBinding, s model.CapacityGuestRetirementEnrollmentStatement) bool {
	return ValidDigest(s.OriginalProvisioningClockSHA256) && binding.EvidenceClass == "owned_provisioner_original" && s.SourceClass == binding.EvidenceClass && binding.ProfileManifest.CoverageClass == "complete_production_roster" && (s.Tuple.Provider == "aws" || s.Tuple.Provider == "hetzner")
}
