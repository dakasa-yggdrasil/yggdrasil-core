package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const GuestProviderNativeIdentitySchema = "guest_provider_native_identity_v1"

var guestAWSNativeID = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var guestNativeToken = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func guestNativeBounded(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && guestNativeToken.MatchString(value)
}
func guestNativeNumeric(value string) bool {
	n, err := strconv.ParseUint(value, 10, 63)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == value
}

// ValidateGuestProviderNativeIdentity checks evidence at the signed witness's
// original observation time. A later boot never rewrites creation time; Guest
// independently reads its current metadata and kernel process lifetimes.
func ValidateGuestProviderNativeIdentity(i *model.CapacityGuestProviderNativeIdentity, tuple model.CapacityGuestNativeTuple, source string, witnessed time.Time) error {
	if i == nil || i.Schema != GuestProviderNativeIdentitySchema || i.Provider != tuple.Provider || i.ResourceID != tuple.ResourceID || i.ResourceCreatedAt != tuple.CreatedAt || !businessSource.MatchString(source) || i.AdapterSourceCommit != source || (!Fresh(i.ObservedAt, witnessed, 30) || i.ObservedAt.After(witnessed)) || !guestNativeBounded(i.Region, 64) || !guestNativeBounded(i.Location, 64) || !guestNativeBounded(i.Hostname, 253) || !guestNativeBounded(i.TypeID, 64) || !guestNativeBounded(i.ImageID, 128) {
		return fmt.Errorf("original provider native identity mismatch")
	}
	created, err := time.Parse(time.RFC3339Nano, i.ResourceCreatedAt)
	if err != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != i.ResourceCreatedAt || created.After(i.ObservedAt.Add(5*time.Second)) {
		return fmt.Errorf("provider creation lifetime invalid")
	}
	switch i.Provider {
	case "aws":
		if !guestAWSNativeID.MatchString(i.ResourceID) || len(i.AccountID) != 12 || strings.Trim(i.AccountID, "0123456789") != "" || i.Location != i.Region || !guestNativeBounded(i.Zone, 64) || !strings.HasPrefix(i.Zone, i.Region) || !strings.HasPrefix(i.ImageID, "ami-") {
			return fmt.Errorf("AWS native realm mismatch")
		}
	case "hetzner":
		// The current Cloud API exposes location/network_zone but removed its
		// datacenter property. It cannot attest metadata's availability-zone.
		if !guestNativeNumeric(i.ResourceID) || !guestNativeNumeric(i.TypeID) || !guestNativeNumeric(i.ImageID) || i.AccountID != "" || i.Zone != "" {
			return fmt.Errorf("hetzner native realm mismatch")
		}
	default:
		return fmt.Errorf("unsupported native provider identity")
	}
	return nil
}

func OriginalGuestProviderIdentity(p model.CapacityPolicySpec, b model.CapacityMutationBinding, plan model.CapacityVMFleetPlan, proof model.CapacityMutationProof, now time.Time) (*model.CapacityGuestProviderNativeIdentity, error) {
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	if provider != "aws" && provider != "hetzner" || plan.Server == nil || proof.ResourceAbsent || !proof.OwnerVerified || !proof.SpecVerified || plan.Server.ID != proof.ResourceID || plan.Server.CreatedAt != proof.ResourceCreatedAt || !businessSource.MatchString(b.OriginalProviderSourceCommit) {
		return nil, fmt.Errorf("native identity has no original read owner")
	}
	s := plan.Server
	i := &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: provider, ResourceID: s.ID, ResourceCreatedAt: s.CreatedAt, Region: s.Location, Location: s.Location, Zone: s.NetworkZone, TypeID: s.TypeID, ImageID: s.ImageID, AccountID: s.ProviderAccountID, Hostname: s.ProviderHostname, ObservedAt: proof.ObservedAt, AdapterSourceCommit: b.OriginalProviderSourceCommit}
	if provider == "hetzner" {
		i.Region = s.NetworkZone
		i.Zone = ""
		i.Hostname = s.Name
	}
	tuple := model.CapacityGuestNativeTuple{Provider: provider, ResourceID: proof.ResourceID, CreatedAt: proof.ResourceCreatedAt}
	if !Fresh(proof.ObservedAt, now, 30) {
		return nil, fmt.Errorf("native identity read expired")
	}
	if err := ValidateGuestProviderNativeIdentity(i, tuple, b.OriginalProviderSourceCommit, proof.ObservedAt); err != nil {
		return nil, err
	}
	return i, nil
}
