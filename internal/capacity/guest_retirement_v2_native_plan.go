package capacity

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// GuestRetirementV2NativeOffPlanContent validates only original native content.
// It never grants freshness, quiescence, a floor, auxiliary absence or DELETE.
// The caller separately owns actual RPC completion and Core PG ledger age.
// No provider/adapter timestamp is compared with Core PG or a substituted now.
func GuestRetirementV2NativeOffPlanContent(p model.CapacityPolicySpec, b model.CapacityMutationBinding, plan model.CapacityVMFleetPlan, original model.CapacityMutationReceipt) error {
	fail := fmt.Errorf("exact source-owned native off content required")
	configured, err := VMObservationBinding(p, b.Name)
	if err != nil || !reflect.DeepEqual(configured, b) {
		return fail
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			if provider != "" {
				return fail
			}
			provider = profile.Provider
		}
	}
	observe, off := VMObserveServer, "off"
	switch provider {
	case "aws":
		if !AWSOriginalMutationPair(b) {
			return fail
		}
		observe, off = "observe_ec2_instance", "stopped"
	case "hetzner":
		if b.EnsureCapability != "ensure_server" || b.DestroyCapability != "destroy_server" || !businessSource.MatchString(b.OriginalProviderSourceCommit) {
			return fail
		}
	default:
		return fail
	}
	g := original.Grant
	if !original.TransportCompleted || original.Outcome != "accepted" || (g.State != "confirmed" && g.State != "settled") || g.CompensationOf != "" || original.NativeReadback != nil || !guestUUID(g.GrantID) || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.Capability != b.EnsureCapability || original.ResourceID == "" || original.ResourceCreatedAt == "" {
		return fail
	}
	slot, err := vmProjection(b, g.Slot, plan.DesiredSpec)
	if err != nil {
		return fail
	}
	if _, err = approvedMutationProjection(b, slot); err != nil {
		return fail
	}
	if g.RequestSHA256 != slot.DesiredSpecSHA256 || plan.DesiredSpec.Capability != observe || plan.DesiredSpec.ExpectedResourceID != original.ResourceID || plan.DesiredSpec.ExpectedResourceCreatedAt != original.ResourceCreatedAt || vmNoAuthority(plan) != nil || plan.CompensationOf != "" || plan.CompensationIdentityVerified || plan.Protected != (g.Slot <= b.ProtectedSlots) || plan.Server == nil {
		return fail
	}
	// Actual AWS observe preserves the original ensure digest while updating
	// its public desired spec. Hetzner hashes its complete observe projection.
	// Preserve each source contract; do not invent a uniform replacement wire.
	wantDigest := slot.DesiredSpecSHA256
	if provider == "hetzner" {
		raw, err := canonicalMutationProjection(plan.DesiredSpec)
		if err != nil {
			return fail
		}
		wantDigest = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	if plan.RequestSHA256 != wantDigest {
		return fail
	}
	s := plan.Server
	if s.ID != original.ResourceID || s.CreatedAt != original.ResourceCreatedAt || s.Name != slot.DesiredSpec.NativeName || s.Status != off || !s.PhysicalSpecVerified || s.CompensationIdentityVerified || len(s.Labels) != 6 || s.Labels["yggdrasil.io/owner"] == "" || len(s.Labels["yggdrasil.io/owner"]) > 128 || s.Labels["yggdrasil.io/scope"] != vmLabelDigest(b.ScopeChecksum) || s.Labels["yggdrasil.io/spec"] != vmLabelDigest(slot.DesiredSpec.ProfileChecksum) || s.Labels["yggdrasil.io/profile"] != b.ProfileName || s.Labels["yggdrasil.io/slot"] != strconv.Itoa(g.Slot) || s.Labels["yggdrasil.io/intent"] != g.GrantID {
		return fail
	}
	for key, value := range s.Labels {
		if len(value) > 128 || strings.ContainsAny(value, "\r\n\t") || (key != "yggdrasil.io/owner" && key != "yggdrasil.io/scope" && key != "yggdrasil.io/spec" && key != "yggdrasil.io/profile" && key != "yggdrasil.io/slot" && key != "yggdrasil.io/intent") {
			return fail
		}
	}
	if provider == "aws" {
		if !regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(s.ID) {
			return fail
		}
	} else {
		id, err := strconv.ParseInt(s.ID, 10, 64)
		if err != nil || id < 1 || strconv.FormatInt(id, 10) != s.ID {
			return fail
		}
	}
	// CreatedAt is provider time; ObservedAt values are adapter time. Even the
	// two adapter fields have different order in the actual AWS/Hetzner source.
	for _, raw := range []string{s.CreatedAt, s.ObservedAt, plan.ObservedAt} {
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != raw {
			return fail
		}
	}
	return nil
}
