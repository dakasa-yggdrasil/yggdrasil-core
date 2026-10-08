package capacity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func ValidDigest(v string) bool {
	if len(v) != sha256.Size*2 || strings.ToLower(v) != v {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func ValidateMutationBindings(p model.CapacityPolicySpec) error {
	if len(p.MutationBindings) > 64 {
		return fmt.Errorf("capacity mutation bindings exceed limit")
	}
	names := map[string]bool{}
	targets := map[string]bool{}
	for _, b := range p.MutationBindings {
		id, err := uuid.Parse(b.IntegrationInstanceID)
		typeID, typeErr := uuid.Parse(b.IntegrationTypeID)
		if err != nil || id == uuid.Nil || id.String() != b.IntegrationInstanceID || typeErr != nil || typeID == uuid.Nil || typeID.String() != b.IntegrationTypeID || !ValidDigest(b.IntegrationTypeChecksum) || b.Name == "" || len(b.Name) > 128 || names[b.Name] || b.AdapterPrincipalID == "" || len(b.AdapterPrincipalID) > 128 || !ValidDigest(b.IntegrationChecksum) || !ValidDigest(b.ScopeChecksum) || !strings.HasPrefix(b.EnsureCapability, "ensure_") || !strings.HasPrefix(b.DestroyCapability, "destroy_") || len(b.EnsureCapability) > 128 || len(b.DestroyCapability) > 128 {
			return fmt.Errorf("capacity mutation binding requires exact identity, digests, principal and capability pair")
		}
		key := b.IntegrationInstanceID + "/" + b.ScopeChecksum + "/" + b.ProfileName
		if targets[key] || b.ProtectedSlots < 0 || b.MaxSlots < b.ProtectedSlots || b.MaxSlots > p.Ceiling || len(b.Slots) != b.MaxSlots {
			return fmt.Errorf("capacity mutation binding requires unique bounded scope and every approved slot")
		}
		found := false
		for _, profile := range p.Profiles {
			if profile.Name == b.ProfileName && b.MaxSlots <= profile.MaxUnits {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("capacity mutation binding profile is outside the envelope")
		}
		slots := map[int]bool{}
		for _, slot := range b.Slots {
			if slot.Slot < 1 || slot.Slot > b.MaxSlots || slots[slot.Slot] || !ValidDigest(slot.DesiredSpecSHA256) {
				return fmt.Errorf("capacity mutation slot requires unique exact desired spec digest")
			}
			slots[slot.Slot] = true
		}
		if len(b.DefinitiveRejections) > 32 {
			return fmt.Errorf("capacity definitive rejections exceed limit")
		}
		rejections := map[string]bool{}
		for _, r := range b.DefinitiveRejections {
			ref, err := url.Parse(r.DocumentationRef)
			key := fmt.Sprintf("%d/%s", r.StatusCode, r.ErrorCode)
			if r.StatusCode < 400 || r.StatusCode > 499 || r.StatusCode == 408 || r.StatusCode == 409 || r.StatusCode == 425 || r.StatusCode == 429 || !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(r.ErrorCode) || len(r.DocumentationRef) > 512 || err != nil || ref.Scheme != "https" || ref.Host == "" || ref.User != nil || rejections[key] {
				return fmt.Errorf("capacity definitive rejection requires an exact reviewed no-acceptance contract")
			}
			rejections[key] = true
		}
		names[b.Name], targets[key] = true, true
	}
	return nil
}

type MutationPlan struct {
	Binding                   model.CapacityMutationBinding
	Capability                string
	Slot                      int
	RequestSHA256             string
	ExpectedResourceID        string
	ExpectedResourceCreatedAt string
	CanonicalSpec             []byte
}

// PrepareMutationPlan binds a provider's dry-run projection to an operator slot
// digest. Core never constructs SDK payloads or learns credential/bootstrap data.
func PrepareMutationPlan(p model.CapacityPolicySpec, issue model.CapacityMutationIssue) (MutationPlan, error) {
	var plan MutationPlan
	for _, b := range p.MutationBindings {
		if b.Name == issue.BindingName {
			plan.Binding = b
			break
		}
	}
	b := plan.Binding
	if b.Name == "" || len(issue.DesiredSpec) == 0 || len(issue.DesiredSpec) > 16384 {
		return plan, fmt.Errorf("capacity mutation requires an approved bounded desired spec")
	}
	d := json.NewDecoder(bytes.NewReader(issue.DesiredSpec))
	d.DisallowUnknownFields()
	var spec *model.CapacityMutationSpecV1
	if err := d.Decode(&spec); err != nil || spec == nil {
		return plan, fmt.Errorf("capacity mutation desired spec must be an object")
	}
	if d.Decode(new(any)) != io.EOF || !mutationProjectionSchemaPattern.MatchString(spec.SchemaVersion) || spec.NativeName == "" || len(spec.NativeName) > 256 || !ValidDigest(spec.ProfileChecksum) || !ValidDigest(spec.AdmissionChecksum) || !ValidDigest(spec.BootstrapSHA256) {
		return plan, fmt.Errorf("capacity mutation desired spec requires a bounded closed non-secret projection")
	}
	if spec.IntegrationInstanceID != b.IntegrationInstanceID || spec.ScopeChecksum != b.ScopeChecksum || spec.ProfileName != b.ProfileName {
		return plan, fmt.Errorf("capacity mutation desired spec identity mismatch")
	}
	plan.Capability = spec.Capability
	if plan.Capability != b.EnsureCapability && plan.Capability != b.DestroyCapability {
		return plan, fmt.Errorf("capacity mutation capability is not approved")
	}
	plan.Slot = spec.Slot
	if plan.Slot < 1 || plan.Slot > b.MaxSlots {
		return plan, fmt.Errorf("capacity mutation slot is outside the approved envelope")
	}
	plan.ExpectedResourceID = spec.ExpectedResourceID
	plan.ExpectedResourceCreatedAt = spec.ExpectedResourceCreatedAt
	if plan.Capability == b.DestroyCapability {
		if plan.Slot <= b.ProtectedSlots || plan.ExpectedResourceID == "" || len(plan.ExpectedResourceID) > 256 {
			return plan, fmt.Errorf("capacity destruction requires an unprotected immutable resource")
		}
		created, err := time.Parse(time.RFC3339Nano, plan.ExpectedResourceCreatedAt)
		if err != nil || created.IsZero() {
			return plan, fmt.Errorf("capacity destruction requires immutable creation time")
		}
	} else if spec.ExpectedResourceID != "" || spec.ExpectedResourceCreatedAt != "" {
		return plan, fmt.Errorf("capacity creation cannot supply a destroy identity")
	}
	var err error
	plan.CanonicalSpec, err = canonicalMutationProjection(*spec)
	if err != nil {
		return plan, err
	}
	plan.RequestSHA256 = fmt.Sprintf("%x", sha256.Sum256(plan.CanonicalSpec))
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = "", ""
	spec.Capability = b.EnsureCapability
	base, err := canonicalMutationProjection(*spec)
	if err != nil {
		return plan, err
	}
	wanted := fmt.Sprintf("%x", sha256.Sum256(base))
	for _, slot := range b.Slots {
		if slot.Slot == plan.Slot && slot.DesiredSpecSHA256 == wanted {
			return plan, nil
		}
	}
	return plan, fmt.Errorf("capacity mutation desired spec is not the operator-approved slot revision")
}

var mutationProjectionSchemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func canonicalMutationProjection(spec model.CapacityMutationSpecV1) ([]byte, error) {
	// Select the closed contract explicitly. Do not serialize generic workflow
	// metadata or an entire deserialized container into an authority digest.
	fields := map[string]any{
		"schema_version":          spec.SchemaVersion,
		"capability":              spec.Capability,
		"integration_instance_id": spec.IntegrationInstanceID,
		"scope_checksum":          spec.ScopeChecksum,
		"profile_checksum":        spec.ProfileChecksum,
		"admission_checksum":      spec.AdmissionChecksum,
		"profile_name":            spec.ProfileName,
		"slot":                    spec.Slot,
		"native_name":             spec.NativeName,
		"bootstrap_sha256":        spec.BootstrapSHA256,
	}
	if spec.ExpectedResourceID != "" {
		fields["expected_resource_id"] = spec.ExpectedResourceID
	}
	if spec.ExpectedResourceCreatedAt != "" {
		fields["expected_resource_created_at"] = spec.ExpectedResourceCreatedAt
	}
	return json.Marshal(fields)
}
