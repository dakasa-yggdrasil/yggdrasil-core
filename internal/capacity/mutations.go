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
		resource := strings.TrimPrefix(b.EnsureCapability, "ensure_")
		if !mutationProjectionSchemaPattern.MatchString(resource) || b.DestroyCapability != "destroy_"+resource {
			return fmt.Errorf("capacity mutation capabilities require one canonical resource pair")
		}
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
			if _, err := approvedMutationProjection(b, slot); err != nil {
				return err
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
	return ValidateVMNodeMembershipBinding(p)
}

const ObserveNodeMembership = "observe_capacity_node_membership"

func ValidateVMNodeMembershipBinding(p model.CapacityPolicySpec) error {
	n := p.VMNodeMembershipBinding
	if n == nil {
		return nil
	}
	if p.AssessmentBinding != nil || p.HPAExecutionBinding != nil || !validObservationAdapter(n.Adapter) {
		return fmt.Errorf("VM node source requires a separate exact native VM binding")
	}
	var b *model.CapacityMutationBinding
	for i := range p.MutationBindings {
		if p.MutationBindings[i].Name == n.MutationBindingName {
			b = &p.MutationBindings[i]
		}
	}
	t := n.Target
	realm, err := uuid.Parse(t.RealmUID)
	if b == nil || b.EnsureCapability != "ensure_server" || b.MaxSlots < 1 || b.MaxSlots > 64 || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`).MatchString(t.BindingName) || err != nil || realm == uuid.Nil || realm.String() != t.RealmUID || t.Owner != p.Owner || !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`).MatchString(t.Owner) || t.ProfileName != b.ProfileName || !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`).MatchString(t.ProfileName) || len(t.Slots) != b.MaxSlots || t.MaxLeaseAgeSeconds < 1 || t.MaxLeaseAgeSeconds > 60 || t.ProviderIDPrefix == "" || len(t.ProviderIDPrefix) > 128 || strings.TrimSpace(t.ProviderIDPrefix) != t.ProviderIDPrefix || strings.ContainsAny(t.ProviderIDPrefix, "\r\n\t ?#") {
		return fmt.Errorf("fixed VM and node realms or slots differ")
	}
	seen := map[string]bool{}
	for i, s := range t.Slots {
		if s.Slot != i+1 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`).MatchString(s.NodeName) || seen[s.NodeName] {
			return fmt.Errorf("bounded approved native node names required")
		}
		for _, label := range strings.Split(s.NodeName, ".") {
			if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(label) {
				return fmt.Errorf("canonical native Node DNS labels required")
			}
		}
		seen[s.NodeName] = true
	}
	return nil
}

// Join only independently observed native tuples. No healthy transition proof
// or useful count is constructed from Node Ready or the lease heartbeat.
func JoinVMNodeMembership(p model.CapacityPolicySpec, inv model.CapacityVMFleetInventory, nodes model.CapacityNodeMembershipResponse, now time.Time) ([]model.CapacityVMNodeJoin, error) {
	if ValidateVMNodeMembershipBinding(p) != nil || p.VMNodeMembershipBinding == nil {
		return nil, fmt.Errorf("fixed native node binding unavailable")
	}
	n := p.VMNodeMembershipBinding
	b, err := VMObservationBinding(p, n.MutationBindingName)
	if err != nil {
		return nil, err
	}
	proofs, err := VMInventoryProofs(p, b, inv, "", 0, now, "core-native-node-membership")
	if err != nil || len(proofs) != len(inv.Members) || inv.FailedCreation != nil {
		return nil, fmt.Errorf("ordinary complete VM membership required")
	}
	rawTarget, _ := json.Marshal(n.Target)
	d := sha256.Sum256(rawTarget)
	if nodes.Operation != ObserveNodeMembership || nodes.Status != "observed" || !nodes.Complete || nodes.BindingName != n.Target.BindingName || nodes.BindingSHA256 != hex.EncodeToString(d[:]) || nodes.RealmUID != n.Target.RealmUID || nodes.Owner != p.Owner || nodes.ProfileName != b.ProfileName || nodes.NativeNodeCount < len(nodes.Nodes) || nodes.NativeNodeCount > 64 || nodes.FirstListVersion == "" || nodes.LastListVersion == "" || !ValidDigest(nodes.FirstListSHA256) || !ValidDigest(nodes.LastListSHA256) || nodes.ObservationStartedAt.IsZero() || nodes.ObservationStartedAt.After(nodes.ObservedAt) || nodes.ObservedAt.After(now) || nodes.ObservedAt.Sub(nodes.ObservationStartedAt) > 60*time.Second || !Fresh(nodes.ObservationStartedAt, now, min(60, p.MaxEvidenceAgeSeconds)) || !Fresh(nodes.ObservedAt, now, min(60, p.MaxEvidenceAgeSeconds)) || nodes.AtomicSnapshot || nodes.BootstrapCompleted || nodes.WarmResources || nodes.UsefulCapacity || nodes.RoutingWithdrawn || nodes.BusinessDrain || nodes.PhysicalReleased || len(nodes.Nodes) != len(inv.Members) || len(nodes.Metadata) != 1 || nodes.Metadata["diagnostic_only"] != true {
		return nil, fmt.Errorf("closed fresh native membership diagnostic required")
	}
	bySlot := map[int]model.CapacityVMFleetInventoryMember{}
	for _, member := range inv.Members {
		if member.Unresolved || member.Server.Status != "running" || member.Server.Labels["yggdrasil.io/owner"] != n.Target.Owner {
			return nil, fmt.Errorf("original VM is not a known running lifetime")
		}
		bySlot[member.Slot] = member
	}
	seenUID, seenSlot, seenProvider := map[string]bool{}, map[int]bool{}, map[string]bool{}
	joins := make([]model.CapacityVMNodeJoin, 0, len(nodes.Nodes))
	lastSlot := 0
	for _, node := range nodes.Nodes {
		member, found := bySlot[node.Slot]
		created, createdErr := time.Parse(time.RFC3339Nano, member.Server.CreatedAt)
		id, uidErr := uuid.Parse(node.UID)
		boot, bootErr := uuid.Parse(node.BootID)
		lease, leaseErr := uuid.Parse(node.LeaseUID)
		if !found || node.Slot <= lastSlot || createdErr != nil || node.Slot < 1 || node.Slot > len(n.Target.Slots) || node.Name != n.Target.Slots[node.Slot-1].NodeName || node.ProviderID != n.Target.ProviderIDPrefix+member.Server.ID || uidErr != nil || id == uuid.Nil || id.String() != node.UID || bootErr != nil || boot == uuid.Nil || boot.String() != node.BootID || leaseErr != nil || lease == uuid.Nil || lease.String() != node.LeaseUID || node.ResourceVersion == "" || node.CreatedAt.IsZero() || node.CreatedAt.Before(created) || node.CreatedAt.After(now) || !node.ReadyKnown || node.ReadyChangedAt.IsZero() || node.ReadyChangedAt.Before(node.CreatedAt) || node.ReadyChangedAt.After(now) || node.LeaseDurationSeconds < 1 || node.LeaseDurationSeconds > 300 || !now.Before(node.LeaseRenewedAt.Add(time.Duration(node.LeaseDurationSeconds)*time.Second)) || node.LeaseVersion == "" || node.LeaseHolder != node.Name || node.LeaseRenewedAt.IsZero() || node.LeaseRenewedAt.Before(node.CreatedAt) || node.LeaseRenewedAt.After(now) || node.LeaseRenewedAt.After(nodes.ObservedAt) || node.ReadyChangedAt.After(nodes.ObservedAt) || node.CreatedAt.After(nodes.ObservedAt) || now.Sub(node.LeaseRenewedAt) > time.Duration(n.Target.MaxLeaseAgeSeconds)*time.Second || seenUID[node.UID] || seenSlot[node.Slot] || seenProvider[node.ProviderID] {
			return nil, fmt.Errorf("original VM and immutable native Node or Lease do not join")
		}
		lastSlot = node.Slot
		seenUID[node.UID], seenSlot[node.Slot], seenProvider[node.ProviderID] = true, true, true
		joins = append(joins, model.CapacityVMNodeJoin{Slot: member.Slot, ResourceID: member.Server.ID, ResourceCreatedAt: member.Server.CreatedAt, DesiredSpecSHA256: member.RequestSHA256, Node: node})
	}
	return joins, nil
}

type MutationPlan struct {
	Binding                   model.CapacityMutationBinding
	Capability                string
	Slot                      int
	RequestSHA256             string
	ExpectedResourceID        string
	ExpectedResourceCreatedAt string
	CanonicalSpec             []byte
	ApprovedSpec              model.CapacityMutationSpecV1
}

// PrepareMutationPlan binds a provider's dry-run projection to an operator slot
// digest. Core never constructs SDK payloads or learns credential/bootstrap data.
func PrepareMutationPlan(p model.CapacityPolicySpec, issue model.CapacityMutationIssue) (MutationPlan, error) {
	return prepareMutationPlan(p, issue, false)
}

// A compensation still uses the approved destroy projection and immutable
// tuple. Only its separate durable parent authority can relax a protected slot.
func PrepareCompensationPlan(p model.CapacityPolicySpec, issue model.CapacityMutationIssue) (MutationPlan, error) {
	return prepareMutationPlan(p, issue, true)
}

func prepareMutationPlan(p model.CapacityPolicySpec, issue model.CapacityMutationIssue, compensation bool) (MutationPlan, error) {
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
	if d.Decode(new(any)) != io.EOF {
		return plan, fmt.Errorf("capacity mutation desired spec requires one closed object")
	}
	if spec.Capability == "start_ec2_instance" || spec.Capability == "stop_ec2_instance" {
		return plan, ErrPowerLifecycleUnqualified
	}
	if !validMutationProjection(*spec) {
		return plan, fmt.Errorf("capacity mutation desired spec requires a bounded closed non-secret projection")
	}
	if spec.IntegrationInstanceID != b.IntegrationInstanceID || spec.ScopeChecksum != b.ScopeChecksum || spec.ProfileName != b.ProfileName {
		return plan, fmt.Errorf("capacity mutation desired spec identity mismatch")
	}
	plan.Capability = spec.Capability
	if plan.Capability != b.EnsureCapability && plan.Capability != b.DestroyCapability {
		return plan, fmt.Errorf("capacity mutation capability is not approved")
	}
	if compensation && (!b.CompensationEnabled || plan.Capability != b.DestroyCapability) {
		return plan, fmt.Errorf("capacity compensation requires an explicitly enabled destroy binding")
	}
	plan.Slot = spec.Slot
	if plan.Slot < 1 || plan.Slot > b.MaxSlots {
		return plan, fmt.Errorf("capacity mutation slot is outside the approved envelope")
	}
	plan.ExpectedResourceID = spec.ExpectedResourceID
	plan.ExpectedResourceCreatedAt = spec.ExpectedResourceCreatedAt
	if plan.Capability == b.DestroyCapability {
		if (!compensation && plan.Slot <= b.ProtectedSlots) || plan.ExpectedResourceID == "" || len(plan.ExpectedResourceID) > 128 {
			return plan, fmt.Errorf("capacity destruction requires an unprotected immutable resource")
		}
		created, err := time.Parse(time.RFC3339Nano, plan.ExpectedResourceCreatedAt)
		if err != nil || created.IsZero() {
			return plan, fmt.Errorf("capacity destruction requires immutable creation time")
		}
	} else if spec.ExpectedResourceID != "" || spec.ExpectedResourceCreatedAt != "" {
		return plan, fmt.Errorf("capacity creation cannot supply a destroy identity")
	}
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = "", ""
	spec.Capability = b.EnsureCapability
	for _, slot := range b.Slots {
		if slot.Slot == plan.Slot {
			approved, err := approvedMutationProjection(b, slot)
			if err != nil {
				return plan, err
			}
			if *spec != *slot.DesiredSpec {
				return plan, fmt.Errorf("capacity mutation desired spec is not the operator-approved slot revision")
			}
			plan.ApprovedSpec = *slot.DesiredSpec
			plan.CanonicalSpec = approved
			if plan.Capability == b.EnsureCapability {
				plan.RequestSHA256 = slot.DesiredSpecSHA256
			}
			return plan, nil
		}
	}
	return plan, fmt.Errorf("capacity mutation desired spec is not the operator-approved slot revision")
}

var mutationProjectionSchemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var mutationNativeNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var mutationProfileNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func validMutationProjection(spec model.CapacityMutationSpecV1) bool {
	return spec.SchemaVersion == "capacity_vm_slot_v1" && mutationNativeNamePattern.MatchString(spec.NativeName) && mutationProfileNamePattern.MatchString(spec.ProfileName) && ValidDigest(spec.ProfileChecksum) && ValidDigest(spec.AdmissionChecksum) && ValidDigest(spec.BootstrapSHA256)
}

func approvedMutationProjection(b model.CapacityMutationBinding, slot model.CapacityMutationSlotBinding) ([]byte, error) {
	spec := slot.DesiredSpec
	if spec == nil || !validMutationProjection(*spec) || spec.Capability != b.EnsureCapability || spec.IntegrationInstanceID != b.IntegrationInstanceID || spec.ScopeChecksum != b.ScopeChecksum || spec.ProfileName != b.ProfileName || spec.Slot != slot.Slot || spec.ExpectedResourceID != "" || spec.ExpectedResourceCreatedAt != "" {
		return nil, fmt.Errorf("capacity mutation slot requires its exact closed approved ensure projection")
	}
	raw, err := canonicalMutationProjection(*spec)
	if err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != slot.DesiredSpecSHA256 {
		return nil, fmt.Errorf("capacity mutation approved projection digest mismatch")
	}
	return raw, nil
}

// BindMutationDestroyPlan is called only after the store has loaded its exact
// immutable slot tuple under the native-slot lock. The runtime tuple must match
// but never supplies bytes for the authoritative request digest.
func BindMutationDestroyPlan(plan MutationPlan, resourceID, createdAt string) (MutationPlan, error) {
	if plan.Capability != plan.Binding.DestroyCapability || resourceID == "" || resourceID != plan.ExpectedResourceID || createdAt != plan.ExpectedResourceCreatedAt {
		return plan, fmt.Errorf("capacity mutation destroy identity does not match registered membership")
	}
	spec := plan.ApprovedSpec
	spec.Capability = plan.Binding.DestroyCapability
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = resourceID, createdAt
	raw, err := canonicalMutationProjection(spec)
	if err != nil {
		return plan, err
	}
	plan.CanonicalSpec = raw
	plan.RequestSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	return plan, nil
}

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
