//go:build linux && nativequalification

package message

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestSourceNativeReadoptionUsesCanonicalApprovedPlan(t *testing.T) {
	spec := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: "ensure_vm", IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("a", 64), ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), ProfileName: "base", Slot: 2, NativeName: "node-2", BootstrapSHA256: strings.Repeat("d", 64)}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The authority digest is the canonical sorted closed map, not struct order.
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture decode")
	}
	canonical, _ := json.Marshal(fields)
	sum := sha256.Sum256(canonical)
	b := model.CapacityMutationBinding{Name: "fleet", IntegrationInstanceID: spec.IntegrationInstanceID, ScopeChecksum: spec.ScopeChecksum, ProfileName: spec.ProfileName, MaxSlots: 2, EnsureCapability: "ensure_vm", DestroyCapability: "destroy_vm", Slots: []model.CapacityMutationSlotBinding{{Slot: 2, DesiredSpec: &spec, DesiredSpecSHA256: fmt.Sprintf("%x", sum)}}}
	p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{b}}
	plan, err := capacity.PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
	if err != nil {
		t.Fatal("approved create", err)
	}
	if capacity.BusinessCreationSHA256(raw) == plan.RequestSHA256 {
		t.Fatal("fixture does not expose encoding mismatch")
	}
	proof := model.CapacityMutationProof{BindingName: b.Name, Slot: 2, RequestSHA256: plan.RequestSHA256}
	got, err := sourceNativeReadoptionDesired(p, b, proof)
	if err != nil || string(got) != string(raw) {
		t.Fatal("canonical original was refused", err)
	}
	for _, bad := range []model.CapacityMutationProof{{BindingName: "other", Slot: 2, RequestSHA256: plan.RequestSHA256}, {BindingName: b.Name, Slot: 1, RequestSHA256: plan.RequestSHA256}, {BindingName: b.Name, Slot: 2, RequestSHA256: capacity.BusinessCreationSHA256(raw)}} {
		if _, err := sourceNativeReadoptionDesired(p, b, bad); err == nil {
			t.Fatal("foreign original projection accepted")
		}
	}
	changed := spec
	changed.NativeName = "changed"
	changedB := b
	changedB.Slots = append([]model.CapacityMutationSlotBinding(nil), b.Slots...)
	changedB.Slots[0].DesiredSpec = &changed
	if _, err := sourceNativeReadoptionDesired(p, changedB, proof); err == nil {
		t.Fatal("unapproved desired projection accepted")
	}
}

func TestSourceRecoveryCleanupObservedEpochIgnoresRedactedLease(t *testing.T) {
	expiry := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	// Observe always returns the owner and executor blanked.
	current := model.CapacityIntent{Generation: 2, FencingToken: 4, RecoveryOnly: true, LeaseExpiresAt: &expiry}
	input := guestOriginalStepInput{Generation: 2, FencingToken: 4, LeaseOwner: uuid.NewString()}
	if !recoveryCleanupObservedEpoch(current, input) {
		t.Fatal("redacted observation refused the current step epoch")
	}
	for name, mutate := range map[string]func(*model.CapacityIntent, *guestOriginalStepInput){
		"not_recovery": func(c *model.CapacityIntent, _ *guestOriginalStepInput) { c.RecoveryOnly = false },
		"generation":   func(_ *model.CapacityIntent, i *guestOriginalStepInput) { i.Generation = 1 },
		"fence":        func(_ *model.CapacityIntent, i *guestOriginalStepInput) { i.FencingToken = 3 },
		"empty_owner":  func(_ *model.CapacityIntent, i *guestOriginalStepInput) { i.LeaseOwner = "" },
	} {
		c, i := current, input
		mutate(&c, &i)
		if recoveryCleanupObservedEpoch(c, i) {
			t.Fatalf("observed epoch accepted: %s", name)
		}
	}
}

// The actual call sites, not synthetic refusals, name the scope, preregistration
// and Realm case stages; the public error text stays the generic step error.
func TestSourceRecoveryCleanupStepNamesCallSiteStage(t *testing.T) {
	old := originalGuestNativeRealm
	t.Cleanup(func() { originalGuestNativeRealm = old })
	const native = "canonical_compensation_protected_failed_create"
	p := model.CapacityPolicySpec{GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "native_qemu_qualification", ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: "qualification-original-echo-writer-v1"}}}
	input := guestOriginalStepInput{Slot: q.SourceFailureSlot(native), RequestID: "source_recovery_cleanup_v1", Generation: 2, FencingToken: 4, LeaseOwner: uuid.NewString()}
	step := func() error {
		_, err := sourceGuestRecoveryCleanupStep(context.Background(), repository.CapacityStore{}, model.Manifest{}, p, input, "capacity.qualify_original_guest_echo")
		return err
	}
	refused := func(err error, stage string) bool {
		return err != nil && err.Error() == "protected original Guest qualification unavailable" && capacity.GuestQualificationPredicate(err) == "original-recovery-cleanup-"+stage && !strings.Contains(err.Error(), input.LeaseOwner)
	}
	originalGuestNativeRealm = nil
	if !refused(step(), "scope") {
		t.Fatal("missing realm not refused at scope")
	}
	originalGuestNativeRealm = &q.Realm{Request: q.SourceRequest{NativeCase: "positive_original_lifecycle"}}
	if !refused(step(), "scope") {
		t.Fatal("non-canonical case not refused at scope")
	}
	realm := &q.Realm{Request: q.SourceRequest{NativeCase: native}}
	originalGuestNativeRealm = realm
	if !refused(step(), "preregistration") {
		t.Fatal("absent preregistration not refused at preregistration")
	}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Slot: input.Slot, WorkflowID: uuid.Nil.String()}
	if !refused(realm.PrepareOriginalRecoveryCleanupRead(context.Background(), repository.CapacityStore{}, model.Manifest{}, pre, nil, input.Generation, input.FencingToken, input.LeaseOwner), "case") {
		t.Fatal("missing client not refused at the Realm case stage")
	}
}
