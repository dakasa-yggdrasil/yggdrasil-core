package repository

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Pure predicate only: the gate also requires the immutable admission row of
// that exact disposal and the compiled approval of the binding.
func TestFailedInstalledExternalCauseBindingAdmittedIsExact(t *testing.T) {
	r := FailedInstalledGuestDisposal{BlockedGuestSource: strings.Repeat("b", 40), BlockedProfileSHA256: strings.Repeat("c", 64), RetirementMode: failedInstalledV2Mode}
	// The stored binding_wire is closed Guest lifecycle JSON: arrays are never
	// null, so the minimal profile manifest carries an empty writer list.
	b := model.CapacityGuestRetirementBinding{GuestSourceCommit: r.BlockedGuestSource, ProfileManifestSHA256: r.BlockedProfileSHA256, CoreAuthoritySourceCommit: strings.Repeat("4", 40),
		ProfileManifest: model.CapacityGuestProtectedProfileManifest{Writers: []model.CapacityGuestProtectedWriterDefinition{}},
		Members:         []model.CapacityGuestRetirementMemberBinding{{Name: "notify-hetzner-1", Slot: 1}}}
	wire, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.CapacityGuestRetirementBinding
	if err = capacity.DecodeGuestLifecycle(wire, &decoded); err != nil {
		t.Fatal("fixture binding is not closed Guest lifecycle JSON", err)
	}
	admitted := originalDispositionDigest(wire)
	if admitted != capacity.GuestRetirementSHA(b) {
		t.Fatal("stored binding_wire digest differs from the canonical binding digest")
	}
	if !failedInstalledExternalCauseBindingAdmitted(&b, r, admitted, wire) {
		t.Fatal("exact admitted unchanged binding refused")
	}
	if failedInstalledExternalCauseBindingAdmitted(nil, r, admitted, wire) || failedInstalledExternalCauseBindingAdmitted(&b, r, "", wire) || failedInstalledExternalCauseBindingAdmitted(&b, r, strings.ToUpper(admitted), wire) ||
		failedInstalledExternalCauseBindingAdmitted(&b, r, admitted, nil) {
		t.Fatal("missing binding, wire or malformed digest admitted")
	}
	// A digest that is not the SHA-256 of the disposed Guest's own stored
	// binding_wire never admits, even when it names this very binding.
	other := b
	other.Members = []model.CapacityGuestRetirementMemberBinding{{Name: "notify-hetzner-1", Slot: 3}}
	otherWire, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if failedInstalledExternalCauseBindingAdmitted(&b, r, admitted, otherWire) || failedInstalledExternalCauseBindingAdmitted(&b, r, originalDispositionDigest(otherWire), wire) ||
		failedInstalledExternalCauseBindingAdmitted(&other, r, admitted, wire) {
		t.Fatal("a digest other than the disposed binding_wire digest admitted")
	}
	marked := r
	marked.ReplacementMode = FailedInstalledCoreReplacementMode
	if failedInstalledExternalCauseBindingAdmitted(&b, marked, admitted, wire) {
		t.Fatal("Core-bound disposal admitted through the external-cause lane")
	}
	for name, edit := range map[string]func(*model.CapacityGuestRetirementBinding){
		"source":    func(x *model.CapacityGuestRetirementBinding) { x.GuestSourceCommit = strings.Repeat("d", 40) },
		"profile":   func(x *model.CapacityGuestRetirementBinding) { x.ProfileManifestSHA256 = strings.Repeat("e", 64) },
		"authority": func(x *model.CapacityGuestRetirementBinding) { x.CoreAuthoritySourceCommit = strings.Repeat("5", 40) },
		"member": func(x *model.CapacityGuestRetirementBinding) {
			x.Members = []model.CapacityGuestRetirementMemberBinding{{Name: "notify-hetzner-1", Slot: 2}}
		},
	} {
		y := b
		edit(&y)
		if failedInstalledExternalCauseBindingAdmitted(&y, r, admitted, wire) {
			t.Fatal("a binding other than the admitted one was accepted", name)
		}
	}
	for _, evidence := range []string{"", " ", strings.Repeat("x", FailedInstalledExternalCauseEvidenceMax+1), "nul\x00", "bell\a", "del\x7f", string([]byte{0xc3})} {
		if ValidFailedInstalledExternalCauseEvidence(evidence) {
			t.Fatal("invalid evidence accepted", len(evidence))
		}
	}
	for _, evidence := range []string{"RabbitMQ user lacked read on notify.guest-canary.*\r\n\tfixed 07:20Z", strings.Repeat("é", FailedInstalledExternalCauseEvidenceMax/2)} {
		if !ValidFailedInstalledExternalCauseEvidence(evidence) {
			t.Fatal("valid evidence refused", len(evidence))
		}
	}
}
