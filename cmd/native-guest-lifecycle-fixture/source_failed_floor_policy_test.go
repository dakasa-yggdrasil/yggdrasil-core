//go:build linux && nativequalification

package main

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestStrongerSourceFloorPolicy(t *testing.T) {
	validUntil := time.Unix(1800000000, 0).UTC()
	before := model.CapacityPolicySpec{
		Environment: "qualification", Domain: "infrastructure", Dimension: "native_echo", TargetIdentity: "target", Owner: "owner",
		Workflow: model.ManifestSelector{Namespace: "scope", Name: "workflow"}, Currency: "USD", Floor: 1, Ceiling: 2, Step: 1,
		MaxEvidenceAgeSeconds: 30, MaxSampleGapSeconds: 5, MinSamples: 1, DownHoldSeconds: 1, LeaseSeconds: 300,
		Signals:  []model.CapacitySignalRule{{Name: "demand", SourceIdentity: "source", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}},
		Profiles: []model.CapacityProfile{{Name: "profile", Provider: "native-qemu", Region: "lab", MinUnits: 1, MaxUnits: 2, QuoteValidUntil: validUntil, ValidationValidUntil: validUntil, ValidationRef: "source"}},
	}
	if err := capacity.ValidatePolicy(before); err != nil {
		t.Fatalf("baseline must be valid: %v", err)
	}
	after, err := strongerSourceFloorPolicy(before)
	if err != nil || after.Floor != 2 || len(after.Profiles) != 1 || after.Profiles[0].MinUnits != 2 || capacity.ValidatePolicy(after) != nil {
		t.Fatalf("expected valid stronger policy, got %#v, %v", after, err)
	}
	if before.Floor != 1 || before.Profiles[0].MinUnits != 1 {
		t.Fatal("raising the floor mutated the original profile")
	}
	if capacity.GuestRetirementSHA(after.Profiles[0]) == capacity.GuestRetirementSHA(before.Profiles[0]) {
		t.Fatal("profile delta was not retained")
	}
	bad := before
	bad.Profiles = append([]model.CapacityProfile(nil), before.Profiles...)
	bad.Profiles[0].MaxUnits = 1
	if _, err := strongerSourceFloorPolicy(bad); err == nil {
		t.Fatal("wrong profile ceiling accepted")
	}
}
