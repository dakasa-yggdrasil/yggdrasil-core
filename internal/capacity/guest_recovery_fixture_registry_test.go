//go:build recoveryfixture && !nativequalification

package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestRecoveryFixtureApprovalIsExplicitAndSeparate(t *testing.T) {
	raw, err := os.ReadFile("testdata/b509-notify-hetzner-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var actual, fixture model.CapacityPolicySpec
	if DecodeNativeCapacity(json.RawMessage(raw), &actual) != nil || DecodeNativeCapacity(json.RawMessage(raw), &fixture) != nil {
		t.Fatal("source policy fixture")
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("u", 32)))
	fixture.GuestRetirementBinding.EnrollmentIssuerPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	originalFingerprint := GuestProtocolCompatibilityMapSHA256()
	if GuestBindingApprovedByCompatibilityMap(fixture, *fixture.GuestRetirementBinding, "2de33bbca46000d86a6dc0d5162383a6128e3517", originalFingerprint) {
		t.Fatal("test key adopted by real approvals")
	}
	t.Setenv("CAPACITY_RECOVERY_FIXTURE_ONLY", "true")
	prior := append([]guestProductionProfileApproval(nil), guestProductionProfileApprovals...)
	t.Cleanup(func() { guestProductionProfileApprovals = prior })
	if err = RegisterRecoveryFixtureApproval(fixture, *fixture.GuestRetirementBinding, "hetzner"); err != nil {
		t.Fatal(err)
	}
	fixtureFingerprint := GuestProtocolCompatibilityMapSHA256()
	if fixtureFingerprint == originalFingerprint {
		t.Fatal("fixture did not change approval data")
	}
	if !GuestBindingApprovedByCompatibilityMap(fixture, *fixture.GuestRetirementBinding, "2de33bbca46000d86a6dc0d5162383a6128e3517", fixtureFingerprint) {
		t.Fatal("fixture approval rejected")
	}
	if !GuestBindingApprovedByCompatibilityMap(actual, *actual.GuestRetirementBinding, "2de33bbca46000d86a6dc0d5162383a6128e3517", fixtureFingerprint) {
		t.Fatal("source approval removed")
	}
	if GuestBindingApprovedByCompatibilityMap(fixture, *fixture.GuestRetirementBinding, "2de33bbca46000d86a6dc0d5162383a6128e3517", originalFingerprint) {
		t.Fatal("fixture changed historical map")
	}
}
