//go:build recoveryfixture && !nativequalification

package capacity

import (
	"testing"
	"time"
)

func TestRecoveryFixtureSignedRegistrationV2(t *testing.T) {
	p, b, r, _ := recoveryRegistrationFixture(t, 0)
	w := r.Result.ProductionClock.Authority.CreateWitness
	if err := GuestOriginalRegistration(p, b, b.Members[0], w, r, w.ObservedAt.Add(20*time.Second)); err != nil {
		t.Fatal("fixture registration", err)
	}
}

func TestRecoveryFixtureSignedEnrollmentAndInstallationV2(t *testing.T) {
	recoveryInstalledFixture(t)
}

func TestRecoveryFixtureOneMemberInventoryShape(t *testing.T) {
	p, b, reg, _, _ := recoveryInstalledFixture(t)
	now := time.Now().UTC()
	mutation := p.MutationBindings[0]
	inv := RecoveryFixtureInventory(t, p, reg, now)
	if err := ValidateGuestNotifyReconcileBinding(p); err != nil {
		t.Fatal("source-shaped policy", err)
	}
	proofs, err := VMInventoryProofs(p, mutation, inv, "", 0, now, "fixture-only")
	if err != nil || len(proofs) != 1 {
		t.Fatal("fixture inventory", err)
	}
	if proofs[0].ResourceID != reg.Result.Tuple.ResourceID || b.GuestSourceCommit != "b50976579e128e9a418ae5209d2b2dfea0fc532b" {
		t.Fatal("fixture member changed")
	}
}

func TestRecoveryFixtureCausalPublicationAndRead(t *testing.T) {
	p, _, reg, receipt, _ := recoveryInstalledFixture(t)
	read, pub, _, transport := RecoveryFixtureCausal(t, p, reg, receipt, 2, "10000000-0000-4000-8000-000000000008", time.Now().UTC().Add(-6*time.Second))
	if transport.DriverReturnedAt.After(read.IssuedAt) || !GuestNotifyCausalPair(pub, read) {
		t.Fatal("fixture original causal pair lost")
	}
}
