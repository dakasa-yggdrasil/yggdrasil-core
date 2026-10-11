package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestCapacityMutationFailedFloorRecoveryPostgres(t *testing.T) {
	ctx := context.Background()
	f := mutationPostgresFixtureWithBaseline(t, true, 3, 2)
	if f.intent.Decision.Reason != "protected_floor_recovery" || f.intent.Decision.Units != 3 || f.intent.BaselineSnapshot.Units != 2 {
		t.Fatal("fixture did not admit exact floor repair", f.intent)
	}
	parent := f.issue(t, 3)
	// The reserved third slot prevents another create from replacing ambiguous
	// native work. Cleanup will remove no registered member from the two-node base.
	if _, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[4]); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("ambiguous failed create lost its target reservation", err)
	}
	nonce := uuid.NewString()
	redemption := mutationRedeem(parent, nonce)
	if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redemption); err != nil {
		t.Fatal(err)
	}
	settled := mutationSettlement(redemption, f.created)
	if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settled); err != nil {
		t.Fatal(err)
	}
	failed := f.proof(t, 3)
	failed.GrantID, failed.ResourceCreatedAt, failed.ObservedCreationGrantID = parent.GrantID, settled.ResourceCreatedAt, parent.GrantID
	failed.ActionsTerminal, failed.ActionsFailed, failed.SpecVerified, failed.CompensationIdentityVerified = true, true, false, true
	failed.ActionIDs = []string{"native-action", "bootstrap-action"}
	var desired model.CapacityMutationSpecV1
	if err := json.Unmarshal(f.plans[3].DesiredSpec, &desired); err != nil {
		t.Fatal(err)
	}
	desired.Capability, desired.ExpectedResourceID, desired.ExpectedResourceCreatedAt = f.binding.DestroyCapability, settled.ResourceID, settled.ResourceCreatedAt
	rawDesired, _ := json.Marshal(desired)
	zero := 0
	drain := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 2), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:failed-third-never-routed", Healthy: true, MembershipComplete: true, AdmissionClosed: true, RoutingWithdrawn: true, Inflight: &zero, NativeActionsInflight: &zero}
	issue := model.CapacityCompensationIssue{ParentGrantID: parent.GrantID, Mutation: model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: rawDesired}, FailedProof: failed, DrainProof: drain}
	expireCapacityTestLease(t, f.db, f.policy.Metadata.Namespace)
	recovery := f.store
	recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
	lease, err := recovery.Recover(ctx, f.policy, f.intent.Generation, freshCapacityTestAssessment(f.a, 2))
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(f.policy.Spec, &p); err != nil {
		t.Fatal(err)
	}
	p.MutationBindings[0].CompensationEnabled = true
	raw, _ := json.Marshal(p)
	current, err := CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: f.policy.APIVersion, Kind: f.policy.Kind, Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.store
	issuer.ExecutorID = uuid.NewString()
	for _, scenario := range []string{"baseline_lost", "incomplete", "wrong_profile", "native_running", "business_running"} {
		bad := issue
		switch scenario {
		case "baseline_lost":
			bad.DrainProof.Assessment.Snapshot.Units = 1
		case "incomplete":
			bad.DrainProof.MembershipComplete = false
		case "wrong_profile":
			bad.DrainProof.Assessment.Snapshot.Profile = "alternate"
		case "native_running":
			one := 1
			bad.DrainProof.NativeActionsInflight = &one
		case "business_running":
			one := 1
			bad.DrainProof.Inflight = &one
		}
		if _, err := issuer.IssueCompensation(ctx, current, bad); err == nil {
			t.Fatal("degraded cleanup bypassed unchanged healthy baseline", scenario)
		}
	}
	terminal := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 2), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:degraded-floor-readback", Healthy: true, MembershipComplete: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants"}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("unresolved parent became closed failed repair", err)
	}
	child, err := issuer.IssueCompensation(ctx, current, issue)
	if err != nil || child.ExpectedResourceID != settled.ResourceID || child.CompensationOf != parent.GrantID {
		t.Fatal("failed protected slot could not be cleaned without removing baseline", child, err)
	}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("unresolved cleanup child released failed repair", err)
	}
	childNonce := uuid.NewString()
	childRedemption := mutationRedeem(child, childNonce)
	if permission, err := issuer.RedeemMutation(ctx, f.binding.AdapterPrincipalID, childRedemption); err != nil || permission.Mode != "write_once" {
		t.Fatal("separate cleanup gate could not redeem belowfloor baseline", permission, err)
	}
	if _, err := issuer.SettleMutation(ctx, f.binding.AdapterPrincipalID, childNonce, mutationSettlement(childRedemption, settled.ResourceCreatedAt)); err != nil {
		t.Fatal(err)
	}
	deleted := failed
	deleted.GrantID, deleted.RequestSHA256 = child.GrantID, child.RequestSHA256
	deleted.ActionsSuccessful, deleted.ActionsFailed, deleted.ResourceAbsent = true, false, true
	deleted.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture"}}
	if _, err := issuer.ConfirmCompensation(ctx, current, deleted); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"baseline_lost", "incomplete", "wrong_profile", "no_mutation"} {
		bad := terminal
		switch scenario {
		case "baseline_lost":
			bad.Assessment.Snapshot.Units = 1
		case "incomplete":
			bad.MembershipComplete = false
		case "wrong_profile":
			bad.Assessment.Snapshot.Profile = "alternate"
		case "no_mutation":
			bad.NoMutationVerified = true
		}
		if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", bad); err == nil {
			t.Fatal("failed floor readback accepted invalid outcome", scenario)
		}
	}
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", terminal); err == nil {
		t.Fatal("ordinary partial recovery claimed protected floor below3")
	}
	terminal.NoMutationVerified = true
	if _, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "aborted", terminal); err == nil {
		t.Fatal("compensated floor repair became no-mutation abort")
	}
	terminal.NoMutationVerified = false
	finished, err := recovery.Reconcile(ctx, f.policy, lease.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_failed_floor", terminal)
	if err != nil || finished.Phase != "reconciled_failed_floor" || !finished.FloorDegraded || finished.Assessment.Snapshot.Units != 2 || finished.Decision.Units != 3 || finished.Decision.ExecutionPermitted || finished.LeaseOwner != "" {
		t.Fatal("failed floor did not close truthfully", finished, err)
	}
	// The next explicit floor repair bypasses ordinary cooldown without turning
	// the closed historical recovery epoch back into write authority.
	nextStore := issuer
	nextStore.ExecutorID = uuid.NewString()
	next, err := nextStore.Assess(ctx, current, freshCapacityTestAssessment(f.a, 2))
	if err != nil || next.Generation != lease.Generation+1 || next.Decision.Reason != "protected_floor_recovery" || next.Decision.Units != 3 || next.FloorDegraded {
		t.Fatal("failed floor deadlocked next independent repair", next, err)
	}
	next, err = nextStore.Claim(ctx, current, next.Generation, freshCapacityTestAssessment(f.a, 2))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := nextStore.IssueMutation(ctx, current, next.Generation, next.FencingToken, next.LeaseOwner, f.plans[3])
	if err != nil || replacement.GrantID == parent.GrantID || replacement.CompensationOf != "" {
		t.Fatal("new floor repair could not reserve a fresh create", replacement, err)
	}
}
