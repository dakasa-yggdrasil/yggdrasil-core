package repository

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Real PostgreSQL refusal, not a synthetic production approval or a native
// useful-membership claim. An actual legacy intent/lease must remain unchanged
// when these source-only methods have no compiled, current Guest authority.
func TestOriginalGuestReconcilePostgresCannotInventAuthority(t *testing.T) {
	db, policy, assessment := capacityPostgresFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	legacy := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := legacy.Assess(ctx, policy, assessment)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = legacy.Claim(ctx, policy, intent.Generation, assessment)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (string, int, int) {
		t.Helper()
		var original string
		var events, grants int
		if e := db.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&original); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&events); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&grants); e != nil {
			t.Fatal(e)
		}
		return original, events, grants
	}
	before, eventCount, grantCount := read()
	for _, name := range []string{"absent_source", "foreign_source", "uncompiled_graph", "caller_complete", "caller_refresh"} {
		t.Run(name, func(t *testing.T) {
			store := legacy
			if name != "absent_source" {
				source := capacity.CurrentGuestCoreSource()
				if name == "foreign_source" {
					source = "ffffffffffffffffffffffffffffffffffffffff"
				}
				step := model.WorkflowStepSpec{ID: "invented", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.CompleteOriginalGuestOperation}, TimeoutSeconds: 90}
				mode := "provision"
				if name == "caller_refresh" {
					mode = "refresh"
				}
				store = store.WithOriginalGuestReconcile(model.Manifest{ID: uuid.New()}, step, source, mode, uuid.NewString(), model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
			}
			if _, _, e := store.OriginalGuestReconcileMembers(ctx, policy); e == nil {
				t.Fatal("native membership invented")
			}
			if _, e := store.AssessOriginalGuest(ctx, policy, assessment); e == nil {
				t.Fatal("caller replaced original intent")
			}
			if _, e := store.AdvanceOriginalGuest(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "promoted", assessment); e == nil {
				t.Fatal("caller certified readiness")
			}
			if _, e := store.OriginalGuestReconcileLeaseDeadline(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner); e == nil {
				t.Fatal("caller installed an original owner")
			}
			after, events, grants := read()
			if after != before || events != eventCount || grants != grantCount {
				t.Fatal("refused source changed durable intent/events/grants")
			}
		})
	}
	var retained model.CapacityIntent
	if json.Unmarshal([]byte(before), &retained) != nil || retained.LeaseOwner != intent.LeaseOwner || retained.Phase != intent.Phase {
		t.Fatal("actual legacy lease was not retained")
	}
}

// A genuine generic zero-to-one floor plan and claim are not the new protected
// source authority. PostgreSQL must retain that SAME original lease and intent
// when a caller supplies a completion opcode or a reporting-shaped object.
func TestOriginalGuestReconcilePostgresFloorBootstrapCannotInventAuthority(t *testing.T) {
	db, policy, assessment := capacityPostgresFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil {
		t.Fatal("fixture policy")
	}
	p.Floor, p.Step, p.Profiles[0].MinUnits = 1, 1, 1
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name}, Spec: raw}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	assessment.Snapshot.Units, assessment.Evidence = 0, nil
	legacy := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorID: uuid.NewString()}
	intent, err := legacy.Assess(ctx, policy, assessment)
	if err != nil || intent.Decision.Reason != "protected_floor_recovery" || intent.Decision.Units != 1 {
		t.Fatal("actual generic floor proposal", err)
	}
	intent, err = legacy.Claim(ctx, policy, intent.Generation, assessment)
	if err != nil || intent.BaselineSnapshot.Units != 0 || intent.LeaseOwner == "" {
		t.Fatal("actual generic floor claim", err)
	}
	read := func() (string, int, int) {
		t.Helper()
		var original string
		var events, grants int
		if e := db.QueryRowContext(ctx, `SELECT intent::text FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&original); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&events); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&grants); e != nil {
			t.Fatal(e)
		}
		return original, events, grants
	}
	before, eventCount, grantCount := read()
	assessment.Snapshot.Units = 1
	for _, name := range []string{"absent_source", "invented_complete", "foreign_source", "retirement_mode", "expired_owner"} {
		t.Run(name, func(t *testing.T) {
			store := legacy
			callCtx := ctx
			if name != "absent_source" {
				source, mode := capacity.CurrentGuestCoreSource(), "provision"
				if name == "foreign_source" {
					source = "ffffffffffffffffffffffffffffffffffffffff"
				}
				if name == "retirement_mode" {
					mode = "retire"
				}
				if name == "expired_owner" {
					callCtx = guestReconcileDelayedCancellation{ctx, time.Now().Add(-time.Second)}
				}
				step := model.WorkflowStepSpec{ID: "complete-original-provision", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.CompleteOriginalGuestOperation}, TimeoutSeconds: 90}
				store = store.WithOriginalGuestReconcile(model.Manifest{ID: uuid.New()}, step, source, mode, "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{OK: true, Reason: "complete"})
			}
			if _, e := store.AdvanceOriginalGuest(callCtx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, "prepared", assessment); e == nil {
				t.Fatal("generic floor or caller reporting became protected production authority")
			}
			after, events, grants := read()
			if after != before || events != eventCount || grants != grantCount {
				t.Fatal("refused first-floor completion changed actual lease, intent, events or grants")
			}
		})
	}
}
