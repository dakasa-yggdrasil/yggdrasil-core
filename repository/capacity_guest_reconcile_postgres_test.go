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
				store = store.WithOriginalGuestReconcile(model.Manifest{ID: uuid.New()}, step, source, mode, uuid.NewString(), model.CapacityVMFleetInventory{})
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
