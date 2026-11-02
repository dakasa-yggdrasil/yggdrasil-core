package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Real runtime-store/PG state and CAS tests. Synthetic storage operands below
// are not native Guest evidence: the public method still requires the complete
// signed original chain and poweroff, and is separately checked to refuse it.
func testGuestRetirementDrainedV2Postgres(t *testing.T, db *sql.DB, policy model.Manifest) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: uuid.New(), ExecutorID: uuid.NewString()}
	expires := time.Now().UTC().Add(time.Minute)
	old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 4, FencingToken: 7, Phase: "draining", LeaseOwner: uuid.NewString(), LeaseExecutorID: store.ExecutorID, LeaseExpiresAt: &expires, Decision: model.CapacityDecision{Action: "drain", Units: 2, Profile: "base"}, Assessment: model.CapacityAssessment{Snapshot: model.CapacitySnapshot{Units: 4, Profile: "base"}}, BaselineSnapshot: model.CapacitySnapshot{Units: 4, Profile: "base"}, UpdatedAt: time.Now().UTC()}
	stored := GuestRetirementOriginalV2{ExecutorID: store.ExecutorID}
	i := &stored.Request.Intent
	i.RequestID, i.PreregistrationID = uuid.NewString(), uuid.NewString()
	i.PolicyID, i.PolicyChecksum, i.WorkflowID = policy.ID.String(), policy.Checksum, store.WorkflowID.String()
	i.Generation, i.Fence, i.LeaseOwner, i.Slot = uint64(old.Generation), uint64(old.FencingToken), old.LeaseOwner, 4
	reset := func() {
		t.Helper()
		wire, e := json.Marshal(old)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, `DELETE FROM public.capacity_intent_events WHERE namespace=$1`, old.Namespace); e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,$6)ON CONFLICT(namespace,environment,domain,dimension)DO UPDATE SET intent=EXCLUDED.intent,updated_at=EXCLUDED.updated_at`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(wire), old.UpdatedAt); e != nil {
			t.Fatal(e)
		}
	}
	advance := func(commit bool) (model.CapacityIntent, error) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return model.CapacityIntent{}, e
		}
		defer tx.Rollback()
		if e = lockMutationScope(ctx, tx, old.Namespace, p); e != nil {
			return model.CapacityIntent{}, e
		}
		current, e := loadCapacityIntent(ctx, tx, old.Namespace, p, true)
		if e != nil {
			return model.CapacityIntent{}, e
		}
		var now time.Time
		if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return model.CapacityIntent{}, e
		}
		next, e := store.guestRetirementDrainedV2State(policy, p, current, stored, old.Generation, old.FencingToken, old.LeaseOwner, now.UTC())
		if e != nil {
			return next, e
		}
		if e = persistGuestRetirementDrainedV2Tx(ctx, tx, current, next, i.RequestID); e != nil {
			return next, e
		}
		if commit {
			e = tx.Commit()
		}
		return next, e
	}
	assertState := func(phase string, events int) model.CapacityIntent {
		t.Helper()
		current, e := loadCapacityIntent(ctx, db, old.Namespace, p, false)
		if e != nil || current.Phase != phase {
			t.Fatal("unexpected durable phase", current.Phase, e)
		}
		var count int
		if e = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1 AND phase='drained'`, old.Namespace).Scan(&count); e != nil || count != events {
			t.Fatal("drained event duplicated or missing", count, e)
		}
		return current
	}
	t.Run("atomic_rollback_then_idempotent_same_epoch", func(t *testing.T) {
		reset()
		if _, err := advance(false); err != nil {
			t.Fatal(err)
		}
		assertState("draining", 0)
		first, err := advance(true)
		if err != nil {
			t.Fatal(err)
		}
		actual := assertState("drained", 1)
		first.Phase, first.UpdatedAt = old.Phase, old.UpdatedAt
		if !reflect.DeepEqual(first, old) {
			t.Fatal("transition altered assessment, lease, fence or decision")
		}
		again, err := advance(true)
		if err != nil || !reflect.DeepEqual(again, actual) {
			t.Fatal("same epoch was renewed or reclassified", err)
		}
		assertState("drained", 1)
	})
	t.Run("concurrent_finish_one_CAS_event", func(t *testing.T) {
		reset()
		var wg sync.WaitGroup
		failures := make(chan error, 2)
		for n := 0; n < 2; n++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, e := advance(true); failures <- e }()
		}
		wg.Wait()
		close(failures)
		for e := range failures {
			if e != nil {
				t.Fatal(e)
			}
		}
		assertState("drained", 1)
	})
	t.Run("stale_JSON_CAS_cannot_overwrite_new_fence", func(t *testing.T) {
		reset()
		next, err := store.guestRetirementDrainedV2State(policy, p, old, stored, old.Generation, old.FencingToken, old.LeaseOwner, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{fencing_token}',to_jsonb($2::bigint))WHERE namespace=$1`, old.Namespace, old.FencingToken+1); err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = persistGuestRetirementDrainedV2Tx(ctx, tx, old, next, i.RequestID); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("stale transition overwrote newer epoch", err)
		}
		assertState("draining", 0)
	})
	t.Run("invalid_quiescence_and_missing_original_never_persist", func(t *testing.T) {
		reset()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = guestQuiescentProofV2Tx(ctx, tx, stored); err == nil {
			t.Fatal("empty original chain became quiescent")
		}
		if err = store.guestDestroyEligibilityV2Tx(ctx, tx, policy, p, old, model.CapacityMutationBinding{}, i.Slot, "resource", "created", time.Now().UTC(), "", i.RequestID); err == nil {
			t.Fatal("missing original authorized native destroy")
		}
		if _, err = store.AdvanceGuestRetirementDrainedV2(ctx, policy, old.Generation, old.FencingToken, old.LeaseOwner, i.RequestID, i.PreregistrationID, i.Slot); err == nil {
			t.Fatal("synthetic SQL operands obtained original workflow authority")
		}
		assertState("draining", 0)
	})
	for _, name := range []string{"expired_lease", "wrong_fence", "wrong_generation", "other_executor", "wrong_request_epoch", "not_reduction", "wrong_phase", "explicit_disposal"} {
		t.Run(name, func(t *testing.T) {
			reset()
			candidate, original, caller := old, stored, store
			switch name {
			case "expired_lease":
				expired := time.Now().UTC().Add(-time.Second)
				candidate.LeaseExpiresAt = &expired
			case "wrong_fence":
				candidate.FencingToken++
			case "wrong_generation":
				candidate.Generation++
			case "other_executor":
				caller.ExecutorID = uuid.NewString()
			case "wrong_request_epoch":
				original.Request.Intent.Fence++
			case "not_reduction":
				candidate.Decision.Action = "hold"
				candidate.Decision.Units = candidate.BaselineSnapshot.Units
			case "wrong_phase":
				candidate.Phase = "preparing"
			case "explicit_disposal":
				candidate.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{}
			}
			if _, err := caller.guestRetirementDrainedV2State(policy, p, candidate, original, old.Generation, old.FencingToken, old.LeaseOwner, time.Now().UTC()); err == nil {
				t.Fatal("invalid epoch obtained drained")
			}
			assertState("draining", 0)
		})
	}
}
