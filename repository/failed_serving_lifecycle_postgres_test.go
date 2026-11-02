//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func failedServingContext(t *testing.T) context.Context {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(stop)
	return ctx
}

func failedServingIssuerForTest() string { return "collaborator:" + uuid.NewString() }

func failedServingQuarantine(t *testing.T, f *failedServingFixture) FailedServingGuestDisposal {
	t.Helper()
	ctx := failedServingContext(t)
	owner, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest())
	if err != nil {
		t.Fatal("source-owned quarantine begin", err)
	}
	r, err := f.store.CompleteFailedServingGuestQuarantine(ctx, owner, f.inventory(t, false))
	if err != nil || r.Stage != "quarantined" || r.ID == "" || r.PreregistrationID != f.pre.PreregistrationID {
		t.Fatal("complete native-one quarantine", r.Stage, err)
	}
	return r
}

func failedServingOff(t *testing.T, f *failedServingFixture, admission string) FailedServingGuestDisposal {
	t.Helper()
	ctx := failedServingContext(t)
	owner, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, admission, failedServingIssuerForTest(), "off")
	if err != nil {
		t.Fatal("source-owned OFF begin", err)
	}
	r, err := f.store.CompleteFailedServingGuestNativeOff(ctx, owner, f.offPlan(t))
	if err != nil || r.Stage != "quiescent" || r.ID != admission {
		t.Fatal("exact original tuple OFF", r.Stage, err)
	}
	return r
}

func TestFailedServingQuarantineLifecyclePostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			before, originals := f.rawIntent(t), f.preserved(t)
			request := f.request(t)
			owner, err := f.store.BeginFailedServingGuestQuarantine(ctx, request, failedServingIssuerForTest())
			if err != nil {
				t.Fatal("real signed/installed/useful original admission", err)
			}
			if got := owner.Candidate(); got.Request.ExpectedResourceID != f.reg.Result.Tuple.ResourceID || got.Request.ExpectedResourceCreatedAt != f.reg.Result.Tuple.CreatedAt || got.Preregistration.PreregistrationID != f.pre.PreregistrationID {
				t.Fatal("candidate was not derived from the exact original")
			}
			r, err := f.store.CompleteFailedServingGuestQuarantine(ctx, owner, f.inventory(t, false))
			if err != nil || r.Stage != "quarantined" || !reflect.DeepEqual(r.OriginalIntentWire, before) || r.OriginalIntentSHA256 != capacity.BusinessCreationSHA256(before) {
				t.Fatal("quarantine lost the complete original frame", err)
			}
			if _, err = f.store.CompleteFailedServingGuestQuarantine(ctx, owner, f.inventory(t, false)); err == nil {
				t.Fatal("one private observation owner was consumed twice")
			}
			var q model.CapacityIntent
			quarantineWire := f.rawIntent(t)
			if json.Unmarshal(quarantineWire, &q) != nil || q.Generation != request.Generation || q.FencingToken != request.FencingToken+1 || q.Phase != FailedServingGuestQuarantinedPhase || q.LeaseOwner != "" || q.LeaseExecutorID != "" || q.LeaseExpiresAt != nil || q.Decision.ExecutionPermitted || q.FailedServingDisposal == nil || q.FailedServingDisposal.ID != r.ID {
				t.Fatal("quarantine did not fence once without a lease")
			}
			waiting, held, err := f.store.FailedServingGuestDisposalWaiting(ctx, f.policy)
			if err != nil || !held || waiting.ID != r.ID {
				t.Fatal("the ordinary plan cannot discover its early HOLD", err)
			}
			failedServingOff(t, f, r.ID)
			absenceOwner, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, r.ID, failedServingIssuerForTest(), "absence")
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := f.store.CompleteFailedServingGuestAbsence(ctx, absenceOwner, failedServingAbsence(t, absenceOwner), f.inventory(t, true))
			if err != nil || terminal.Stage != "terminal" || terminal.ID != r.ID {
				t.Fatal("complete original main/aux absence plus complete zero inventory", err)
			}
			if _, err = f.store.CompleteFailedServingGuestAbsence(ctx, absenceOwner, failedServingAbsence(t, absenceOwner), f.inventory(t, true)); err == nil {
				t.Fatal("terminal reused the already consumed original owner")
			}
			var ended model.CapacityIntent
			if json.Unmarshal(f.rawIntent(t), &ended) != nil || ended.Phase != FailedServingGuestDisposedPhase || ended.Assessment.Snapshot.Units != 0 || ended.Decision.Units != 0 || ended.Decision.Action != "hold" || ended.Decision.ExecutionPermitted || ended.LeaseExpiresAt != nil || ended.RecoveryOnly || ended.FloorDegraded {
				t.Fatal("physical absence became a useful/promotion/recovery claim")
			}
			var resource string
			var tombstone bool
			if err = f.db.QueryRow(`SELECT resource_id,(slot_record->>'tombstone')::boolean FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=1`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension).Scan(&resource, &tombstone); err != nil || resource != "" || !tombstone {
				t.Fatal("only the original slot must be tombstoned", err)
			}
			if got := f.preserved(t); !reflect.DeepEqual(got, originals) {
				t.Fatal("a serving original's accepted/useful facts changed", originals, got)
			}
			records, err := f.store.ReadFailedServingGuestDisposals(ctx, f.pre.PreregistrationID)
			if err != nil || len(records) != 3 || records[0].Stage != "quarantined" || records[1].Stage != "quiescent" || records[2].Stage != "terminal" {
				t.Fatal("append-only lifecycle history unavailable", len(records), err)
			}
			if pendingCapacityPhase(FailedServingGuestDisposedPhase) || !pendingCapacityPhase(FailedServingGuestQuarantinedPhase) {
				t.Fatal("quarantine/terminal phase classification permits a bypass or deadlock")
			}
		})
	}
}

func TestFailedServingQuarantineCASAndCentralGuardsPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			before := f.rawIntent(t)
			for _, name := range []string{"intent_sha", "policy_id", "policy_checksum", "preregistration", "generation", "fence", "issuer"} {
				t.Run(name, func(t *testing.T) {
					req, issuer := f.request(t), failedServingIssuerForTest()
					switch name {
					case "intent_sha":
						req.IntentSHA256 = strings.Repeat("f", 64)
					case "policy_id":
						req.PolicyID = uuid.NewString()
					case "policy_checksum":
						req.PolicyChecksum = strings.Repeat("f", 64)
					case "preregistration":
						req.PreregistrationID = uuid.NewString()
					case "generation":
						req.Generation++
					case "fence":
						req.FencingToken++
					case "issuer":
						issuer = "service:unapproved-automation"
					}
					if _, err := f.store.BeginFailedServingGuestQuarantine(ctx, req, issuer); err == nil {
						t.Fatal("foreign caller/CAS reached admission")
					}
					if !reflect.DeepEqual(f.rawIntent(t), before) {
						t.Fatal("rejected request changed the original intent")
					}
				})
			}
			r := failedServingQuarantine(t, f)
			quarantined := f.rawIntent(t)
			called := false
			_, err := f.store.recoveryTransaction(ctx, f.policy, func(_ model.CapacityPolicySpec, old *model.CapacityIntent, _ time.Time) (model.CapacityIntent, string, error) {
				called = true
				return *old, "unexpected-recovery-bypass", nil
			})
			if err == nil || called {
				t.Fatal("central historical/recovery transaction reached its mutator")
			}
			baseline := f.intent.BaselineSnapshot
			baseline.ObservedAt = time.Now().UTC()
			if _, err = f.store.Recover(ctx, f.policy, f.intent.Generation, model.CapacityAssessment{Snapshot: baseline}); err == nil {
				t.Fatal("pending, unleased quarantine acquired a recovery lease")
			}
			if _, err = f.store.RenewRecovery(ctx, f.policy, f.intent.Generation, f.intent.FencingToken+1, uuid.NewString()); err == nil {
				t.Fatal("quarantine renewed recovery")
			}
			if _, err = f.store.Reconcile(ctx, f.policy, f.intent.Generation, f.intent.FencingToken+1, uuid.NewString(), "reconciled", model.CapacityTransitionProof{}); err == nil {
				t.Fatal("quarantine reconciled through generic recovery")
			}
			tx, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = lockNativeMutationSlot(ctx, tx, f.p.MutationBindings[0], 1); err == nil {
				_ = tx.Rollback()
				t.Fatal("shared native slot admitted an ordinary authority")
			}
			_ = tx.Rollback()
			if !reflect.DeepEqual(f.rawIntent(t), quarantined) {
				t.Fatal("a denied recovery changed the frozen quarantine")
			}
			if _, err = f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
				t.Fatal("second active quarantine admitted")
			}
			if got, held, e := f.store.FailedServingGuestDisposalWaiting(ctx, f.policy); e != nil || !held || got.ID != r.ID {
				t.Fatal("quarantine lost its explicit early HOLD", e)
			}
		})
	}
}
