//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// The declared disposable fixture supplies transport records, not provider or
// Guest execution. All claims, callbacks, ledger writes and M95 guards are real
// PostgreSQL operations in CI; original deadlines and leases expire naturally.
func TestFailedUnwitnessedExpansionCleanupPostgresReadDeadlineContinuation(t *testing.T) {
	f := NewFailedExpansionCleanupRecoveryFixture(t)
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	var body94 string
	if err := f.DB.QueryRow(`SELECT prosrc FROM pg_proc WHERE oid='public.guard_failed_unwitnessed_expansion_cleanup_event()'::regprocedure`).Scan(&body94); err != nil {
		t.Fatal("actual94 event guard before95", err)
	}
	if err := goose.UpTo(f.DB, migrations, 95); err != nil {
		t.Fatal("explicit new schema95 after unchanged94 fixture", err)
	}
	if head, err := goose.GetDBVersion(f.DB); err != nil || head != 95 {
		t.Fatal("actual Goose schema95 required", head, err)
	}
	migration, err := os.ReadFile(filepath.Join(migrations, "00095_failed_expansion_read_failure_continuation.sql"))
	if err != nil {
		t.Fatal(err)
	}
	up := strings.SplitN(string(migration), "-- +goose Down", 2)[0]
	parts := strings.SplitN(up, "CREATE OR REPLACE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_event() RETURNS trigger LANGUAGE plpgsql AS $$", 2)
	if len(parts) != 2 {
		t.Fatal("closed95 Source function declaration missing")
	}
	parts = strings.SplitN(parts[1], "$$;", 2)
	var body95 string
	if len(parts) != 2 {
		t.Fatal("closed95 Source function body missing")
	}
	if err := f.DB.QueryRow(`SELECT prosrc FROM pg_proc WHERE oid='public.guard_failed_unwitnessed_expansion_cleanup_event()'::regprocedure`).Scan(&body95); err != nil || body95 != parts[0] || body95 == body94 {
		t.Fatal("actual installed event guard must equal exact95 Source body", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	original := failedCleanupTestOriginal(t, f.DB, f.GrantID)
	a, err := f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal("same real failed-create admission", err)
	}
	_, current, selected, handled, err := f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy)
	if err != nil || !handled || selected.ID != a.ID {
		t.Fatal("genuine initial cleanup owner", err)
	}
	store, _, handled, err := f.RetirementStore().BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !handled {
		t.Fatal(err)
	}
	if err = store.RefreshFailedExpansionSurvivors(ctx, f.Policy, cleanupNativeInventory(t, f, a, true)); err != nil {
		t.Fatal(err)
	}
	cleanupNativeCanaries(t, f, store, current, "before_retirement_floor")
	read, err := store.PrepareFailedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil {
		t.Fatal(err)
	}
	if _, pending, err := store.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeInventoryReturn(t, f, a, read)); err != nil || pending {
		t.Fatal("actual qualified dry-run before the one child", pending, err)
	}
	grant, err := store.IssueFailedExpansionDestroy(ctx, f.Policy)
	if err != nil || grant.GrantID != a.ChildGrantID || grant.CompensationOf != "" {
		t.Fatal("one separately linked normal destroy", grant, err)
	}
	if _, err = store.PrepareFailedExpansionRead(ctx, f.Policy, "absence"); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("issued/unsettled child acquired absence authority", err)
	}
	if err = store.MarkFailedExpansionPossibleSend(ctx, f.Policy); err != nil {
		t.Fatal(err)
	}
	receipt := cleanupNativeSettle(t, f, ctx, store, grant)
	finish, _, handled, err := f.FinishStore().BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !handled {
		t.Fatal(err)
	}
	pendingRead, err := finish.PrepareFailedExpansionRead(ctx, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	if proof, pending, err := finish.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeAbsenceReturn(t, pendingRead, receipt, true)); err != nil || !pending || proof.ResourceAbsent {
		t.Fatal("qualified paid-ENI Pending anchor", pending, err)
	}
	readCtx, cancelRead := context.WithTimeout(ctx, time.Second)
	defer cancelRead()
	read, err = finish.PrepareFailedExpansionRead(readCtx, f.Policy, "absence")
	if err != nil || read.ReadID == pendingRead.ReadID || read.OriginalDeadlineCore.Sub(read.IssuedAtCore) > 5*time.Second {
		t.Fatal("new finite original read challenge", read, err)
	}
	raw := cleanupNativeReturn(t, read)
	raw.Receipt = &receipt
	raw.ReceiptWire = failedServingWire(t, receipt)
	raw.CallFailed, raw.OriginalContextFailed = true, true
	beforeRaw := failedCleanupTestLedger(t, f.DB, a)
	// These callers never match the actual prepared pair, so raw custody must
	// not be attached to another read or ownership epoch.
	for _, mutate := range []func(*FailedExpansionReadReturn){
		func(r *FailedExpansionReadReturn) { r.Read.ReadID = uuid.NewString() },
		func(r *FailedExpansionReadReturn) { r.Read.ClaimSequence++ },
	} {
		bad := cleanupNativeReturn(t, read)
		mutate(&bad)
		bad.ReadWire = failedServingWire(t, bad.Read)
		if _, _, err = finish.RecordFailedExpansionRead(ctx, f.Policy, bad); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("foreign prepared pair was recorded", err)
		}
		if !reflect.DeepEqual(beforeRaw, failedCleanupTestLedger(t, f.DB, a)) {
			t.Fatal("foreign read refusal changed sealed events")
		}
	}
	// Reproduce the final raw return after its ORIGINAL <=5s read deadline.
	// No clock, old prepared row, SDK record, read ID or lease is rewritten.
	<-readCtx.Done()
	if !errors.Is(readCtx.Err(), context.DeadlineExceeded) {
		t.Fatal("original read context did not reach its own deadline", readCtx.Err())
	}
	raw.ReturnedAtCore = time.Now().UTC()
	if proof, pending, err := finish.RecordFailedExpansionRead(ctx, f.Policy, raw); !errors.Is(err, ErrCapacityConflict) || pending || proof.ResourceAbsent {
		t.Fatal("deadline failure became qualified absence", pending, err)
	}
	_, events, err := finish.ReadFailedUnwitnessedExpansionCleanup(ctx, a.GrantID)
	if err != nil || len(events) < 3 || events[len(events)-1].Stage != "absence_returned" || events[len(events)-2].Stage != "absence_prepared" || events[len(events)-3].Stage != "pending_absence" || !bytes.Equal(events[len(events)-1].Evidence, failedServingWire(t, raw)) {
		t.Fatal("actual qualified/prepared/raw contiguous suffix", err)
	}
	oldLedger := failedCleanupTestLedger(t, f.DB, a)
	var childWire, childSDK []byte
	if err = f.DB.QueryRow(`SELECT grant_record::text,(grant_record#>'{settlement,original_provider_destroy_return}')::text FROM public.capacity_mutation_grants WHERE id=$1`, a.ChildGrantID).Scan(&childWire, &childSDK); err != nil {
		t.Fatal(err)
	}
	if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("failed read inherited full absence or old floor", err)
	}
	// The same real still-running owner has no failed ACK, and its live lease
	// cannot be renewed through another claim.
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, ok := latestFailedExpansionClaim(events)
	if !ok {
		_ = tx.Rollback()
		t.Fatal("missing genuine claim")
	}
	child, err := failedExpansionChildTx(ctx, tx, a)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = failedExpansionClosedOwnerTx(ctx, tx, claim); !errors.Is(err, ErrCapacityConflict) {
		_ = tx.Rollback()
		t.Fatal("running/no-ACK owner accepted as failed closure", err)
	}
	var pgNow time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&pgNow); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	_ = tx.Rollback()
	if !failedExpansionDeadlineReturnContinuation(events, claim, a, child, pgNow) {
		t.Fatal("genuine raw deadline suffix not recognized as readonly-only structure")
	}
	cleanupReadFailureNegativeSuffixes(t, f, a, events, claim, child, pgNow)
	if _, _, _, _, err = f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityLease) {
		t.Fatal("live original lease was renewed", err)
	}
	// Finish the actual owning dispatch as failed, retaining the error while
	// obtaining its real workflow finished_at / returned / ACK relation.
	var jobID uuid.UUID
	if err = f.DB.QueryRowContext(ctx, `SELECT id FROM public.capacity_dispatch_jobs WHERE run_id=$1`, f.store.OriginalRunID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	tx, err = f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := readCapacityDispatchJob(ctx, tx, jobID, false)
	_ = tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	returned := time.Now().UTC()
	failure := errors.New("DECLARED original absence read context deadline")
	response := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "failed", StartedAt: *job.StartedAt, FinishedAt: returned}
	if err = FinishCapacityDispatch(ctx, f.DB, job, response, returned, failure); !errors.Is(err, failure) {
		t.Fatal("original failed workflow lost its error/ACK", err)
	}
	var acknowledged bool
	var closedRun, closedJob []byte
	if err = f.DB.QueryRowContext(ctx, `SELECT j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=$2,to_jsonb(w)::text,to_jsonb(j)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, jobID, events[len(events)-1].RecordedAt).Scan(&acknowledged, &closedRun, &closedJob); err != nil || !acknowledged {
		t.Fatal("real failed ACK after retained raw read required", acknowledged, err)
	}
	oldRun := f.store.OriginalRunID
	f.startSuccessorDispatch()
	plan := f.PlanStore()
	beforeNew := failedCleanupTestIntent(t, f.DB, f.Policy, f.Spec)
	if plan.OriginalRunID == oldRun {
		t.Fatal("successor reused failed run")
	}
	if _, _, _, _, err = plan.TryClaimFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityLease) {
		t.Fatal("genuine new run claimed before natural old lease expiry", err)
	}
	if !bytes.Equal(beforeNew, failedCleanupTestIntent(t, f.DB, f.Policy, f.Spec)) || !reflect.DeepEqual(oldLedger, failedCleanupTestLedger(t, f.DB, a)) {
		t.Fatal("premature claim changed original epoch or events")
	}
	time.Sleep(max(0, time.Until(*current.LeaseExpiresAt)) + 5*time.Millisecond)
	unknown := plan
	unknown.OriginalRunID = uuid.New()
	if _, _, _, _, err = unknown.TryClaimFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("unregistered requester acquired continuation", err)
	}
	_, next, same, handled, err := plan.TryClaimFailedExpansionCleanup(ctx, f.Policy)
	if err != nil || !handled || same.ID != a.ID || next.Generation != current.Generation || next.FencingToken != current.FencingToken+1 || next.LeaseOwner == current.LeaseOwner || next.LeaseExpiresAt == nil || !next.LeaseExpiresAt.After(*current.LeaseExpiresAt) {
		t.Fatal("new finite readonly owner after exact failed ACK/expiry", next, err)
	}
	if !reflect.DeepEqual(next.Assessment, current.Assessment) || !reflect.DeepEqual(next.BaselineSnapshot, current.BaselineSnapshot) || !reflect.DeepEqual(next.Decision, current.Decision) {
		t.Fatal("readonly continuation changed failed N2 decision or baseline")
	}
	finish, _, handled, err = f.FinishStore().BindFailedExpansionCleanup(ctx, f.Policy, next.Generation, next.FencingToken, next.LeaseOwner)
	if err != nil || !handled {
		t.Fatal(err)
	}
	if _, err = finish.IssueFailedExpansionDestroy(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("readonly successor reissued child", err)
	}
	if err = finish.MarkFailedExpansionPossibleSend(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("readonly successor replayed possible send", err)
	}
	callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256, ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString()))}
	if permit, err := callback.RedeemMutation(ctx, f.Spec.MutationBindings[0].AdapterPrincipalID, request); err == nil && permit.Mode == "write_once" {
		t.Fatal("settled known child obtained a new provider write permit")
	}
	if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("new owner completed using only old Pending/failed read")
	}
	if !reflect.DeepEqual(original, failedCleanupTestOriginal(t, f.DB, a.GrantID)) {
		t.Fatal("readonly continuation changed original CREATE SDK/settlement")
	}
	var currentChild []byte
	if err = f.DB.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, a.ChildGrantID).Scan(&currentChild); err != nil || !bytes.Equal(childWire, currentChild) {
		t.Fatal("claim/write refusals changed settled child bytes", err)
	}
	if err = finish.RefreshFailedExpansionSurvivors(ctx, f.Policy, cleanupNativeInventory(t, f, a, false)); err != nil {
		t.Fatal(err)
	}
	cleanupNativeCanaries(t, f, finish, next, "before_retirement_floor")
	fresh, err := finish.PrepareFailedExpansionRead(ctx, f.Policy, "absence")
	if err != nil || fresh.ReadID == read.ReadID || fresh.ReadID == pendingRead.ReadID || fresh.ClaimSequence == read.ClaimSequence {
		t.Fatal("new claim must issue a fresh readonly pair", fresh, err)
	}
	if proof, pending, err := finish.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeAbsenceReturn(t, fresh, receipt, false)); err != nil || pending || !proof.ResourceAbsent || len(proof.AuxiliaryAbsent) != 2 {
		t.Fatal("same SDK child fresh complete VM/AUX2 absence", pending, err)
	}
	if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("fresh after-absence floor missing", err)
	}
	if err = finish.RefreshFailedExpansionSurvivors(ctx, f.Policy, cleanupNativeInventory(t, f, a, false)); err != nil {
		t.Fatal(err)
	}
	cleanupNativeCanaries(t, f, finish, next, "after_retirement_floor")
	terminal, err := finish.CompleteFailedExpansionCleanup(ctx, f.Policy)
	if err != nil || terminal.Phase != "hold" || terminal.Decision.Units != 1 || terminal.LeaseOwner != "" || terminal.LeaseExpiresAt != nil {
		t.Fatal("normal terminal cleanup after fresh readonly proof", terminal, err)
	}
	var parentSDK, finalChildSDK, finalRun, finalJob []byte
	var parentState, childState string
	var children, sends int
	if err = f.DB.QueryRow(`SELECT state,(grant_record#>'{settlement,original_provider_create_return}')::text FROM public.capacity_mutation_grants WHERE id=$1`, a.GrantID).Scan(&parentState, &parentSDK); err != nil || parentState != "cleanup_closed" || !bytes.Equal(parentSDK, original.sdk) {
		t.Fatal("original SDK CREATE changed at terminal", err)
	}
	if err = f.DB.QueryRow(`SELECT state,(grant_record#>'{settlement,original_provider_destroy_return}')::text FROM public.capacity_mutation_grants WHERE id=$1`, a.ChildGrantID).Scan(&childState, &finalChildSDK); err != nil || childState != "confirmed" || !bytes.Equal(finalChildSDK, childSDK) {
		t.Fatal("single original SDK DELETE changed at terminal", err)
	}
	if err = f.DB.QueryRow(`SELECT(SELECT count(*) FROM public.capacity_mutation_grants WHERE failed_unwitnessed_expansion_cleanup_id=$1),(SELECT count(*) FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$1 AND stage='possible_send')`, a.ID).Scan(&children, &sends); err != nil || children != 1 || sends != 1 {
		t.Fatal("continuation duplicated child or send", children, sends, err)
	}
	if err = f.DB.QueryRow(`SELECT to_jsonb(w)::text,to_jsonb(j)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, jobID).Scan(&finalRun, &finalJob); err != nil || !bytes.Equal(closedRun, finalRun) || !bytes.Equal(closedJob, finalJob) {
		t.Fatal("failed original run or ACK changed", err)
	}
	finalLedger := failedCleanupTestLedger(t, f.DB, a)
	for _, old := range oldLedger {
		found := false
		for _, now := range finalLedger {
			found = found || bytes.Equal(old, now)
		}
		if !found {
			t.Fatal("immutable admission/Pending/prepared/failed raw wire changed")
		}
	}
	// This disposable database alone returns to94. The original event body and
	// every retained business/event byte must survive the reversible95 upgrade.
	if err = goose.DownTo(f.DB, migrations, 94); err != nil {
		t.Fatal("95 Down must restore actual94 without rewriting evidence", err)
	}
	if version, err := goose.GetDBVersion(f.DB); err != nil || version != 94 {
		t.Fatal("actual restored Goose94", version, err)
	}
	var restoredBody string
	if err = f.DB.QueryRow(`SELECT prosrc FROM pg_proc WHERE oid='public.guard_failed_unwitnessed_expansion_cleanup_event()'::regprocedure`).Scan(&restoredBody); err != nil || restoredBody != body94 || !reflect.DeepEqual(finalLedger, failedCleanupTestLedger(t, f.DB, a)) {
		t.Fatal("Down changed original94 function or retained ledger", err)
	}
}

// Mutations are LOCAL COPIES of actual PG events/child after real accepted SDK
// settlement. They exercise the production pure suffix predicate; no stored
// wire, source clock, failed ACK or production authority is manufactured.
func cleanupReadFailureNegativeSuffixes(t *testing.T, f *FailedExpansionCleanupRecoveryFixture, a FailedUnwitnessedExpansionCleanup, events []FailedUnwitnessedExpansionCleanupEvent, claim FailedUnwitnessedExpansionCleanupEvent, child capacityMutationRecord, now time.Time) {
	t.Helper()
	ledger := failedCleanupTestLedger(t, f.DB, a)
	cases := []struct {
		name string
		edit func([]FailedUnwitnessedExpansionCleanupEvent, *capacityMutationRecord, *FailedExpansionReadReturn)
	}{
		{"call_did_not_fail", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.CallFailed = false
		}},
		{"not_original_context_deadline", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.OriginalContextFailed = false
		}},
		{"unsupported_output_status", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.Status = "observed"
		}},
		{"return_before_original_deadline", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.ReturnedAtCore = r.Read.OriginalDeadlineCore.Add(-time.Nanosecond)
		}},
		{"mismatched_read_wire", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.ReadWire = append(r.ReadWire, ' ')
		}},
		{"inventory_kind", func(e []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.Read.Kind = "inventory"
			r.ReadWire = failedServingWire(t, r.Read)
			e[len(e)-2].Evidence = failedServingWire(t, r.Read)
		}},
		{"zero_read_id", func(e []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.Read.ReadID = uuid.Nil.String()
			r.ReadWire = failedServingWire(t, r.Read)
			e[len(e)-2].Evidence = failedServingWire(t, r.Read)
		}},
		{"foreign_claim", func(e []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, _ *FailedExpansionReadReturn) {
			e[len(e)-1].FencingToken++
		}},
		{"forged_receipt", func(_ []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, r *FailedExpansionReadReturn) {
			r.Receipt.ActionID = uuid.NewString()
			r.ReceiptWire = failedServingWire(t, *r.Receipt)
		}},
		{"unsettled_child", func(_ []FailedUnwitnessedExpansionCleanupEvent, c *capacityMutationRecord, _ *FailedExpansionReadReturn) {
			c.Grant.State = "issued"
			c.Settlement = nil
		}},
		{"missing_qualified_anchor", func(e []FailedUnwitnessedExpansionCleanupEvent, _ *capacityMutationRecord, _ *FailedExpansionReadReturn) {
			e[len(e)-3].Stage = "absence_returned"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var copyEvents []FailedUnwitnessedExpansionCleanupEvent
			var copyChild capacityMutationRecord
			if json.Unmarshal(failedServingWire(t, events), &copyEvents) != nil || json.Unmarshal(failedServingWire(t, child), &copyChild) != nil {
				t.Fatal("declared actual PG operand copies")
			}
			var raw FailedExpansionReadReturn
			if json.Unmarshal(copyEvents[len(copyEvents)-1].Evidence, &raw) != nil {
				t.Fatal("actual retained raw return")
			}
			c.edit(copyEvents, &copyChild, &raw)
			copyEvents[len(copyEvents)-1].Evidence = failedServingWire(t, raw)
			if failedExpansionDeadlineReturnContinuation(copyEvents, claim, a, copyChild, now) {
				t.Fatal("non-authoritative failed return accepted", c.name)
			}
			if !reflect.DeepEqual(ledger, failedCleanupTestLedger(t, f.DB, a)) {
				t.Fatal("local predicate vectors changed immutable PG ledger")
			}
		})
	}
}
