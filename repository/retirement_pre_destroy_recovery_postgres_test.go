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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// The existing Live root calls this after its old children release their
// fixture mutex. Nothing here changes the old M97/M101/M102 fixture databases.
func retirementForwardPreDestroy103Regression(t *testing.T) {
	t.Helper()
	originalPID := os.Getpid() // Actual owning CI process; not a fabricated server start clock.
	f := NewGuestRetirementForwardRecoveryFixture(t, "aws", 5, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	preDestroy103Migration(t, f, ctx)
	originals := f.PreservedOriginals()
	// This is a separate DECLARED historical storage operand, not a provider
	// execution or a rewrite of the actual current incarnation's create grant.
	oldHistory := preDestroy103Grant(t, f, "confirmed", "declared-old-incarnation", "2020-01-01T00:00:00Z", false)
	if _, err := f.DB.ExecContext(ctx, oldHistory.query, oldHistory.args...); err != nil {
		t.Fatal("declared old-incarnation confirmed DELETE", err)
	}
	var oldHistoryBefore []byte
	if e := f.DB.QueryRowContext(ctx, `SELECT to_jsonb(g)::text FROM public.capacity_mutation_grants g WHERE id=$1`, oldHistory.id).Scan(&oldHistoryBefore); e != nil {
		t.Fatal("whole declared historical grant preimage", e)
	}
	parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil || parent.Mode != "live" || parent.Stage != "admitted" {
		t.Fatal("actual live G49-shaped origin", parent, err)
	}
	preDestroy103NoAuthority(t, f, ctx)
	off := preDestroy103Off(t, f, ctx)
	if requested, e := f.PlanStore().TryRequestGuestRetirementForwardPreDestroyRecovery(ctx, f.Policy); e != nil || requested {
		t.Fatal("still-live owner cannot become failed recovery", requested, e)
	}
	oldOwner, oldStore := f.Intent, f.FinishStore()
	preDestroy103FailACK(t, f, ctx, parent.ID, true)
	parent = preDestroy103Waiting(t, f, ctx)
	if parent.Stage != "off_qualified" || parent.Mode != "live" || parent.NativeOffReadID != off.Read.ReadID {
		t.Fatal("retained live OFF qualification", parent)
	}
	parentCustody := preDestroy103Custody(t, f, []string{parent.ID}, []string{parent.RunID})
	f.WaitHistoricalBarrier() // Actual original lease/context expiry; no rewrite.
	f.StartSuccessorDispatch()
	first := preDestroy103RequestRace(t, f, ctx)
	preDestroy103RequireProof(t, first, parent, off)
	preDestroy103DownRefusal(t, f, ctx, "REQUESTED")
	preDestroy103ProofVectors(t, f, ctx, first)
	preDestroy103AuthorityVectors(t, f, ctx, first)
	preDestroy103HistoryVectors(t, f, ctx, first, off)
	preDestroy103QuietVectors(t, f, ctx, first)
	preDestroy103ClaimRace(t, f, ctx, first, oldStore, oldOwner)
	preDestroy103NoFreshAuthority(t, f, ctx)
	firstOFF := preDestroy103Off(t, f, ctx)
	incomplete := f.Inventory(true)
	incomplete.Complete = false
	if e := f.FinishStore().RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, incomplete); e == nil {
		t.Fatal("declared incomplete inventory passed the actual refresh gate")
	}
	if _, e := f.FinishStore().AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); e == nil {
		t.Fatal("fresh OFF without fresh inventory/floor permitted DELETE")
	}
	preDestroy103NoAuthority(t, f, ctx)
	// A real failed child after its own positive OFF represents an inventory or
	// floor refusal. It is not relabelled as successful inventory or publication.
	preDestroy103FailACK(t, f, ctx, first.ID, false)
	first = preDestroy103Waiting(t, f, ctx)
	firstCustody := preDestroy103Custody(t, f, []string{parent.ID, first.ID}, []string{parent.RunID, first.RunID})
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	second := preDestroy103RequestRace(t, f, ctx)
	preDestroy103RequireProof(t, second, first, firstOFF)
	preReadClaim(t, f, ctx, second)
	preDestroy103NoFreshAuthority(t, f, ctx)
	// Existing helper requires another actual child OFF, exact native inventory,
	// fresh useful survivor canaries, the first issue and its one redemption.
	receipt := forwardTestSettledDestroy(t, f, ctx, true)
	if receipt.Outcome != "accepted" || !receipt.TransportCompleted || receipt.Grant.State != "settled" {
		t.Fatal("one actual first DELETE settlement", receipt)
	}
	preDestroy103OneCurrentDelete(t, f, ctx, receipt.Grant.GrantID)
	if requested, e := f.PlanStore().TryRequestGuestRetirementForwardPreDestroyRecovery(ctx, f.Policy); e != nil || requested {
		t.Fatal("first committed DELETE must close pre-destroy admission", requested, e)
	}
	preDestroy103RequireCustody(t, f, parentCustody, []string{parent.ID}, []string{parent.RunID})
	preDestroy103RequireCustody(t, f, firstCustody, []string{parent.ID, first.ID}, []string{parent.RunID, first.RunID})
	// Preserve the owning M102 lane after the FIRST accepted DELETE: the actual
	// absence context expires, its failure/ACK remains, and only read/Confirm
	// authority is recovered on a new fence. No old OFF or DELETE is replayed.
	_, failedRead := closedRead102ExpiredRead(t, f, ctx, receipt.Grant.GrantID)
	second = preDestroy103Waiting(t, f, ctx)
	preDestroy103FailACK(t, f, ctx, second.ID, false)
	postDeleteCustody := closedRead102Custody(t, f, []string{parent.ID, first.ID, second.ID})
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	if requested, e := f.PlanStore().TryRequestGuestRetirementForwardPreDestroyRecovery(ctx, f.Policy); e != nil || requested {
		t.Fatal("settled current DELETE re-entered the no-authority lane", requested, e)
	}
	preDestroy103M102CarryGuard(t, f, ctx, failedRead.ID)
	continued := continuationTestRequest(t, f, ctx)
	if continued.Continuation == nil || continued.Continuation.Schema != GuestRetirementForwardClosedFailedReadContinuationSchema || continued.Continuation.ClosedFailedRead == nil || continued.Continuation.ClosedFailedRead.ReadID != failedRead.ID || !reflect.DeepEqual(continued.PreDestroyRecovery, second.PreDestroyRecovery) || continued.DestroyGrantID != receipt.Grant.GrantID {
		t.Fatal("M102 must preserve pre-destroy ancestry and the exact spent DELETE", continued)
	}
	preReadClaim(t, f, ctx, continued)
	forwardTestComplete(t, f, ctx)
	if err = FinishCapacityDispatch(ctx, f.DB, f.job, preReadWorkflowResult(f, f.Intent, continued.ID, "succeeded", ""), time.Now().UTC(), nil); err != nil {
		t.Fatal("actual new final successful ACK", err)
	}
	var finalACK bool
	if err = f.DB.QueryRowContext(ctx, `SELECT j.state='returned' AND j.return_status='succeeded' AND j.finalization_ack_at>=j.returned_at AND w.status='succeeded' AND w.finished_at=j.returned_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.job.JobID).Scan(&finalACK); err != nil || !finalACK {
		t.Fatal("same actual successful run/job must retain its final ACK", finalACK, err)
	}
	if !reflect.DeepEqual(originals, f.PreservedOriginals()) || !reflect.DeepEqual(postDeleteCustody, closedRead102Custody(t, f, []string{parent.ID, first.ID, second.ID})) {
		t.Fatal("new owner rewrote original Guest/failed ACK/read/settlement custody")
	}
	preDestroy103OneCurrentDelete(t, f, ctx, receipt.Grant.GrantID)
	preDestroy103DownRefusal(t, f, ctx, "CARRIED-M102")
	if os.Getpid() != originalPID {
		t.Fatal("same-process admission unexpectedly replaced its CI process")
	}
	var historicalRecord []byte
	if err = f.DB.QueryRowContext(ctx, `SELECT to_jsonb(g)::text FROM public.capacity_mutation_grants g WHERE id=$1`, oldHistory.id).Scan(&historicalRecord); err != nil || !bytes.Equal(historicalRecord, oldHistoryBefore) {
		t.Fatal("old incarnation's confirmed DELETE history changed", err)
	}
	preDestroy103Put(t, "M103-PRE-DESTROY-RESULT.PUBLIC.json", failedServingWire(t, map[string]any{
		"schema": "pre_destroy_recovery103_pg_fixture_v1", "source_commit": capacity.CurrentGuestCoreSource(),
		"live_off_qualified_failed_ACK_origin": true, "natural_original_leases": true,
		"same_ci_process_pid_before_and_after":        originalPID,
		"historical_process_barrier_supplied":         false,
		"old_incarnation_confirmed_destroy_preserved": true, "two_request_calls_one_child": true,
		"old_issue_two_claim_calls_one_new_owner": true, "fresh_OFF_inventory_floor_before_first_DELETE": true,
		"own_OFF_failed_child_recovery": true, "eight_unbound_states_two_realms_current_tuple_hold": true,
		"unbound_cleanup_closed_exact_storage_refusal": true,
		"unknown_unACK_open_failed_latest_hold":        true, "first_DELETE_once_then_M102_read_confirm": true,
		"whole_old_originals_preserved": true, "real_final_success_ACK": true,
		"parent_id": parent.ID, "first_child": first.ID, "repeat_child": second.ID,
		"post_delete_read_child": continued.ID, "destroy_grant_id": receipt.Grant.GrantID,
		"fixture_only": true, "native_cloud": false, "Root_acceptance": false,
	}))
}

// Build only an unpersisted proposal from the actual failed owner/read/ACK and
// spent DELETE. Its complete INSERT must pass before sole-proof alterations
// are rejected. Every insertion is rolled back; the public request follows.
func preDestroy103M102CarryGuard(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, readID string) {
	t.Helper()
	s := f.PlanStore()
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	x, err := s.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal("actual carry proposal snapshot", err)
	}
	if err = s.guestReconcileSourceTx(ctx, tx, f.Policy, x.spec); err != nil {
		t.Fatal("actual carry proposal Source", err)
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, f.Policy, x.spec, s.OriginalRunID, nil); err != nil {
		t.Fatal("actual carry proposal requester", err)
	}
	parent, parentSHA, err := loadRetirementForwardTx(ctx, tx, x.current.RetirementForward.ID, x.current.RetirementForward.Stage)
	if err != nil || parent.PreDestroyRecovery == nil {
		t.Fatal("actual carry proposal parent", err)
	}
	admitted, admittedSHA, err := loadRetirementForwardTx(ctx, tx, parent.ID, "admitted")
	if err != nil {
		t.Fatal(err)
	}
	failed, err := s.failedForwardRetirementRunTx(ctx, tx, x, parent.RunID)
	if err != nil {
		t.Fatal("actual carry proposal failed ACK", err)
	}
	proof := &GuestRetirementForwardContinuationProof{RequestingRunID: s.OriginalRunID.String(), Schema: GuestRetirementForwardContinuationSchema, FailedRunID: parent.RunID, FailedRunSHA256: capacity.BusinessCreationSHA256([]byte(failed))}
	var dispatch []byte
	if err = tx.QueryRowContext(ctx, `SELECT id::text,to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE run_id=$1`, parent.RunID).Scan(&proof.DispatchID, &dispatch); err != nil {
		t.Fatal(err)
	}
	proof.DispatchSHA256 = capacity.BusinessCreationSHA256(dispatch)
	var destroy string
	if err = tx.QueryRowContext(ctx, `SELECT b.destroy_grant_id::text,b.eligibility_sha256,encode(digest(g.grant_record::text,'sha256'),'hex') FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1 AND `+capacityGrantUndisposedSQL+` AND g.state='settled'`, parent.RetirementRequestID).Scan(&destroy, &proof.DeleteEligibilitySHA256, &proof.DestroyGrantSHA256); err != nil {
		t.Fatal("actual carry proposal spent DELETE", err)
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, admitted, destroy)
	if err != nil {
		t.Fatal(err)
	}
	eligible, err := s.retirementForwardClosedFailedReadContinuationTx(ctx, tx, x, parent, admitted, admittedSHA, readID, original, proof)
	if err != nil || !eligible {
		t.Fatal("actual production closed-read proof", eligible, err)
	}
	if err = retirementForwardContinuationQuietTx(ctx, tx, x, destroy, s.OriginalRunID.String()); err != nil {
		t.Fatal("actual carry proposal typed quiet", err)
	}
	r := forwardRecord(x, s, GuestRetirementForwardContinuationMode, "requested", "source:settled-absence-continuation")
	r.RootAdmissionID, r.ParentAdmissionID, r.ParentAdmissionSHA256 = parent.RootAdmissionID, parent.ID, parentSHA
	r.RunID, r.FailedRun, r.DestroyGrantID, r.Continuation, r.PreDestroyRecovery = "", []byte(failed), destroy, proof, parent.PreDestroyRecovery
	if _, err = tx.ExecContext(ctx, `SAVEPOINT carry_baseline`); err != nil {
		t.Fatal(err)
	}
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		t.Fatal("full authentic carried proposal must pass every INSERT guard", err)
	}
	if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT carry_baseline`); err != nil {
		t.Fatal(err)
	}
	baseWire := failedServingWire(t, r)
	results := []map[string]any{{"case": "exact", "insert_succeeded": true, "rolled_back": true}}
	for _, fault := range []string{"missing", "null", "changed"} {
		var v map[string]json.RawMessage
		if err = json.Unmarshal(baseWire, &v); err != nil {
			t.Fatal(err)
		}
		switch fault {
		case "missing":
			delete(v, "pre_destroy_recovery")
		case "null":
			v["pre_destroy_recovery"] = json.RawMessage(`null`)
		case "changed":
			changed := *r.PreDestroyRecovery
			changed.FailedRunSHA256 = strings.Repeat("a", 64)
			v["pre_destroy_recovery"] = failedServingWire(t, changed)
		}
		wire := failedServingWire(t, v)
		var baselineOther, alteredOther map[string]json.RawMessage
		if json.Unmarshal(baseWire, &baselineOther) != nil || json.Unmarshal(wire, &alteredOther) != nil {
			t.Fatal("carry guard proposal operands")
		}
		delete(baselineOther, "pre_destroy_recovery")
		delete(alteredOther, "pre_destroy_recovery")
		if !reflect.DeepEqual(baselineOther, alteredOther) {
			t.Fatal("carry vector changed a field outside its sole proof", fault)
		}
		if _, err = tx.ExecContext(ctx, `SAVEPOINT carry_fault`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_retirement_forwards(id,stage,retirement_request_id,preregistration_id,namespace,environment,domain,dimension,integration_instance_id,scope_checksum,profile_name,slot,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16)`, r.ID, r.Stage, r.RetirementRequestID, r.PreregistrationID, r.Namespace, r.Environment, r.Domain, r.Dimension, r.Original.Request.Intent.Tuple.InstanceID, r.Original.Request.Intent.Tuple.ScopeChecksum, r.Original.Request.Intent.Tuple.Profile, r.Original.Request.Intent.Slot, capacity.BusinessCreationSHA256(wire), wire, string(wire), r.RecordedAt)
		var pg *pq.Error
		if !errors.As(err, &pg) || pg.Code != "P0001" || pg.Message != "settled child preserves exact pre-DELETE origin" {
			t.Fatal("sole carried-proof alteration must hit its exact storage guard", fault, err)
		}
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT carry_fault`); err != nil {
			t.Fatal(err)
		}
		results = append(results, map[string]any{"case": fault, "sqlstate": pg.Code, "error": pg.Message, "proposal_sha256": capacity.BusinessCreationSHA256(wire), "rolled_back": true})
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forwards WHERE id=$1`, r.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("carry guard proposals must remain unpersisted", remaining, err)
	}
	preDestroy103Put(t, "M103-M102-CARRY.UNCOMMITTED.PROPOSAL.json", baseWire)
	preDestroy103Put(t, "M103-M102-CARRY-STORAGE-VECTORS.PUBLIC.json", failedServingWire(t, map[string]any{"proposal_id": r.ID, "fixture_only": true, "uncommitted": true, "results": results}))
}

func preDestroy103Off(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) GuestRetirementForwardReadReturn {
	t.Helper()
	r, err := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
	if err != nil {
		t.Fatal("actual fresh owner OFF challenge", err)
	}
	v := f.NativeOffReturn(r, "")
	if _, err = f.FinishStore().RecordGuestRetirementForwardRead(ctx, v); err != nil {
		t.Fatal("actual positive owner OFF", err)
	}
	return v
}

func preDestroy103Waiting(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) GuestRetirementForward {
	t.Helper()
	r, found, err := f.PlanStore().GuestRetirementForwardWaiting(ctx, f.Policy)
	if err != nil || !found {
		t.Fatal("actual retained owner", found, err)
	}
	return r
}

func preDestroy103FailACK(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, id string, missingACK bool) {
	t.Helper()
	result := preReadWorkflowResult(f, f.Intent, id, "failed", "finish-original-retirement")
	if missingACK {
		c, err := finishCapacityDispatchFirstCommitOnce(ctx, f.DB, f.job, result, time.Now().UTC(), nil, nil)
		if err != nil || c.current.FinalizationAckAt != nil {
			t.Fatal("failed return before real ACK", err)
		}
		preReadMissingACKCoalesces(t, f, ctx, c.current)
		if err = acknowledgeCapacityDispatchFinalization(ctx, f.DB, c.current); err != nil {
			t.Fatal("real parent finalization ACK", err)
		}
	} else if err := FinishCapacityDispatch(ctx, f.DB, f.job, result, time.Now().UTC(), nil); err != nil {
		t.Fatal("real failed child finalization ACK", err)
	}
}

func preDestroy103Issue(t *testing.T, f *GuestRetirementForwardRecoveryFixture) model.CapacityMutationIssue {
	t.Helper()
	b := f.Spec.MutationBindings[0]
	d := *b.Slots[f.Pre.Slot-1].DesiredSpec
	d.Capability, d.ExpectedResourceID, d.ExpectedResourceCreatedAt = b.DestroyCapability, f.Request.Intent.Tuple.ResourceID, f.Request.Intent.Tuple.CreatedAt
	return model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(t, d)}
}

func preDestroy103NoFreshAuthority(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	if _, err := f.FinishStore().AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
		t.Fatal("old owner's OFF/floor authorized a fresh owner")
	}
	if _, err := f.FinishStore().IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, preDestroy103Issue(t, f)); err == nil {
		t.Fatal("new claim acquired DELETE before its own fresh barriers")
	}
	preDestroy103NoAuthority(t, f, ctx)
}

func preDestroy103NoAuthority(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	var absent bool
	var bound int
	if err := f.DB.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_authority_absent103($1)`, f.Request.Intent.RequestID).Scan(&absent); err != nil || !absent {
		t.Fatal("no current physical tuple authority across all states/realms", absent, err)
	}
	if err := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&bound); err != nil || bound != 0 {
		t.Fatal("pre-destroy fixture already bound a DELETE", bound, err)
	}
}

func preDestroy103RequestRace(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) GuestRetirementForward {
	t.Helper()
	before := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
	plan := f.PlanStore()
	type answer struct {
		requested bool
		err       error
	}
	out := make(chan answer, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := plan.TryRequestGuestRetirementForwardPreDestroyRecovery(ctx, f.Policy)
			out <- answer{v, e}
		}()
	}
	wg.Wait()
	close(out)
	winners := 0
	for a := range out {
		if a.err != nil && !errors.Is(a.err, ErrCapacityConflict) && !errors.Is(a.err, ErrCapacityLease) {
			t.Fatal("request race storage failure", a.err)
		}
		if a.requested {
			winners++
		}
	}
	if winners != 1 || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != before+1 {
		t.Fatal("competing same real requester calls must append exactly one request", winners)
	}
	r := preDestroy103Waiting(t, f, ctx)
	if r.Mode != GuestRetirementForwardPreDestroyRecoveryMode || r.Stage != "requested" || r.DestroyGrantID != "" || r.Barrier != (CapacityDispatchExecutorBarrier{}) {
		t.Fatal("new source-owned no-write request", r)
	}
	if again, e := plan.TryRequestGuestRetirementForwardPreDestroyRecovery(ctx, f.Policy); e != nil || again {
		t.Fatal("duplicate request was not idempotent HOLD", again, e)
	}
	return r
}

func preDestroy103ClaimRace(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward, oldStore CapacityStore, old model.CapacityIntent) {
	t.Helper()
	// Hold the actual production scope lock before starting the contenders.
	// Their backends must be observed waiting on THIS lock before release.
	barrier, lockErr := f.DB.BeginTx(ctx, nil)
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	defer barrier.Rollback()
	if lockErr = lockMutationScope(ctx, barrier, f.Policy.Metadata.Namespace, f.Spec); lockErr != nil {
		t.Fatal(lockErr)
	}
	var holderPID int
	if lockErr = barrier.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); lockErr != nil {
		t.Fatal(lockErr)
	}
	plan := f.PlanStore()
	issue := preDestroy103Issue(t, f)
	type answer struct {
		intent  model.CapacityIntent
		handled bool
		err     error
		old     bool
	}
	out := make(chan answer, 3)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, _, _, h, e := plan.TryClaimGuestRetirementForward(ctx, f.Policy)
			out <- answer{intent: v, handled: h, err: e}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, e := oldStore.IssueMutation(ctx, f.Policy, old.Generation, old.FencingToken, old.LeaseOwner, issue)
		out <- answer{err: e, old: true}
	}()
	var waitingPIDs []int64
	waitUntil := time.Now().Add(3 * time.Second)
	for time.Now().Before(waitUntil) {
		lockErr = f.DB.QueryRowContext(ctx, `SELECT COALESCE(array_agg(DISTINCT w.pid ORDER BY w.pid),'{}'::integer[]) FROM pg_locks h JOIN pg_locks w ON w.locktype=h.locktype AND w.database IS NOT DISTINCT FROM h.database AND w.classid IS NOT DISTINCT FROM h.classid AND w.objid IS NOT DISTINCT FROM h.objid AND w.objsubid IS NOT DISTINCT FROM h.objsubid WHERE h.pid=$1 AND h.locktype='advisory' AND h.granted AND NOT w.granted`, holderPID).Scan(pq.Array(&waitingPIDs))
		if lockErr != nil || len(waitingPIDs) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Releasing this lock precedes every contender's lease/epoch decision;
	// no timestamp, row, lease or original process barrier is changed.
	unlockErr := barrier.Rollback()
	wg.Wait()
	close(out)
	if lockErr != nil || unlockErr != nil || len(waitingPIDs) != 3 {
		t.Fatal("all three real API backends must wait on the same production lock", waitingPIDs, lockErr, unlockErr)
	}
	preDestroy103Put(t, "M103-LOCK-SERIALIZATION.PUBLIC.json", failedServingWire(t, map[string]any{"holder_pid": holderPID, "waiting_backend_pids": waitingPIDs, "contenders": []string{"old_IssueMutation", "TryClaim_1", "TryClaim_2"}, "pool_limit": f.DB.Stats().MaxOpenConnections, "scope_lock_held_before_contenders": true, "scope_lock_released_before_outcome_assertion": true, "fixture_only": true, "native_authority": false}))
	wins := 0
	for a := range out {
		if a.old {
			if a.err == nil {
				t.Fatal("expired old owner raced a new claim into DELETE authority")
			}
			continue
		}
		if a.err == nil && a.handled {
			wins++
			f.Intent = a.intent
		} else if a.err != nil && !errors.Is(a.err, ErrCapacityConflict) && !errors.Is(a.err, ErrCapacityLease) {
			t.Fatal("claim race storage error", a.err)
		}
	}
	if wins != 1 || f.Intent.Generation != old.Generation || f.Intent.FencingToken != old.FencingToken+1 || f.Intent.LeaseOwner == old.LeaseOwner || f.Intent.RetirementForward == nil || f.Intent.RetirementForward.ID != child.ID {
		t.Fatal("one fresh fence/owner required", wins, f.Intent)
	}
	preDestroy103NoAuthority(t, f, ctx)
}

func preDestroy103RequireProof(t *testing.T, child, parent GuestRetirementForward, off GuestRetirementForwardReadReturn) {
	t.Helper()
	p := child.PreDestroyRecovery
	var keys map[string]json.RawMessage
	if p == nil || json.Unmarshal(failedServingWire(t, p), &keys) != nil || len(keys) != 11 || p.Schema != GuestRetirementForwardPreDestroyRecoverySchema || p.FailedRunID != parent.RunID || p.NativeOffReadID != off.Read.ReadID || p.NativeOffReturnSHA256 != capacity.BusinessCreationSHA256(failedServingWire(t, off)) || child.ParentAdmissionID != parent.ID || child.RootAdmissionID != parent.RootAdmissionID || child.Generation != parent.Generation || child.Fence != parent.Fence || child.DestroyGrantID != "" {
		t.Fatal("closed exact old owner/OFF proof and root lineage", child)
	}
}

type preDestroy103GrantOperand struct {
	id     string
	query  string
	args   []any
	record []byte
}

func preDestroy103Grant(t *testing.T, f *GuestRetirementForwardRecoveryFixture, state, resource, created string, foreign bool) preDestroy103GrantOperand {
	t.Helper()
	b := f.Spec.MutationBindings[0]
	id := uuid.NewString()
	ns, env, domain, dim := f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension
	if foreign {
		ns, env, domain, dim = "declared-foreign-realm", "declared-foreign-environment", "declared-foreign-domain", "declared-foreign-dimension"
	}
	r := map[string]any{"grant": map[string]any{"grant_id": id, "state": state, "capability": b.DestroyCapability, "slot": f.Pre.Slot, "expected_resource_id": resource, "expected_resource_created_at": created}, "binding": b, "policy_id": f.Policy.ID, "workflow_id": f.Workflow.ID, "generation": f.Intent.Generation, "fencing_token": f.Intent.FencingToken, "created_at": time.Now().UTC(), "fixture_only": true}
	query := `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,clock_timestamp()+interval '1 hour',clock_timestamp())`
	wire := failedServingWire(t, r)
	return preDestroy103GrantOperand{id: id, query: query, record: wire, args: []any{id, ns, env, domain, dim, f.Intent.Generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, f.Pre.Slot, state, string(wire)}}
}

func preDestroy103AuthorityVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward) {
	t.Helper()
	// A new, unpersisted proposal exercises admission, not the immutable
	// historical validator for an already accepted requested row.
	child.ID = uuid.NewString()
	results := []map[string]any{}
	for _, state := range []string{"issued", "redeemed", "settled", "confirmed", "rejected", "expired", "compensating", "compensated", "cleanup_closed"} {
		for _, foreign := range []bool{false, true} {
			tx, e := f.DB.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			o := preDestroy103Grant(t, f, state, f.Request.Intent.Tuple.ResourceID, f.Request.Intent.Tuple.CreatedAt, foreign)
			_, e = tx.ExecContext(ctx, o.query, o.args...)
			if state == "cleanup_closed" {
				var pg *pq.Error
				if !errors.As(e, &pg) || pg.Code != "P0001" || pg.Message != "unbound failed expansion grant refused" {
					tx.Rollback()
					t.Fatal("M94 must reject an unbound cleanup_closed grant", foreign, e)
				}
				if e = tx.Rollback(); e != nil {
					t.Fatal(e)
				}
				results = append(results, map[string]any{"state": state, "foreign_realm": foreign, "unbound": true, "storage_refused": "P0001:unbound failed expansion grant refused"})
				continue
			}
			if e != nil {
				tx.Rollback()
				t.Fatal("declared current-tuple authority operand", state, foreign, e)
			}
			var absent, valid bool
			e = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_authority_absent103($1),public.retirement_forward_pre_destroy_recovery_valid103($2::jsonb,$1)`, f.Request.Intent.RequestID, string(failedServingWire(t, child))).Scan(&absent, &valid)
			if e != nil || absent || valid {
				tx.Rollback()
				t.Fatal("any current tuple authority without binding must HOLD", state, foreign, absent, valid, e)
			}
			if e = tx.Rollback(); e != nil {
				t.Fatal(e)
			}
			results = append(results, map[string]any{"state": state, "foreign_realm": foreign, "unbound": true, "authority_absent": absent, "valid": valid})
		}
	}
	preDestroy103NoAuthority(t, f, ctx)
	preDestroy103Put(t, "M103-ALL-STATES-REALMS-AUTHORITY-VECTORS.PUBLIC.json", failedServingWire(t, results))
}

func preDestroy103ProofVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward) {
	t.Helper()
	var base map[string]any
	if json.Unmarshal(failedServingWire(t, child), &base) != nil {
		t.Fatal("proof base")
	}
	results := []map[string]any{}
	for _, fault := range []string{"exact", "extra", "missing", "null", "foreign_schema", "foreign_requester", "foreign_failed_run", "foreign_dispatch", "foreign_off", "prepared_hash", "return_hash", "failed_hash", "dispatch_hash", "deadline", "lease", "wrong_type"} {
		var v map[string]any
		json.Unmarshal(failedServingWire(t, base), &v)
		v["id"] = uuid.NewString()
		p := v["pre_destroy_recovery"].(map[string]any)
		switch fault {
		case "extra":
			p["caller_healthy"] = true
		case "missing":
			delete(p, "dispatch_sha256")
		case "null":
			v["pre_destroy_recovery"] = nil
		case "foreign_schema":
			p["schema"] = "original_unknown_recovery"
		case "foreign_requester":
			p["requesting_run_id"] = uuid.NewString()
		case "foreign_failed_run":
			p["failed_run_id"] = uuid.NewString()
		case "foreign_dispatch":
			p["dispatch_id"] = uuid.NewString()
		case "foreign_off":
			p["native_off_read_id"] = uuid.NewString()
		case "prepared_hash":
			p["native_off_prepared_sha256"] = strings.Repeat("a", 64)
		case "return_hash":
			p["native_off_return_sha256"] = strings.Repeat("b", 64)
		case "failed_hash":
			p["failed_run_sha256"] = strings.Repeat("c", 64)
		case "dispatch_hash":
			p["dispatch_sha256"] = strings.Repeat("d", 64)
		case "deadline":
			p["original_context_deadline"] = "2000-01-01T00:00:00Z"
		case "lease":
			p["original_lease_expires_at"] = "2000-01-01T00:00:00Z"
		case "wrong_type":
			p["dispatch_id"] = true
		}
		var valid bool
		e := f.DB.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_recovery_valid103($1::jsonb,$2) AND public.retirement_forward_continuation_quiet(($1::jsonb)||jsonb_build_object('destroy_grant_id',''),($1::jsonb#>>'{pre_destroy_recovery,requesting_run_id}')::uuid)`, string(failedServingWire(t, v)), f.Request.Intent.RequestID).Scan(&valid)
		if e != nil || valid != (fault == "exact") {
			t.Fatal("complete typed proof validator", fault, valid, e)
		}
		results = append(results, map[string]any{"case": fault, "valid": valid})
	}
	preDestroy103Put(t, "M103-CLOSED-PROOF-VECTORS.PUBLIC.json", failedServingWire(t, results))
}

func preDestroy103HistoryVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward, old GuestRetirementForwardReadReturn) {
	t.Helper()
	// A new, unpersisted proposal exercises admission, not the immutable
	// historical validator for an already accepted requested row.
	child.ID = uuid.NewString()
	results := []map[string]any{}
	for _, fault := range []string{"open_off", "failed_off", "malformed_off", "foreign_off", "open_absence"} {
		tx, e := f.DB.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		c := old.Read
		c.ReadID = uuid.NewString()
		c.IssuedAtCore = time.Now().UTC()
		c.OriginalDeadlineCore = c.IssuedAtCore.Add(time.Second)
		if fault == "foreign_off" {
			c.AdapterSourceCommit = strings.Repeat("f", 40)
		}
		if fault == "open_absence" {
			c.Kind = "absence"
			c.DestroyGrantID = uuid.NewString()
		}
		insert := func(stage string, wire []byte) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_retirement_forward_reads(id,admission_id,retirement_request_id,kind,stage,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,clock_timestamp())`, c.ReadID, c.AdmissionID, c.RetirementRequestID, c.Kind, stage, capacity.BusinessCreationSHA256(wire), wire, string(wire))
			return err
		}
		if e = insert("prepared", failedServingWire(t, c)); e != nil {
			tx.Rollback()
			t.Fatal("append-only declared prepared operand", fault, e)
		}
		if !strings.HasPrefix(fault, "open_") {
			v := old
			v.Read = c
			v.StartedAtCore = c.IssuedAtCore
			v.OriginalReturnedAtCore = c.IssuedAtCore.Add(time.Millisecond)
			switch fault {
			case "failed_off":
				v.CallFailed = true
				v.Status = ""
				v.Plan = nil
			case "malformed_off":
				v.Schema = "declared_unsupported"
			}
			e = insert("returned", failedServingWire(t, v))
			if fault == "malformed_off" {
				var pg *pq.Error
				if !errors.As(e, &pg) || pg.Code != "P0001" || pg.Message != "return cannot replace original challenge or failure" {
					tx.Rollback()
					t.Fatal("unsupported returned schema must retain exact storage refusal", e)
				}
				if e = tx.Rollback(); e != nil {
					t.Fatal(e)
				}
				results = append(results, map[string]any{"case": fault, "storage_refused": "P0001:return cannot replace original challenge or failure"})
				continue
			}
			if e != nil {
				tx.Rollback()
				t.Fatal("declared complete returned operand", fault, e)
			}
		}
		var valid bool
		e = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_recovery_valid103($1::jsonb,$2) AND public.retirement_forward_continuation_quiet(($1::jsonb)||jsonb_build_object('destroy_grant_id',''),($1::jsonb#>>'{pre_destroy_recovery,requesting_run_id}')::uuid)`, string(failedServingWire(t, child)), f.Request.Intent.RequestID).Scan(&valid)
		if e != nil || valid {
			tx.Rollback()
			t.Fatal("no earlier favorable OFF selection after later/open doubt", fault, valid, e)
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
		results = append(results, map[string]any{"case": fault, "valid": valid})
	}
	preDestroy103Put(t, "M103-LATEST-AND-OPEN-READ-VECTORS.PUBLIC.json", failedServingWire(t, results))
}

func preDestroy103QuietVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward) {
	t.Helper()
	// A new, unpersisted proposal exercises admission, not the immutable
	// historical validator for an already accepted requested row.
	child.ID = uuid.NewString()
	for _, fault := range []string{"queued", "unknown", "returned_without_ack", "logical_workflow_busy"} {
		tx, e := f.DB.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		s := f.PlanStore()
		x, e := s.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
		if e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		if e = retirementForwardContinuationQuietTx(ctx, tx, x, "", f.RunID.String()); e != nil {
			tx.Rollback()
			t.Fatal("baseline actual quiet", e)
		}
		if e = continuationTestBusyDispatch(t, f, ctx, tx, fault); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		goErr := retirementForwardContinuationQuietTx(ctx, tx, x, "", f.RunID.String())
		var valid bool
		e = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_recovery_valid103($1::jsonb,$2) AND public.retirement_forward_continuation_quiet(($1::jsonb)||jsonb_build_object('destroy_grant_id',''),($1::jsonb#>>'{pre_destroy_recovery,requesting_run_id}')::uuid)`, string(failedServingWire(t, child)), f.Request.Intent.RequestID).Scan(&valid)
		if e != nil || valid || !errors.Is(goErr, ErrCapacityConflict) {
			tx.Rollback()
			t.Fatal("unknown/unACK work stayed nonquiet in both Source predicates", fault, valid, goErr, e)
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
	}
	// A same-profile survivor CREATE isolates ordinary quiet from the tail's
	// authority-absence predicate; the guard supplies destroy_grant_id="".
	tx, e := f.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	s := f.PlanStore()
	x, e := s.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
	if e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	o := preDestroy103Grant(t, f, "issued", f.members[0].reg.Result.Tuple.ResourceID, f.members[0].reg.Result.Tuple.CreatedAt, false)
	var record map[string]any
	if json.Unmarshal(o.record, &record) != nil {
		tx.Rollback()
		t.Fatal("declared active CREATE record")
	}
	grant := record["grant"].(map[string]any)
	grant["capability"], grant["slot"] = f.Spec.MutationBindings[0].EnsureCapability, 1
	o.args[9], o.args[11] = 1, string(failedServingWire(t, record))
	if _, e = tx.ExecContext(ctx, o.query, o.args...); e != nil {
		tx.Rollback()
		t.Fatal("declared same-profile active CREATE", e)
	}
	var absent, quiet bool
	e = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_authority_absent103($1),public.retirement_forward_continuation_quiet(($2::jsonb)||jsonb_build_object('destroy_grant_id',''),$3::uuid)`, f.Request.Intent.RequestID, string(failedServingWire(t, child)), f.RunID).Scan(&absent, &quiet)
	goErr := retirementForwardContinuationQuietTx(ctx, tx, x, "", f.RunID.String())
	if e != nil || !absent || quiet || !errors.Is(goErr, ErrCapacityConflict) {
		tx.Rollback()
		t.Fatal("active survivor CREATE must isolate shared-profile quiet", absent, quiet, goErr, e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	preDestroy103Put(t, "M103-ACTIVE-CREATE-QUIET.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"tail_authority_absent": absent, "profile_quiet_sql": quiet, "profile_quiet_go": false, "destroy_grant_default": "", "survivor_slot": 1, "fixture_only": true, "native_authority": false}))
}

func preDestroy103Custody(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ids, runs []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	queries := map[string]string{"frames": `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forwards r WHERE id=ANY($1::uuid[])`, "reads": `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forward_reads r WHERE admission_id=ANY($1::uuid[])`, "jobs": `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb)::text FROM public.capacity_dispatch_jobs r WHERE run_id=ANY($1::uuid[])`, "runs": `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb)::text FROM public.workflow_runs r WHERE id=ANY($1::uuid[])`}
	for name, q := range queries {
		arg := ids
		if name == "jobs" || name == "runs" {
			arg = runs
		}
		var raw []byte
		if e := f.DB.QueryRow(q, pq.Array(arg)).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		out[name] = capacity.BusinessCreationSHA256(raw)
	}
	return out
}
func preDestroy103RequireCustody(t *testing.T, f *GuestRetirementForwardRecoveryFixture, want map[string]string, ids, runs []string) {
	t.Helper()
	if !reflect.DeepEqual(want, preDestroy103Custody(t, f, ids, runs)) {
		t.Fatal("historical original frames, reads and failed ACKs changed")
	}
}

func preDestroy103OneCurrentDelete(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, id string) {
	t.Helper()
	var n, bound int
	b := f.Spec.MutationBindings[0]
	if e := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND grant_record#>>'{grant,capability}'=$5 AND grant_record#>>'{grant,expected_resource_id}'=$6 AND grant_record#>>'{grant,expected_resource_created_at}'=$7`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, f.Pre.Slot, b.DestroyCapability, f.Request.Intent.Tuple.ResourceID, f.Request.Intent.Tuple.CreatedAt).Scan(&n); e != nil || n != 1 {
		t.Fatal("one first current incarnation destroy grant", n, e)
	}
	if e := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1 AND destroy_grant_id=$2`, f.Request.Intent.RequestID, id).Scan(&bound); e != nil || bound != 1 {
		t.Fatal("one exact original DELETE binding", bound, e)
	}
}

// Run only the actual Down's first guard block inside a rollback transaction.
// No Goose history row is modified and no retained proof is removed.
func preDestroy103DownRefusal(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, phase string) {
	t.Helper()
	migration, e := os.ReadFile(filepath.Join(failedServingRepositoryRoot(t), "db", "migrations", "00103_guest_retirement_pre_destroy_recovery.sql"))
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.SplitN(string(migration), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("actual103 Down Source required")
	}
	start := strings.Index(parts[1], "-- +goose StatementBegin")
	if start < 0 {
		t.Fatal("actual103 Down first block")
	}
	block := parts[1][start+len("-- +goose StatementBegin"):]
	end := strings.Index(block, "-- +goose StatementEnd")
	if end < 0 {
		t.Fatal("actual103 Down first block end")
	}
	block = block[:end]
	tx, e := f.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.ExecContext(ctx, block)
	var pg *pq.Error
	if !errors.As(e, &pg) || pg.Code != "P0001" || pg.Message != "used pre-DELETE recovery proof is permanent provenance" {
		tx.Rollback()
		t.Fatal("retained new mode or carried M102 proof must refuse actual Down", phase, e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	preDestroy103Put(t, "M103-DOWN-REFUSAL-"+phase+".PUBLIC.json", failedServingWire(t, map[string]any{"phase": phase, "sqlstate": "P0001", "message": pg.Message, "actual_Down_block_sha256": capacity.BusinessCreationSHA256([]byte(block)), "rolled_back": true, "retained_provenance_unchanged": true, "fixture_only": true, "native_authority": false}))
}

func preDestroy103Put(t *testing.T, name string, raw []byte) {
	t.Helper()
	closedRead102Put(t, name, raw)
}

// The expected semantic catalog inventory is fixed below, not inferred from
// whatever a migration happened to change. Whole originals precede assertions.
func preDestroy103Migration(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	root := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if e := goose.UpToContext(ctx, f.DB, root, 102); e != nil {
		t.Fatal("actual schema102 predecessor", e)
	}
	before := installedReadinessCatalog(t, f.DB)
	preDestroy103Put(t, "M103-PG-BEFORE102-CATALOG.original.json", before)
	if e := goose.UpToContext(ctx, f.DB, root, 103); e != nil {
		t.Fatal("actual additive schema103", e)
	}
	after := installedReadinessCatalog(t, f.DB)
	preDestroy103Put(t, "M103-PG-AFTER103-CATALOG.original.json", after)
	var a, b map[string]json.RawMessage
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil || len(a) != len(b) {
		t.Fatal("whole actual public catalogs")
	}
	for _, key := range []string{"server_version_num", "columns", "indexes", "triggers"} {
		if !bytes.Equal(a[key], b[key]) {
			t.Fatal("M103 changed unrelated catalog", key)
		}
	}
	var wa, wb string
	var ha, hb []map[string]any
	if json.Unmarshal(a["history_wire"], &wa) != nil || json.Unmarshal(b["history_wire"], &wb) != nil || json.Unmarshal([]byte(wa), &ha) != nil || json.Unmarshal([]byte(wb), &hb) != nil || len(hb) != len(ha)+1 || ha[len(ha)-1]["version_id"] != float64(102) || !reflect.DeepEqual(ha, hb[:len(ha)]) || hb[len(ha)]["version_id"] != float64(103) || hb[len(ha)]["is_applied"] != true {
		t.Fatal("sole103 history append")
	}
	var fa, fb []map[string]any
	json.Unmarshal(a["functions"], &fa)
	json.Unmarshal(b["functions"], &fb)
	key := func(r map[string]any) string { return r["name"].(string) + "(" + r["arguments"].(string) + ")" }
	by := map[string]map[string]any{}
	for _, r := range fb {
		by[key(r)] = r
	}
	changed := []string{}
	for _, r := range fa {
		n, ok := by[key(r)]
		if !ok {
			t.Fatal("removed old function", r["name"])
		}
		if !reflect.DeepEqual(r, n) {
			changed = append(changed, r["name"].(string))
		}
		delete(by, key(r))
	}
	added := []string{}
	for _, r := range by {
		added = append(added, r["name"].(string))
	}
	sort.Strings(changed)
	sort.Strings(added)
	if !reflect.DeepEqual(changed, []string{"guard_retirement_forward"}) || !reflect.DeepEqual(added, []string{"retirement_forward_pre_destroy_authority_absent103", "retirement_forward_pre_destroy_recovery_valid103"}) {
		t.Fatal("exact additive103 functions required", changed, added)
	}
	// Constraint inventory is completed against the primary author's fixed
	// names before Source freeze; no arbitrary new constraint is accepted.
	preDestroy103Constraints(t, a["constraints"], b["constraints"])
	migration, e := os.ReadFile(filepath.Join(root, "00103_guest_retirement_pre_destroy_recovery.sql"))
	if e != nil {
		t.Fatal(e)
	}
	up := strings.SplitN(string(migration), "-- +goose Down", 2)[0]
	for _, name := range append(added, changed...) {
		start := strings.Index(up, "CREATE OR REPLACE FUNCTION public."+name+"(")
		if start < 0 {
			t.Fatal("exact Source function missing", name)
		}
		section := up[start:]
		pos := strings.Index(section, "AS $$")
		if pos < 0 {
			t.Fatal("Source body missing", name)
		}
		body := strings.SplitN(section[pos+5:], "$$;", 2)[0]
		var actual string
		if e = f.DB.QueryRowContext(ctx, `SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$1`, name).Scan(&actual); e != nil || actual != body {
			t.Fatal("installed103 body differs from signed Source", name, e)
		}
	}
	preDestroy103Put(t, "M103-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "pre_destroy_recovery103_whole_public_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "migration103_sha256": capacity.BusinessCreationSHA256(migration), "whole_history_sole103_append": true, "changed_functions": changed, "added_functions": added, "all_other_public_objects_exact": true, "fixture_only": true, "native_authority": false}))
}

func preDestroy103Constraints(t *testing.T, old, new json.RawMessage) {
	t.Helper()
	var a, b []map[string]any
	if json.Unmarshal(old, &a) != nil || json.Unmarshal(new, &b) != nil {
		t.Fatal("whole constraints")
	}
	by := map[string]map[string]any{}
	for _, r := range b {
		if r["validated"] != true {
			t.Fatal("unvalidated public constraint", r["name"])
		}
		by[r["table"].(string)+"/"+r["name"].(string)] = r
	}
	for _, r := range a {
		k := r["table"].(string) + "/" + r["name"].(string)
		if k == "capacity_guest_retirement_forwards/retirement_forward_mode97" {
			if by[k] != nil {
				t.Fatal("old mode97 constraint remained")
			}
			continue
		}
		if !reflect.DeepEqual(r, by[k]) {
			t.Fatal("unrelated constraint changed", k)
		}
		delete(by, k)
	}
	if len(by) != 2 || by["capacity_guest_retirement_forwards/retirement_forward_mode103"] == nil || by["capacity_guest_retirement_forwards/retirement_forward_pre_destroy103"] == nil {
		t.Fatal("exact mode+proof constraints required", by)
	}
}
