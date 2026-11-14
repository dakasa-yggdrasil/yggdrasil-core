//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// Called only after every existing normal-finish child has released the global
// fixture mutex. These are declared PG operands, never provider execution.
func retirementForwardClosedFailedRead102Regression(t *testing.T) {
	t.Helper()
	// Declare the complete43-read workload's lease before the first policy,
	// intent or original frame. Both successors must await real60s expiry.
	f := newGuestRetirementForwardRecoveryFixture(t, "aws", 2, 4, 60, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	oldValidator := closedRead102Migration(t, f, ctx)
	parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil || parent.Mode != "live" || parent.Stage != "admitted" {
		t.Fatal("actual LIVE origin required for M102", parent, err, f.AdmissionDiagnostics())
	}
	receipt := forwardTestSettledDestroy(t, f, ctx, true)
	current, found, err := f.Store.GuestRetirementForwardWaiting(ctx, f.Policy)
	if err != nil || !found || current.ID != parent.ID || current.Mode != "live" || current.Stage != "off_qualified" || receipt.Grant.State != "settled" || receipt.Outcome != "accepted" || !receipt.TransportCompleted {
		t.Fatal("LIVE/off-qualified owner and one accepted settled DELETE", current, receipt, err)
	}
	parent = current
	if requested, e := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); e != nil || requested {
		t.Fatal("still-running LIVE owner became a failed continuation", requested, e)
	}
	pendingIDs := make([]string, 0, 43)
	for i := 0; i < 43; i++ {
		read, e := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
		if e != nil {
			t.Fatal("genuine earlier absence challenge", i, e)
		}
		if proof, e := f.FinishStore().RecordGuestRetirementForwardRead(ctx, continuationTestPending(t, f, read, receipt)); !errors.Is(e, ErrGuestRetirementForwardNativePending) || proof.ResourceAbsent {
			t.Fatal("genuine earlier Pending must stay Pending", i, e)
		}
		pendingIDs = append(pendingIDs, read.ReadID)
	}
	prepared, returned := closedRead102ExpiredRead(t, f, ctx, receipt.Grant.GrantID)
	// The real return is committed first. Missing ACK cannot create a runnable
	// replacement; the ordinary finalization API then records its actual ACK.
	result := preReadWorkflowResult(f, f.Intent, parent.ID, "failed", "finish-original-retirement")
	committed, err := finishCapacityDispatchFirstCommitOnce(ctx, f.DB, f.job, result, time.Now().UTC(), nil, nil)
	if err != nil || committed.current.FinalizationAckAt != nil {
		t.Fatal("real failed parent return before ACK", err)
	}
	preReadMissingACKCoalesces(t, f, ctx, committed.current)
	if err = acknowledgeCapacityDispatchFinalization(ctx, f.DB, committed.current); err != nil {
		t.Fatal("actual parent failure ACK", err)
	}
	before := f.PreservedOriginals()
	custody := closedRead102Custody(t, f, []string{parent.ID})
	closedRead102Put(t, "M102-PARENT-FAILURE-INPUTS.original.json", failedServingWire(t, map[string]any{"fixture_only": true, "native_authority": false, "parent": parent, "pending_read_ids": pendingIDs, "prepared": closedRead102RowJSON(t, prepared), "returned": closedRead102RowJSON(t, returned), "custody": custody}))
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	first := continuationTestRequest(t, f, ctx)
	closedRead102RequireProof(t, first, parent.ID, prepared, returned)
	closedRead102QuietVectors(t, f, ctx, first, receipt.Grant.GrantID)
	closedRead102ProofVectors(t, f, first, oldValidator)
	closedRead102HistoryVectors(t, f, ctx, parent, first, receipt, prepared, returned)
	firstOwner := f.Intent
	preReadClaim(t, f, ctx, first)
	if f.Intent.Generation != firstOwner.Generation || f.Intent.FencingToken != firstOwner.FencingToken+1 || f.Intent.LeaseOwner == firstOwner.LeaseOwner || preReadOwnRows(t, f, first.ID) != 0 {
		t.Fatal("first new fence must retain zero own reads before its declared failure")
	}
	f.FinishFailedRun("finish-original-retirement")
	// This newly claimed child has no own read and has just recorded its real
	// failed ACK. Prove that ACK cannot replace its still-live lease before
	// spending time on unrelated pure pair operands; never renew any clock.
	if f.Intent.LeaseExpiresAt == nil || !f.Intent.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("fresh failed child's lease must still be live after its real ACK")
	}
	if requested, e := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); e != nil || requested {
		t.Fatal("ACK did not replace the failed child's unexpired lease", requested, e)
	}
	closedRead102PairVectors(t, f, prepared, returned)
	if !reflect.DeepEqual(before, f.PreservedOriginals()) || !reflect.DeepEqual(custody, closedRead102Custody(t, f, []string{parent.ID})) {
		t.Fatal("first read-only child rewrote its LIVE parent or original SDK custody")
	}
	secondCustody := closedRead102Custody(t, f, []string{parent.ID, first.ID})
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	second := continuationTestRequest(t, f, ctx)
	closedRead102RequireProof(t, second, first.ID, prepared, returned)
	if !reflect.DeepEqual(first.Continuation.ClosedFailedRead, second.Continuation.ClosedFailedRead) || preReadOwnRows(t, f, first.ID) != 0 {
		t.Fatal("M96 zero-own-read repeat changed or searched behind its fixed failure anchor")
	}
	preReadClaim(t, f, ctx, second)
	if _, e := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", ""); !errors.Is(e, ErrCapacityConflict) {
		t.Fatal("read-only continuation acquired a new OFF operation", e)
	}
	var grantsBefore int
	if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, f.Policy.Metadata.Namespace).Scan(&grantsBefore); err != nil {
		t.Fatal(err)
	}
	// Existing completion requires fresh survivor canaries/inventory, a NEW
	// own absence pair and Confirm on the same original accepted DELETE.
	forwardTestComplete(t, f, ctx)
	if preReadOwnRows(t, f, second.ID) != 2 {
		t.Fatal("fresh own prepared/returned absence pair was not retained")
	}
	if !reflect.DeepEqual(before, f.PreservedOriginals()) || !reflect.DeepEqual(secondCustody, closedRead102Custody(t, f, []string{parent.ID, first.ID})) {
		t.Fatal("new read/Confirm rewrote failed ACKs, old reads, frames or SDK settlement")
	}
	var grantsAfter, bindings int
	if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, f.Policy.Metadata.Namespace).Scan(&grantsAfter); err != nil || grantsAfter != grantsBefore {
		t.Fatal("continuation minted another provider grant", grantsBefore, grantsAfter, err)
	}
	if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&bindings); err != nil || bindings != 1 {
		t.Fatal("the original settled DELETE lost its unique binding", bindings, err)
	}
	if err = FinishCapacityDispatch(ctx, f.DB, f.job, preReadWorkflowResult(f, f.Intent, second.ID, "succeeded", ""), time.Now().UTC(), nil); err != nil {
		t.Fatal("actual successful new owner finalization ACK", err)
	}
	var acknowledged bool
	if err = f.DB.QueryRow(`SELECT j.state='returned' AND j.return_status='succeeded' AND j.finalization_ack_at>=j.returned_at AND w.status='succeeded' AND w.finished_at=j.returned_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.job.JobID).Scan(&acknowledged); err != nil || !acknowledged {
		t.Fatal("successful completion must retain the real same-job/run ACK", acknowledged, err)
	}
	closedRead102Put(t, "M102-CLOSED-FAILED-READ.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "closed_failed_read_continuation102_pg_fixture_v1", "source_commit": capacity.CurrentGuestCoreSource(), "live_parent_off_qualified": true, "earlier_authenticated_Pending": len(pendingIDs), "absolute_latest_failure": returned.ID, "prepared_sha256": prepared.SHA256, "returned_sha256": returned.SHA256, "both_natural_leases_expired": true, "real_parent_and_child_failed_ACKs": true, "missing_ACK_coalesces_no_new_requester": true, "first_child": first.ID, "repeat_child": second.ID, "same_failure_anchor_zero_own_read_repeat": true, "fresh_own_absence_confirm_terminal_and_success_ACK": true, "old_originals_custody_unchanged": true, "no_new_OFF_DELETE_or_grant": true, "fixture_only": true, "native_cloud": false, "Root_acceptance": false}))
}

func closedRead102ExpiredRead(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, destroy string) (retirementForwardClosedReadRow, retirementForwardClosedReadRow) {
	t.Helper()
	readCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	read, err := f.FinishStore().PrepareGuestRetirementForwardRead(readCtx, f.Request.Intent.RequestID, "absence", destroy)
	if err != nil {
		t.Fatal("actual bounded final absence challenge", err)
	}
	started := time.Now().UTC()
	// A declared call waits its ORIGINAL context; no row or deadline is edited.
	call := func(c context.Context) error { <-c.Done(); return c.Err() }
	callErr := call(readCtx)
	if !errors.Is(callErr, context.DeadlineExceeded) || !errors.Is(readCtx.Err(), context.DeadlineExceeded) {
		t.Fatal("the actual original call context did not expire", callErr)
	}
	failed := GuestRetirementForwardReadReturn{Schema: GuestRetirementForwardReadReturnSchema, Read: read, StartedAtCore: started, OriginalReturnedAtCore: time.Now().UTC(), CallFailed: callErr != nil, OriginalContextFailed: readCtx.Err() != nil}
	if proof, e := f.FinishStore().RecordGuestRetirementForwardRead(ctx, failed); !errors.Is(e, ErrCapacityConflict) || proof.ResourceAbsent {
		t.Fatal("closed contextual failure became qualified absence", proof, e)
	}
	load := func(stage string) retirementForwardClosedReadRow {
		var r retirementForwardClosedReadRow
		if e := f.DB.QueryRow(`SELECT id::text,admission_id::text,retirement_request_id::text,kind,stage,record_sha256,original_wire,original_record::text,recorded_at FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage=$2`, read.ReadID, stage).Scan(&r.ID, &r.AdmissionID, &r.RetirementRequestID, &r.Kind, &r.Stage, &r.SHA256, &r.Wire, &r.Record, &r.RecordedAt); e != nil {
			t.Fatal("whole final failed pair", stage, e)
		}
		return r
	}
	p, r := load("prepared"), load("returned")
	if _, valid := retirementForwardClosedFailedReadPairValid(p, r); !valid {
		t.Fatal("actual empty-status failed pair must match the new production classifier")
	}
	return p, r
}

func closedRead102RequireProof(t *testing.T, child GuestRetirementForward, parent string, prepared, returned retirementForwardClosedReadRow) {
	t.Helper()
	p := child.Continuation
	if child.Mode != GuestRetirementForwardContinuationMode || child.ParentAdmissionID != parent || p == nil || p.Schema != GuestRetirementForwardClosedFailedReadContinuationSchema || p.PendingReadID != "" || p.PendingReadSHA256 != "" || p.ClosedFailedRead == nil || p.ClosedFailedRead.ReadID != returned.ID || p.ClosedFailedRead.PreparedSHA256 != prepared.SHA256 || p.ClosedFailedRead.ReturnedSHA256 != returned.SHA256 {
		t.Fatal("truthful closed-failure proof must not relabel one of43 earlier Pending rows", child)
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(failedServingWire(t, p), &outer) != nil || len(outer) != 11 {
		t.Fatal("exact old10 plus optional closed_failed_read field required")
	}
	var inner map[string]json.RawMessage
	if json.Unmarshal(outer["closed_failed_read"], &inner) != nil || len(inner) != 3 {
		t.Fatal("exact read/prepared/returned three-field custody required")
	}
}

func closedRead102RowJSON(t *testing.T, r retirementForwardClosedReadRow) []byte {
	t.Helper()
	return failedServingWire(t, map[string]any{"id": r.ID, "admission_id": r.AdmissionID, "retirement_request_id": r.RetirementRequestID, "kind": r.Kind, "stage": r.Stage, "record_sha256": r.SHA256, "original_wire": "\\x" + hex.EncodeToString(r.Wire), "original_record": json.RawMessage(r.Record), "recorded_at": r.RecordedAt.UTC().Format(time.RFC3339Nano)})
}

func closedRead102PairVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, prepared, returned retirementForwardClosedReadRow) {
	t.Helper()
	clone := func(r retirementForwardClosedReadRow) retirementForwardClosedReadRow {
		r.Wire = append([]byte(nil), r.Wire...)
		r.Record = append([]byte(nil), r.Record...)
		return r
	}
	seal := func(r *retirementForwardClosedReadRow, wire []byte) {
		r.Wire = wire
		r.Record = append([]byte(nil), wire...)
		r.SHA256 = capacity.BusinessCreationSHA256(wire)
	}
	changeReturn := func(r *retirementForwardClosedReadRow, change func(*GuestRetirementForwardReadReturn)) {
		var v GuestRetirementForwardReadReturn
		if json.Unmarshal(r.Wire, &v) != nil {
			t.Fatal("actual return decode")
		}
		change(&v)
		seal(r, failedServingWire(t, v))
	}
	changeRead := func(p, r *retirementForwardClosedReadRow, change func(*GuestRetirementForwardRead)) {
		var v GuestRetirementForwardRead
		var out GuestRetirementForwardReadReturn
		if json.Unmarshal(p.Wire, &v) != nil || json.Unmarshal(r.Wire, &out) != nil {
			t.Fatal("actual pair decode")
		}
		change(&v)
		out.Read = v
		seal(p, failedServingWire(t, v))
		seal(r, failedServingWire(t, out))
	}
	type vector struct {
		name   string
		valid  bool
		change func(*retirementForwardClosedReadRow, *retirementForwardClosedReadRow)
	}
	vectors := []vector{
		{"genuine_control", true, func(p, r *retirementForwardClosedReadRow) {}},
		{"started_at_deadline_is_not_forbidden", true, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.StartedAtCore = v.Read.OriginalDeadlineCore })
		}},
		{"returned_exactly_deadline", true, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.OriginalReturnedAtCore = v.Read.OriginalDeadlineCore })
		}},
		{"returned_one_ns_before_deadline", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) {
				v.OriginalReturnedAtCore = v.Read.OriginalDeadlineCore.Add(-time.Nanosecond)
			})
		}},
		{"started_before_issue", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.StartedAtCore = v.Read.IssuedAtCore.Add(-time.Nanosecond) })
		}},
		{"returned_before_started", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) {
				v.StartedAtCore = v.OriginalReturnedAtCore.Add(time.Nanosecond)
			})
		}},
		{"deadline_over_five_seconds", false, func(p, r *retirementForwardClosedReadRow) {
			changeRead(p, r, func(v *GuestRetirementForwardRead) {
				v.OriginalDeadlineCore = v.IssuedAtCore.Add(5*time.Second + time.Nanosecond)
			})
		}},
		{"empty_creator_source", false, func(p, r *retirementForwardClosedReadRow) {
			changeRead(p, r, func(v *GuestRetirementForwardRead) { v.AdapterSourceCommit = "" })
		}},
		{"foreign_shaped_creator_source", false, func(p, r *retirementForwardClosedReadRow) {
			changeRead(p, r, func(v *GuestRetirementForwardRead) { v.AdapterSourceCommit = strings.Repeat("Z", 40) })
		}},
		{"nil_destroy_UUID", false, func(p, r *retirementForwardClosedReadRow) {
			changeRead(p, r, func(v *GuestRetirementForwardRead) { v.DestroyGrantID = uuid.Nil.String() })
		}},
		{"uppercase_destroy_UUID", false, func(p, r *retirementForwardClosedReadRow) {
			changeRead(p, r, func(v *GuestRetirementForwardRead) { v.DestroyGrantID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" })
		}},
		{"observed_is_not_failed", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.Status = "observed" })
		}},
		{"false_call_failed", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.CallFailed = false })
		}},
		{"false_context_failed", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.OriginalContextFailed = false })
		}},
		{"challenge_mismatch", false, func(p, r *retirementForwardClosedReadRow) {
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) { v.Read.ReadID = uuid.NewString() })
		}},
		{"foreign_row_parent", false, func(p, r *retirementForwardClosedReadRow) { r.AdmissionID = uuid.NewString() }},
		{"foreign_row_retirement", false, func(p, r *retirementForwardClosedReadRow) { r.RetirementRequestID = uuid.NewString() }},
		{"foreign_row_kind", false, func(p, r *retirementForwardClosedReadRow) { r.Kind = "off" }},
		{"wrong_stage", false, func(p, r *retirementForwardClosedReadRow) { r.Stage = "prepared" }},
		{"wire_SHA_mismatch", false, func(p, r *retirementForwardClosedReadRow) { r.SHA256 = strings.Repeat("f", 64) }},
		{"wire_record_mismatch", false, func(p, r *retirementForwardClosedReadRow) { r.Record = []byte(`{}`) }},
		{"returned_PG_before_prepared", false, func(p, r *retirementForwardClosedReadRow) { r.RecordedAt = p.RecordedAt.Add(-time.Microsecond) }},
		{"returned_PG_before_actual_Core_return", false, func(p, r *retirementForwardClosedReadRow) {
			var v GuestRetirementForwardReadReturn
			json.Unmarshal(r.Wire, &v)
			r.RecordedAt = v.OriginalReturnedAtCore.Add(-time.Microsecond)
		}},
	}
	for _, flag := range []string{"call_failed", "original_context_failed"} {
		for _, bad := range []string{"null", `"true"`, "1"} {
			flag, bad := flag, bad
			vectors = append(vectors, vector{flag + "_type_" + bad, false, func(p, r *retirementForwardClosedReadRow) {
				before := []byte(`"` + flag + `":true`)
				if bytes.Count(r.Wire, before) != 1 {
					t.Fatal("one original bool flag required")
				}
				seal(r, bytes.Replace(r.Wire, before, []byte(`"`+flag+`":`+bad), 1))
			}})
		}
	}
	for _, extra := range []string{`"plan":null`, `"observation":null`, `"original_destroy_receipt":null`, `"observer_source_commit":""`, `"original_observer_return":""`, `"caller_proof":true`} {
		extra := extra
		vectors = append(vectors, vector{"extra_" + extra, false, func(p, r *retirementForwardClosedReadRow) {
			seal(r, append(append(append([]byte(nil), r.Wire[:len(r.Wire)-1]...), ','), []byte(extra+"}")...))
		}})
	}
	var actualRead GuestRetirementForwardRead
	if json.Unmarshal(prepared.Wire, &actualRead) != nil {
		t.Fatal("actual tuple slot operand")
	}
	actualSlot, err := json.Marshal(actualRead.Tuple.Slot)
	if err != nil {
		t.Fatal(err)
	}
	replaceSlot := func(row *retirementForwardClosedReadRow, replacement string) {
		key := append([]byte(`"slot":`), actualSlot...)
		if bytes.Count(row.Wire, key) != 1 {
			t.Fatal("exact one genuine tuple slot")
		}
		seal(row, bytes.Replace(row.Wire, key, []byte(`"slot":`+replacement), 1))
	}
	for _, bad := range []string{"true", `"2"`, "2.5", "9223372036854775808"} {
		bad := bad
		vectors = append(vectors, vector{"tuple_slot_type_or_overflow_" + bad, false, func(p, r *retirementForwardClosedReadRow) {
			replaceSlot(p, bad)
			replaceSlot(r, bad)
		}})
	}
	vectors = append(vectors,
		vector{"record_wire_integer_alias_above_2pow53", false, func(p, r *retirementForwardClosedReadRow) {
			replaceSlot(p, "9007199254740992")
			replaceSlot(r, "9007199254740992")
			r.Record = bytes.Replace(r.Record, []byte(`"slot":9007199254740992`), []byte(`"slot":9007199254740993`), 1)
		}},
		vector{"duplicate_top_level_bool", false, func(p, r *retirementForwardClosedReadRow) {
			seal(r, append(append([]byte(nil), r.Wire[:len(r.Wire)-1]...), []byte(`,"call_failed":true}`)...))
		}},
		vector{"noncanonical_wire_whitespace", false, func(p, r *retirementForwardClosedReadRow) {
			seal(r, append([]byte(" "), r.Wire...))
		}},
		vector{"invalid_calendar_date", false, func(p, r *retirementForwardClosedReadRow) {
			var v GuestRetirementForwardReadReturn
			if json.Unmarshal(r.Wire, &v) != nil {
				t.Fatal("actual returned clock operand")
			}
			old := []byte(`"original_returned_at_core":"` + v.OriginalReturnedAtCore.Format(time.RFC3339Nano) + `"`)
			if bytes.Count(r.Wire, old) != 1 {
				t.Fatal("exact original returned clock")
			}
			seal(r, bytes.Replace(r.Wire, old, []byte(`"original_returned_at_core":"2026-02-30T00:00:00Z"`), 1))
		}},
		vector{"deadline_one_ns_rollover_reversal", false, func(p, r *retirementForwardClosedReadRow) {
			at := time.Date(2026, time.November, 11, 0, 0, 0, 999999999, time.UTC)
			changeRead(p, r, func(v *GuestRetirementForwardRead) {
				v.IssuedAtCore, v.OriginalDeadlineCore = at, at.Add(time.Nanosecond)
			})
			changeReturn(r, func(v *GuestRetirementForwardReadReturn) {
				v.StartedAtCore, v.OriginalReturnedAtCore = at, at
			})
		}},
	)
	results := []map[string]any{}
	for _, v := range vectors {
		p, r := clone(prepared), clone(returned)
		v.change(&p, &r)
		_, goOK := retirementForwardClosedFailedReadPairValid(p, r)
		var sqlOK bool
		err := f.DB.QueryRow(`SELECT public.retirement_forward_closed_failed_read102_pair_valid(jsonb_populate_record(NULL::public.capacity_guest_retirement_forward_reads,$1::jsonb),jsonb_populate_record(NULL::public.capacity_guest_retirement_forward_reads,$2::jsonb))`, string(closedRead102RowJSON(t, p)), string(closedRead102RowJSON(t, r))).Scan(&sqlOK)
		if err != nil || goOK != v.valid || sqlOK != v.valid {
			t.Fatal("same full pair Go/SQL independent predicate mismatch", v.name, goOK, sqlOK, v.valid, err)
		}
		results = append(results, map[string]any{"case": v.name, "Go": goOK, "SQL": sqlOK, "expected": v.valid})
	}
	closedRead102Put(t, "M102-PAIR-GO-SQL-VECTORS.PUBLIC.json", failedServingWire(t, results))
}

func closedRead102ProofVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, child GuestRetirementForward, oldValidator string) {
	t.Helper()
	ctx := context.Background()
	conn, err := f.DB.Conn(ctx)
	if err != nil {
		t.Fatal("same-session old101 predicate control", err)
	}
	defer conn.Close()
	oldValidator = strings.Replace(oldValidator, "CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_valid(", "CREATE OR REPLACE FUNCTION pg_temp.closed_read102_old101_valid(", 1)
	if _, err := conn.ExecContext(ctx, oldValidator); err != nil {
		t.Fatal("actual schema101 validator control", err)
	}
	valid := func(query string, wire []byte) bool {
		var ok bool
		if err := conn.QueryRowContext(ctx, query, string(wire), f.Request.Intent.RequestID).Scan(&ok); err != nil {
			t.Fatal("actual continuation predicate", err)
		}
		return ok
	}
	original := failedServingWire(t, child)
	if !valid(`SELECT public.retirement_forward_continuation_valid($1::jsonb,$2::uuid)`, original) || valid(`SELECT pg_temp.closed_read102_old101_valid($1::jsonb,$2::uuid)`, original) {
		t.Fatal("new production proof must pass102 and fail exact old101 SQL")
	}
	for _, fault := range []string{"missing_closed", "extra_closed", "read_id", "prepared_sha256", "returned_sha256", "pending_read_id", "pending_read_sha256", "failed_run_id", "failed_run_sha256", "dispatch_id", "dispatch_sha256", "destroy_grant_sha256", "delete_eligibility_sha256", "requesting_run_id", "parent_admission_id", "root_admission_id"} {
		var r map[string]any
		if json.Unmarshal(original, &r) != nil {
			t.Fatal("actual requested frame decode")
		}
		p := r["continuation"].(map[string]any)
		switch fault {
		case "missing_closed":
			delete(p, "closed_failed_read")
		case "extra_closed":
			p["closed_failed_read"].(map[string]any)["replacement_authority"] = true
		case "read_id", "prepared_sha256", "returned_sha256":
			value := strings.Repeat("f", 64)
			if fault == "read_id" {
				value = uuid.NewString()
			}
			p["closed_failed_read"].(map[string]any)[fault] = value
		case "parent_admission_id", "root_admission_id":
			r[fault] = uuid.NewString()
		case "pending_read_id":
			p[fault] = uuid.NewString()
		case "pending_read_sha256":
			p[fault] = strings.Repeat("f", 64)
		default:
			value := uuid.NewString()
			if strings.HasSuffix(fault, "sha256") {
				value = strings.Repeat("f", 64)
			}
			p[fault] = value
		}
		if valid(`SELECT public.retirement_forward_continuation_valid($1::jsonb,$2::uuid)`, failedServingWire(t, r)) {
			t.Fatal("SQL accepted forged full continuation custody", fault)
		}
	}
}

func closedRead102QuietVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, parent GuestRetirementForward, destroy string) {
	t.Helper()
	for _, fault := range []string{"queued", "unknown", "returned_without_ack", "logical_workflow_busy"} {
		tx, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		s := f.PlanStore()
		x, err := s.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = retirementForwardContinuationQuietTx(ctx, tx, x, destroy, f.RunID.String()); err != nil {
			tx.Rollback()
			t.Fatal("eligible pre-negative Go quiet", err)
		}
		var baseline bool
		if err = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_continuation_quiet($1::jsonb,$2::uuid)`, string(failedServingWire(t, parent)), f.RunID).Scan(&baseline); err != nil || !baseline {
			tx.Rollback()
			t.Fatal("eligible pre-negative SQL quiet", baseline, err)
		}
		if err = continuationTestBusyDispatch(t, f, ctx, tx, fault); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var sqlQuiet bool
		err = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_continuation_quiet($1::jsonb,$2::uuid)`, string(failedServingWire(t, parent)), f.RunID).Scan(&sqlQuiet)
		goErr := retirementForwardContinuationQuietTx(ctx, tx, x, destroy, f.RunID.String())
		if err != nil || sqlQuiet || !errors.Is(goErr, ErrCapacityConflict) {
			tx.Rollback()
			t.Fatal("UNKNOWN/unACK/foreign busy work must remain HOLD in both predicates", fault, sqlQuiet, goErr, err)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
}

// Append only new declared diagnostic operands inside a rollback transaction.
// No sealed row, original timestamp or accepted SDK record is ever rewritten.
func closedRead102HistoryVectors(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, parent, child GuestRetirementForward, receipt model.CapacityMutationReceipt, prepared, returned retirementForwardClosedReadRow) {
	t.Helper()
	for _, fault := range []string{"later_bad_absence", "later_foreign_kind_off", "open_absence", "open_off"} {
		tx, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		check := func() (bool, bool) {
			s := f.PlanStore()
			x, e := s.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
			if e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
			admitted, admittedSHA, e := loadRetirementForwardTx(ctx, tx, parent.ID, "admitted")
			if e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
			original, e := retirementForwardDestroyRecordTx(ctx, tx, admitted, receipt.Grant.GrantID)
			if e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
			proof := *child.Continuation
			goOK, e := s.retirementForwardClosedFailedReadContinuationTx(ctx, tx, x, parent, admitted, admittedSHA, returned.ID, original, &proof)
			if e != nil && !errors.Is(e, ErrCapacityConflict) {
				tx.Rollback()
				t.Fatal("production typed classifier storage error", e)
			}
			var sqlOK bool
			if e = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_continuation_valid($1::jsonb,$2::uuid)`, string(failedServingWire(t, child)), f.Request.Intent.RequestID).Scan(&sqlOK); e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
			return goOK, sqlOK
		}
		if g, s := check(); !g || !s {
			tx.Rollback()
			t.Fatal("actual typed Go/SQL positive before rollback fault", fault, g, s)
		}
		var challenge GuestRetirementForwardRead
		if json.Unmarshal(prepared.Wire, &challenge) != nil {
			tx.Rollback()
			t.Fatal("actual prepared DTO")
		}
		challenge.ReadID = uuid.NewString()
		challenge.IssuedAtCore = time.Now().UTC()
		challenge.OriginalDeadlineCore = challenge.IssuedAtCore.Add(time.Second)
		if strings.HasSuffix(fault, "off") {
			challenge.Kind, challenge.DestroyGrantID = "off", ""
		}
		insert := func(stage string, wire []byte) {
			_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_retirement_forward_reads(id,admission_id,retirement_request_id,kind,stage,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,clock_timestamp())`, challenge.ReadID, parent.ID, f.Request.Intent.RequestID, challenge.Kind, stage, capacity.BusinessCreationSHA256(wire), wire, string(wire))
			if e != nil {
				tx.Rollback()
				t.Fatal("append-only declared rollback read operand", fault, stage, e)
			}
		}
		insert("prepared", failedServingWire(t, challenge))
		if !strings.HasPrefix(fault, "open_") {
			bad := GuestRetirementForwardReadReturn{Schema: GuestRetirementForwardReadReturnSchema, Read: challenge, Status: "declared_unsupported_status", StartedAtCore: time.Now().UTC(), OriginalReturnedAtCore: time.Now().UTC(), CallFailed: true}
			insert("returned", failedServingWire(t, bad))
		}
		if g, s := check(); g || s {
			tx.Rollback()
			t.Fatal("absolute latest or any-kind open read must forbid old anchor selection in Go/SQL", fault, g, s)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
}

func closedRead102Custody(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ids []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, query := range map[string]string{
		"old_frames":     `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forwards r WHERE id=ANY($1::uuid[])`,
		"old_read_pairs": `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forward_reads r WHERE admission_id=ANY($1::uuid[])`,
	} {
		var raw []byte
		if err := f.DB.QueryRow(query, pq.Array(ids)).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		out[name] = capacity.BusinessCreationSHA256(raw)
	}
	for name, query := range map[string]string{
		"settlement": `SELECT (grant_record->'settlement')::text FROM public.capacity_mutation_grants WHERE id=(SELECT destroy_grant_id FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`,
		"binding":    `SELECT encode(original_wire,'hex') FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`,
	} {
		var raw []byte
		if err := f.DB.QueryRow(query, f.Request.Intent.RequestID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		out[name] = capacity.BusinessCreationSHA256(raw)
	}
	return out
}

func closedRead102Migration(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) string {
	t.Helper()
	root := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if err := goose.UpToContext(ctx, f.DB, root, 101); err != nil {
		t.Fatal("actual schema101 predecessor", err)
	}
	before := installedReadinessCatalog(t, f.DB)
	closedRead102Put(t, "M102-PG-BEFORE101-CATALOG.original.json", before)
	if err := goose.UpToContext(ctx, f.DB, root, 102); err != nil {
		t.Fatal("actual additive schema102", err)
	}
	after := installedReadinessCatalog(t, f.DB)
	closedRead102Put(t, "M102-PG-AFTER102-CATALOG.original.json", after)
	var old, next map[string]json.RawMessage
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || len(old) != len(next) {
		t.Fatal("whole public before101/after102 catalogs required")
	}
	for _, key := range []string{"server_version_num", "columns", "indexes", "triggers"} {
		if !bytes.Equal(old[key], next[key]) {
			t.Fatal("M102 changed unrelated whole catalog", key)
		}
	}
	var oldHistoryWire, newHistoryWire string
	var h0, h1 []map[string]any
	if json.Unmarshal(old["history_wire"], &oldHistoryWire) != nil || json.Unmarshal(next["history_wire"], &newHistoryWire) != nil || json.Unmarshal([]byte(oldHistoryWire), &h0) != nil || json.Unmarshal([]byte(newHistoryWire), &h1) != nil || len(h1) != len(h0)+1 || h0[len(h0)-1]["version_id"] != float64(101) || !reflect.DeepEqual(h0, h1[:len(h0)]) || h1[len(h0)]["version_id"] != float64(102) || h1[len(h0)]["is_applied"] != true {
		t.Fatal("sole102 history append required")
	}
	var f0, f1 []map[string]any
	if json.Unmarshal(old["functions"], &f0) != nil || json.Unmarshal(next["functions"], &f1) != nil {
		t.Fatal("whole function catalogs")
	}
	fnKey := func(r map[string]any) string { return r["name"].(string) + "(" + r["arguments"].(string) + ")" }
	by := map[string]map[string]any{}
	for _, r := range f1 {
		by[fnKey(r)] = r
	}
	oldValidator := ""
	changed := []string{}
	for _, r := range f0 {
		n, ok := by[fnKey(r)]
		if !ok {
			t.Fatal("M102 removed an old function", r["name"])
		}
		if !reflect.DeepEqual(r, n) {
			if r["name"] != "retirement_forward_continuation_valid" {
				t.Fatal("M102 changed unrelated function including101quiet", r["name"])
			}
			changed = append(changed, r["name"].(string))
		}
		if r["name"] == "retirement_forward_continuation_valid" {
			oldValidator = r["definition"].(string)
		}
		delete(by, fnKey(r))
	}
	added := []string{}
	for _, r := range by {
		added = append(added, r["name"].(string))
	}
	sort.Strings(added)
	if !reflect.DeepEqual(changed, []string{"retirement_forward_continuation_valid"}) || !reflect.DeepEqual(added, []string{"retirement_forward_closed_failed_read102_pair_valid", "retirement_forward_closed_failed_read102_valid"}) || oldValidator == "" {
		t.Fatal("exact two new helpers and sole validator dispatch required", changed, added)
	}
	var c0, c1 []map[string]any
	json.Unmarshal(old["constraints"], &c0)
	json.Unmarshal(next["constraints"], &c1)
	checks := map[string]map[string]any{}
	for _, r := range c1 {
		if r["validated"] != true {
			t.Fatal("unvalidated public constraint", r["name"])
		}
		checks[r["table"].(string)+"/"+r["name"].(string)] = r
	}
	for _, r := range c0 {
		key := r["table"].(string) + "/" + r["name"].(string)
		if key == "capacity_guest_retirement_forwards/retirement_forward_continuation96" {
			if _, exists := checks[key]; exists {
				t.Fatal("old96 constraint remained beside102")
			}
			continue
		}
		if !reflect.DeepEqual(r, checks[key]) {
			t.Fatal("M102 changed unrelated CHECK/constraint", key)
		}
		delete(checks, key)
	}
	if len(checks) != 1 || checks["capacity_guest_retirement_forwards/retirement_forward_continuation102"] == nil || !strings.Contains(checks["capacity_guest_retirement_forwards/retirement_forward_continuation102"]["definition"].(string), GuestRetirementForwardClosedFailedReadContinuationSchema) {
		t.Fatal("sole checked96-to102 replacement required", checks)
	}
	migration, err := os.ReadFile(filepath.Join(root, "00102_retirement_closed_failed_read_continuation.sql"))
	if err != nil {
		t.Fatal(err)
	}
	up := strings.SplitN(string(migration), "-- +goose Down", 2)[0]
	for _, name := range append(added, "retirement_forward_continuation_valid") {
		start := strings.Index(up, "CREATE OR REPLACE FUNCTION public."+name+"(")
		if start < 0 {
			t.Fatal("exact Source function missing", name)
		}
		section := up[start:]
		i := strings.Index(section, "AS $$")
		if i < 0 {
			t.Fatal("Source dollar body missing", name)
		}
		body := strings.SplitN(section[i+5:], "$$;", 2)[0]
		var actual string
		if err := f.DB.QueryRow(`SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=$1`, name).Scan(&actual); err != nil || actual != body {
			t.Fatal("installed102 function body differs from committed Source", name, err)
		}
	}
	closedRead102Put(t, "M102-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "closed_failed_read102_whole_public_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "migration102_sha256": capacity.BusinessCreationSHA256(migration), "whole_history_sole102_append": true, "changed_functions": changed, "added_functions": added, "sole_constraint96_to102_replacement": true, "all_other_public_objects_and101quiet_exact": true, "fixture_only": true, "native_authority": false}))
	return oldValidator
}

func closedRead102Put(t *testing.T, name string, raw []byte) {
	t.Helper()
	dir := os.Getenv("RETIREMENT_FORWARD_LOGS")
	if dir == "" {
		return
	}
	if len(raw) > 16<<20 {
		t.Fatal("bounded whole owning artifact", name, len(raw))
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		f.Close()
		t.Fatal("whole exclusive owning artifact", n, e)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
