//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// This is declared provider/Guest data in the existing isolated PG16/17
// fixture. It does not execute SDK/Guest calls or qualify production evidence.
// Both owner expiries are real elapsed time; no stored deadline or ACK changes.
func TestGuestRetirementForwardPreReadContinuationPostgres(t *testing.T) {
	t.Run("zero_read_and_repeated_typed_same_destroy", func(t *testing.T) {
		f := NewGuestRetirementForwardRecoveryFixture(t, "aws", 2, 4)
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		if err := goose.UpToContext(ctx, f.DB, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 96); err != nil {
			t.Fatal("isolated fixture migration96", err)
		}
		if version, err := goose.GetDBVersion(f.DB); err != nil || version != 96 {
			t.Fatal("actual isolated database must be schema96", version, err)
		}

		parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
		if err != nil {
			t.Fatal("real live root admission", err, f.AdmissionDiagnostics())
		}
		receipt := forwardTestSettledDestroy(t, f, ctx, true)
		rootFinish := f.FinishStore()
		pendingRead, err := rootFinish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = rootFinish.RecordGuestRetirementForwardRead(ctx, continuationTestPending(t, f, pendingRead, receipt)); !errors.Is(err, ErrGuestRetirementForwardNativePending) {
			t.Fatal("root authenticated Pending anchor", err)
		}
		var pendingWire []byte
		var pendingSHA string
		if err = f.DB.QueryRow(`SELECT original_wire,record_sha256 FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, pendingRead.ReadID).Scan(&pendingWire, &pendingSHA); err != nil || capacity.BusinessCreationSHA256(pendingWire) != pendingSHA {
			t.Fatal("exact original Pending wire", err)
		}
		f.FinishFailedRun("finish-original-retirement")
		originals := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		first := continuationTestRequest(t, f, ctx)
		if first.Continuation == nil || first.Continuation.Schema != GuestRetirementForwardContinuationSchema || first.Continuation.PendingReadID != pendingRead.ReadID || first.Continuation.PendingReadSHA256 != pendingSHA {
			t.Fatal("first ordinary continuation must retain the real root Pending", first)
		}
		preReadClaim(t, f, ctx, first)
		firstOwner := f.Intent
		firstFinish := f.FinishStore()
		firstRun := f.RunID
		firstJob := f.job
		// A native inventory failure is BEFORE Prepare, so even a prepared/read
		// diagnostic must not exist under this child. No fake absence is supplied.
		badInventory := f.Inventory(false)
		badInventory.Complete = false
		if err = firstFinish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, badInventory); err == nil {
			t.Fatal("incomplete inventory became fresh floor authority")
		}
		if count := preReadOwnRows(t, f, first.ID); count != 0 {
			t.Fatal("pre-read failed child acquired any kind/stage of read", count)
		}
		var admittedWire []byte
		if err = f.DB.QueryRow(`SELECT original_wire FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='admitted'`, first.ID).Scan(&admittedWire); err != nil {
			t.Fatal(err)
		}
		var admitted GuestRetirementForward
		if err = json.Unmarshal(admittedWire, &admitted); err != nil || admitted.RunID != firstRun.String() || admitted.Stage != "admitted" {
			t.Fatal("actual first child's admitted owner", err)
		}

		// Stop at the actual return's first commit. This models a missing ACK
		// without editing a previously committed ACK or sealed workflow result.
		failed := preReadWorkflowResult(f, firstOwner, first.ID, "failed", "finish-original-retirement")
		returnedAt := time.Now().UTC()
		committed, err := finishCapacityDispatchFirstCommitOnce(ctx, f.DB, firstJob, failed, returnedAt, nil, nil)
		if err != nil || committed.current.FinalizationAckAt != nil {
			t.Fatal("genuine failed first commit without ACK", err)
		}
		preReadMissingACKCoalesces(t, f, ctx, firstJob)
		if err = acknowledgeCapacityDispatchFinalization(ctx, f.DB, committed.current); err != nil {
			t.Fatal("actual failed return ACK", err)
		}
		var jobState, returnStatus, workflowState string
		var finished, returned, ack time.Time
		if err = f.DB.QueryRow(`SELECT j.state,j.return_status,w.status,w.finished_at,j.returned_at,j.finalization_ack_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, firstJob.JobID).Scan(&jobState, &returnStatus, &workflowState, &finished, &returned, &ack); err != nil || jobState != "returned" || returnStatus != "failed" || workflowState != "failed" || !finished.Equal(returned) || ack.Before(returned) {
			t.Fatal("current pre-read failed owner needs its own real closed ACK", err)
		}

		// A genuine new started planner exists while the old capacity lease is
		// still alive. Refusal must not be an old closed-run identity accident.
		preReadStartNextTick(t, f)
		probeRun := f.RunID
		beforeRefusal := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
		if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested {
			t.Fatal("pre-read owner lease was adopted before natural expiry", requested, err)
		}
		if firstOwner.LeaseExpiresAt == nil || !firstOwner.LeaseExpiresAt.After(time.Now()) || beforeRefusal != forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") || preReadOwnRows(t, f, first.ID) != 0 {
			t.Fatal("live-lease refusal changed authority or did not exercise a live lease")
		}
		// Close the unclaimed planner truthfully, before its own dispatch lease
		// expires; the next real run starts AFTER the prior capacity lease expires.
		probeFailure := preReadWorkflowResult(f, firstOwner, first.ID, "failed", "plan-original-guest")
		if err = FinishCapacityDispatch(ctx, f.DB, f.job, probeFailure, time.Now().UTC(), nil); err != nil {
			t.Fatal("unclaimed live-lease planner failed ACK", err)
		}
		before := preReadImmutableSnapshot(t, f, parent.ID, first.ID)
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		second := continuationTestRequest(t, f, ctx)
		if second.Continuation == nil || second.Continuation.Schema != GuestRetirementForwardPreReadContinuationSchema || second.Continuation.FailedRunID != firstRun.String() || second.Continuation.FailedRunID == probeRun.String() || second.Continuation.RequestingRunID != f.RunID.String() || second.Continuation.PendingReadID != pendingRead.ReadID || second.Continuation.PendingReadSHA256 != pendingSHA || second.ParentAdmissionID != first.ID || second.RootAdmissionID != parent.ID || second.DestroyGrantID != receipt.Grant.GrantID || second.Barrier != (CapacityDispatchExecutorBarrier{}) {
			t.Fatal("typed pre-read successor changed the parent/root/Pending/SDK authority", second)
		}
		if second.Continuation.Schema != "original_settled_absence_pre_read_continuation_v1" || preReadOwnRows(t, f, first.ID) != 0 {
			t.Fatal("new schema requires zero reads of ANY kind/stage by its failed parent")
		}
		preReadProofRefusals(t, f, second)
		preReadClaim(t, f, ctx, second)
		// Ordinary scheduler ticks reuse this actual Core process executor.
		// New run/fence/owner/lease authority does not require a process restart.
		secondOwner := f.Intent
		if secondOwner.FencingToken != firstOwner.FencingToken+1 || secondOwner.LeaseOwner == firstOwner.LeaseOwner || secondOwner.LeaseExecutorID != f.Store.ExecutorID || secondOwner.LeaseExpiresAt == nil || !secondOwner.LeaseExpiresAt.After(time.Now()) {
			t.Fatal("second continuation did not acquire a fresh actual fenced lease", secondOwner)
		}
		if _, err = firstFinish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID); err == nil {
			t.Fatal("expired prior owner prepared a new read")
		}
		finish := f.FinishStore()
		if _, err = finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", ""); err == nil {
			t.Fatal("typed pre-read continuation acquired OFF authority")
		}
		b := f.Spec.MutationBindings[0]
		desired := *b.Slots[f.Pre.Slot-1].DesiredSpec
		desired.Capability, desired.ExpectedResourceID, desired.ExpectedResourceCreatedAt = b.DestroyCapability, receipt.Grant.ExpectedResourceID, receipt.Grant.ExpectedResourceCreatedAt
		if _, err = finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(t, desired)}); err == nil {
			t.Fatal("pre-read continuation acquired another DELETE grant")
		}
		callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
		if permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, mutationRedeem(receipt.Grant, uuid.NewString())); err == nil && permit.Mode == "write_once" {
			t.Fatal("same settled original DELETE acquired another SDK write permit")
		}
		if !reflect.DeepEqual(before, preReadImmutableSnapshot(t, f, parent.ID, first.ID)) {
			t.Fatal("request/claim/refusals rewrote the old grant, SDK, root Pending or failed child")
		}

		// A typed96 owner can itself fail before preparing any read. Its next
		// successor must still resolve the ONE real classic/root Pending anchor,
		// rather than stop at a hard-coded single typed retry or mint a new DELETE.
		typedFailedOwner, typedFailedRun := f.Intent, f.RunID
		badInventory = f.Inventory(false)
		badInventory.Complete = false
		if err = finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, badInventory); err == nil || preReadOwnRows(t, f, second.ID) != 0 {
			t.Fatal("typed96 failure was not strictly before every read", err)
		}
		f.FinishFailedRun("finish-original-retirement")
		before = preReadImmutableSnapshot(t, f, parent.ID, first.ID, second.ID)
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		finalChild := continuationTestRequest(t, f, ctx)
		if finalChild.Continuation == nil || finalChild.Continuation.Schema != GuestRetirementForwardPreReadContinuationSchema || finalChild.ParentAdmissionID != second.ID || finalChild.RootAdmissionID != parent.ID || finalChild.Continuation.FailedRunID != typedFailedRun.String() || finalChild.Continuation.PendingReadID != pendingRead.ReadID || finalChild.Continuation.PendingReadSHA256 != pendingSHA || finalChild.DestroyGrantID != receipt.Grant.GrantID {
			t.Fatal("repeated typed96 pre-read failure changed immutable root/Pending/SDK lineage", finalChild)
		}
		preReadClaim(t, f, ctx, finalChild)
		finalOwner := f.Intent
		if finalOwner.FencingToken != typedFailedOwner.FencingToken+1 || finalOwner.LeaseOwner == typedFailedOwner.LeaseOwner || finalOwner.LeaseExecutorID != f.Store.ExecutorID || finalOwner.LeaseExpiresAt == nil || !finalOwner.LeaseExpiresAt.After(time.Now()) {
			t.Fatal("repeated typed96 failure did not receive a new actual owner/fence", finalOwner)
		}
		finish = f.FinishStore()
		if err = finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Inventory(false)); err != nil {
			t.Fatal("new owner fresh survivor-only inventory", err)
		}
		tx, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		x, record, _, err := finish.retirementForwardCurrentTx(ctx, tx, f.Request.Intent.RequestID)
		if err == nil {
			err = finish.retirementForwardFloorTx(ctx, tx, x, record)
		}
		_ = tx.Rollback()
		if !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("old owner floor canaries were accepted as fresh new-owner floor", err)
		}
		// Existing positive helper creates NEW survivor canaries and inventory,
		// one fresh absence challenge/return, Confirm of the SAME grant and terminal.
		forwardTestComplete(t, f, ctx)
		if preReadOwnRows(t, f, first.ID) != 0 || preReadOwnRows(t, f, second.ID) != 0 || preReadOwnRows(t, f, finalChild.ID) != 2 {
			t.Fatal("failed parent gained reads or new owner skipped its fresh prepared+returned pair")
		}
		var terminalWire []byte
		if err = f.DB.QueryRow(`SELECT original_wire FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='terminal'`, finalChild.ID).Scan(&terminalWire); err != nil {
			t.Fatal("normal terminal missing", err)
		}
		var terminal GuestRetirementForward
		if err = json.Unmarshal(terminalWire, &terminal); err != nil || terminal.DestroyGrantID != receipt.Grant.GrantID || terminal.RootAdmissionID != parent.ID || terminal.ParentAdmissionID != second.ID {
			t.Fatal("normal terminal replaced root/parent/DELETE", err)
		}
		success := preReadWorkflowResult(f, finalOwner, finalChild.ID, "succeeded", "")
		if err = FinishCapacityDispatch(ctx, f.DB, f.job, success, time.Now().UTC(), nil); err != nil {
			t.Fatal("normal terminal owning run ACK", err)
		}
		var count int
		if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1 AND destroy_grant_id=$2`, f.Request.Intent.RequestID, receipt.Grant.GrantID).Scan(&count); err != nil || count != 1 || !reflect.DeepEqual(originals, f.PreservedOriginals()) {
			t.Fatal("terminal did not preserve original one-DELETE binding and all prior originals", count, err)
		}
		after := preReadImmutableSnapshot(t, f, parent.ID, first.ID, second.ID)
		// Confirm may change only the ordinary grant state/proof, not its accepted
		// SDK settlement, original binding, root Pending or failed child's frames.
		for _, key := range []string{"settlement", "binding", "root_pending", "old_forward_rows", "grant_count"} {
			if after[key] != before[key] {
				t.Fatal("terminal changed original immutable content", key)
			}
		}
	})
	for _, fault := range []string{"own_prepared", "own_returned_failed_malformed"} {
		t.Run(fault, func(t *testing.T) {
			preReadOwnBoundary(t, fault)
		})
	}
}

func preReadClaim(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, child GuestRetirementForward) {
	t.Helper()
	i, _, _, handled, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy)
	if err != nil || !handled || i.RetirementForward == nil || i.RetirementForward.ID != child.ID || i.LeaseExpiresAt == nil || !i.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("real continuation claim", handled, err, f.AdmissionDiagnostics())
	}
	f.Intent = i
}

func preReadOwnRows(t *testing.T, f *GuestRetirementForwardRecoveryFixture, admission string) int {
	t.Helper()
	var count int
	if err := f.DB.QueryRow(`SELECT count(*) FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1`, admission).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func preReadImmutableSnapshot(t *testing.T, f *GuestRetirementForwardRecoveryFixture, root string, failedChildren ...string) map[string]string {
	t.Helper()
	queries := map[string]string{
		"grant_record":     `SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=(SELECT destroy_grant_id FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`,
		"settlement":       `SELECT (grant_record->'settlement')::text FROM public.capacity_mutation_grants WHERE id=(SELECT destroy_grant_id FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`,
		"binding":          `SELECT encode(original_wire,'hex') FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`,
		"root_pending":     `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY recorded_at,id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forward_reads r WHERE retirement_request_id=$1 AND admission_id=$2`,
		"old_forward_rows": `SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY recorded_at,id,stage),'[]'::jsonb)::text FROM public.capacity_guest_retirement_forwards f WHERE retirement_request_id=$1 AND id=ANY($3::uuid[])`,
		"grant_count":      `SELECT count(*)::text FROM public.capacity_mutation_grants WHERE namespace=$1`,
	}
	out := map[string]string{}
	for key, query := range queries {
		var raw string
		args := []any{f.Request.Intent.RequestID}
		if key == "grant_count" {
			args = []any{f.Policy.Metadata.Namespace}
		}
		if key == "root_pending" {
			args = append(args, root)
		}
		if key == "old_forward_rows" {
			// Preserve PostgreSQL parameter positions without inventing a row.
			query = strings.ReplaceAll(query, "$3", "$2")
			args = append(args, pq.Array(append([]string{root}, failedChildren...)))
		}
		if err := f.DB.QueryRow(query, args...).Scan(&raw); err != nil {
			t.Fatal("immutable snapshot", key, err)
		}
		out[key] = capacity.BusinessCreationSHA256([]byte(raw))
	}
	return out
}

func preReadWorkflowResult(f *GuestRetirementForwardRecoveryFixture, owner model.CapacityIntent, forwardID, status, failedStep string) model.RunWorkflowResponse {
	r := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: status}
	for _, step := range f.private.steps {
		x := model.WorkflowRunStepResult{ID: step.ID, Status: "skipped"}
		if failedStep == "plan-original-guest" {
			if step.ID == failedStep {
				x.Status, x.Error = "failed", "declared_plan_refused_live_capacity_lease"
			}
			r.Steps = append(r.Steps, x)
			continue
		}
		switch step.ID {
		case "plan-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"mode": "retire", "generation": owner.Generation, "fencing_token": owner.FencingToken, "lease_owner": owner.LeaseOwner, "preregistration_id": f.Pre.PreregistrationID, "slot": f.Pre.Slot, "request_id": f.Request.Intent.RequestID}
		case "retire-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"request_id": f.Request.Intent.RequestID, "retirement_forward_id": forwardID, "normal_guest_success": false}
		case "finish-original-retirement", "complete-original-retirement":
			if status == "succeeded" {
				x.Status = "succeeded"
			}
		}
		if step.ID == failedStep {
			x.Status, x.Error = "failed", "declared_readonly_inventory_failed_before_any_forward_read"
		}
		r.Steps = append(r.Steps, x)
	}
	return r
}

func preReadStartNextTick(t *testing.T, f *GuestRetirementForwardRecoveryFixture) {
	t.Helper()
	for time.Now().UTC().Truncate(time.Second).Format(time.RFC3339) == f.envelope.SourceTick {
		time.Sleep(10 * time.Millisecond)
	}
	f.StartSuccessorDispatch()
}

func preReadMissingACKCoalesces(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, old CapacityDispatchJob) {
	t.Helper()
	e := f.envelope
	e.JobID, e.RunID, e.SourceTick = uuid.New(), uuid.New(), time.Now().UTC().Format(time.RFC3339Nano)
	e.Metadata = map[string]any{}
	for key, value := range f.envelope.Metadata {
		e.Metadata[key] = value
	}
	e.Metadata["scheduled_for"], e.Metadata["capacity_dispatch_job_id"] = e.SourceTick, e.JobID.String()
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	job, coalesced, err := EnqueueCapacityDispatch(ctx, tx, e)
	if err != nil || !coalesced || job.JobID != old.JobID || job.RunID != old.RunID || job.FinalizationAckAt != nil {
		t.Fatal("missing actual ACK admitted a new runnable requester", coalesced, err)
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.workflow_runs WHERE id=$1`, e.RunID).Scan(&count); err != nil || count != 0 {
		t.Fatal("missing ACK left a new workflow run", count, err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func preReadProofRefusals(t *testing.T, f *GuestRetirementForwardRecoveryFixture, child GuestRetirementForward) {
	t.Helper()
	original := failedServingWire(t, child)
	valid := func(raw []byte) bool {
		var ok bool
		if err := f.DB.QueryRow(`SELECT public.retirement_forward_continuation_valid($1::jsonb,$2::uuid)`, string(raw), f.Request.Intent.RequestID).Scan(&ok); err != nil {
			t.Fatal("migration96 typed proof", err)
		}
		return ok
	}
	if !valid(original) {
		t.Fatal("migration96 rejected actual zero-read requested successor")
	}
	for _, fault := range []string{"classic_schema", "pending_read_id", "pending_read_sha256", "failed_run_id", "failed_run_sha256", "dispatch_sha256", "parent_admission_id", "root_admission_id", "destroy_grant_id", "extra_proof_key"} {
		var row map[string]any
		if err := json.Unmarshal(original, &row); err != nil {
			t.Fatal(err)
		}
		proof := row["continuation"].(map[string]any)
		switch fault {
		case "classic_schema":
			proof["schema"] = GuestRetirementForwardContinuationSchema
		case "extra_proof_key":
			proof["replacement_process_authority"] = true
		case "parent_admission_id", "root_admission_id", "destroy_grant_id":
			row[fault] = uuid.NewString()
		default:
			if strings.HasSuffix(fault, "_sha256") {
				proof[fault] = strings.Repeat("f", 64)
			} else {
				proof[fault] = uuid.NewString()
			}
		}
		if valid(failedServingWire(t, row)) {
			t.Fatal("migration96 accepted foreign pre-read custody", fault)
		}
	}
}

func preReadOwnBoundary(t *testing.T, fault string) {
	t.Helper()
	f := NewGuestRetirementForwardRecoveryFixture(t, "aws", 2, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := goose.UpToContext(ctx, f.DB, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 96); err != nil {
		t.Fatal(err)
	}
	if version, err := goose.GetDBVersion(f.DB); err != nil || version != 96 {
		t.Fatal("own-read boundary actualschema96", version, err)
	}
	parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal("own-read boundary root", err, f.AdmissionDiagnostics())
	}
	receipt := forwardTestSettledDestroy(t, f, ctx, true)
	finish := f.FinishStore()
	read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = finish.RecordGuestRetirementForwardRead(ctx, continuationTestPending(t, f, read, receipt)); !errors.Is(err, ErrGuestRetirementForwardNativePending) {
		t.Fatal("own-read boundary originalPending", err)
	}
	f.FinishFailedRun("finish-original-retirement")
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	child := continuationTestRequest(t, f, ctx)
	preReadClaim(t, f, ctx, child)
	finish = f.FinishStore()
	own, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
	if err != nil || f.Intent.LeaseExpiresAt == nil || !f.Intent.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("real own challenge created whileleasealive", err)
	}
	wantRows := 1
	if fault == "own_returned_failed_malformed" {
		at := time.Now().UTC()
		// Valid JSON diagnostic but failed context/unsupported status, with no
		// observer/absence DTO. Persisted bythe realRecord boundary, never Pending.
		bad := GuestRetirementForwardReadReturn{Schema: GuestRetirementForwardReadReturnSchema, Read: own, Status: "declared_unsupported_status", CallFailed: true, OriginalContextFailed: true, StartedAtCore: at, OriginalReturnedAtCore: at}
		if _, err = finish.RecordGuestRetirementForwardRead(ctx, bad); err == nil || errors.Is(err, ErrGuestRetirementForwardNativePending) {
			t.Fatal("failed/malformed own return became authenticatedPending", err)
		}
		wantRows = 2
	}
	if preReadOwnRows(t, f, child.ID) != wantRows || !f.Intent.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("actual own diagnostic was notdurable withinlivelease")
	}
	f.FinishFailedRun("finish-original-retirement")
	originals := f.PreservedOriginals()
	before := preReadImmutableSnapshot(t, f, parent.ID, child.ID)
	var ownWire string
	if err = f.DB.QueryRow(`SELECT jsonb_agg(to_jsonb(r) ORDER BY recorded_at,id,stage)::text FROM public.capacity_guest_retirement_forward_reads r WHERE admission_id=$1`, child.ID).Scan(&ownWire); err != nil {
		t.Fatal(err)
	}
	f.WaitHistoricalBarrier()
	f.StartSuccessorDispatch()
	rows := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
	if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested {
		t.Fatal("retained own read was bypassed by inheritedrootPending", fault, requested, err)
	}
	var afterWire string
	if err = f.DB.QueryRow(`SELECT jsonb_agg(to_jsonb(r) ORDER BY recorded_at,id,stage)::text FROM public.capacity_guest_retirement_forward_reads r WHERE admission_id=$1`, child.ID).Scan(&afterWire); err != nil || afterWire != ownWire || preReadOwnRows(t, f, child.ID) != wantRows || rows != forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") || !reflect.DeepEqual(before, preReadImmutableSnapshot(t, f, parent.ID, child.ID)) || !reflect.DeepEqual(originals, f.PreservedOriginals()) {
		t.Fatal("own-read refusal changed immutable rows orminted successor", fault, err)
	}
}
