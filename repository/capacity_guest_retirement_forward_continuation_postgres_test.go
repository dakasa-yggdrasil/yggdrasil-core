//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Declared provider DTOs exercise real PostgreSQL provenance and grant APIs.
// These are not SDK execution, native Guest or production capacity evidence.
func continuationTestPending(t *testing.T, f *GuestRetirementForwardRecoveryFixture, read GuestRetirementForwardRead, receipt model.CapacityMutationReceipt) GuestRetirementForwardReadReturn {
	t.Helper()
	r := f.NativeAbsenceReturn(read, receipt)
	o := r.Observation
	o.BillableResourcesAbsent, o.RetirementComplete, o.BillingExposure = false, false, nil
	if read.Tuple.Provider == "aws" {
		found := false
		for n := range o.AuxiliaryResources {
			if o.AuxiliaryResources[n].Kind == "aws_network_interface" {
				o.AuxiliaryResources[n].Absent = false
				found = true
			}
		}
		if !found {
			t.Fatal("declared original ENI identity missing")
		}
		o.HoldReasons = []string{"aws_network_interface_still_present"}
	} else {
		if len(o.AuxiliaryResources) == 0 {
			t.Fatal("declared original auxiliary identity missing")
		}
		o.AuxiliaryResources[0].Absent = false
		o.HoldReasons = []string{"native_billable_resources_present"}
	}
	if len(r.OriginalObserverReturn) != 0 {
		var original GuestRetirementReadonlyReturn
		if err := json.Unmarshal(r.OriginalObserverReturn, &original); err != nil {
			t.Fatal(err)
		}
		original.Observation = *o
		r.OriginalObserverReturn = failedServingWire(t, original)
	}
	return r
}

func continuationTestParent(t *testing.T, provider, fault string) (*GuestRetirementForwardRecoveryFixture, context.Context, GuestRetirementForward, model.CapacityMutationReceipt) {
	t.Helper()
	f := NewGuestRetirementForwardRecoveryFixture(t, provider, 2, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal("live parent", err, f.AdmissionDiagnostics())
	}
	receipt := forwardTestSettledDestroy(t, f, ctx, fault != "unknown_delete")
	if fault != "unknown_delete" {
		finish := f.FinishStore()
		read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		returned := continuationTestPending(t, f, read, receipt)
		switch fault {
		case "wrong_source":
			returned.ObserverSourceCommit = strings.Repeat("f", 40)
		case "malformed_observer":
			returned.OriginalObserverReturn = []byte("{")
		}
		_, err = finish.RecordGuestRetirementForwardRead(ctx, returned)
		if fault == "wrong_source" || fault == "malformed_observer" {
			if err == nil || errors.Is(err, ErrGuestRetirementForwardNativePending) {
				t.Fatal("foreign/malformed observer became authenticated Pending", err)
			}
		} else if !errors.Is(err, ErrGuestRetirementForwardNativePending) {
			t.Fatal("strict declared Pending was not retained", err)
		}
		if fault == "open_challenge" {
			if _, err = finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID); err != nil {
				t.Fatal(err)
			}
		}
	}
	return f, ctx, parent, receipt
}

func continuationTestRequest(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) GuestRetirementForward {
	t.Helper()
	requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy)
	if err != nil || !requested {
		t.Fatal("ordinary source request", requested, err, f.AdmissionDiagnostics())
	}
	child, found, err := f.Store.GuestRetirementForwardWaiting(ctx, f.Policy)
	if err != nil || !found || child.Stage != "requested" || child.Mode != GuestRetirementForwardContinuationMode || child.Continuation == nil {
		t.Fatal("requested continuation frame", child, found, err)
	}
	return child
}

func TestGuestRetirementForwardContinuationPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider+"/new_owner_same_settled_destroy", func(t *testing.T) {
			f, ctx, parent, receipt := continuationTestParent(t, provider, "")
			oldIntent, oldStore := f.Intent, f.FinishStore()
			if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested {
				t.Fatal("live unfinished parent was adopted", requested, err)
			}
			f.FinishFailedRun("finish-original-retirement")
			if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested {
				t.Fatal("failed parent renewed its unexpired lease", requested, err)
			}
			before := f.PreservedOriginals()
			// One real elapsed wait demonstrates the accepted DELETE/Pending
			// survives its original60s invocation. No stored clock is rewritten.
			if provider == "aws" {
				started := time.Now()
				time.Sleep(61 * time.Second)
				if time.Since(started) <= 60*time.Second {
					t.Fatal("original sixty-second bound did not actually expire")
				}
			}
			f.WaitHistoricalBarrier() // Natural expiry only; no replacement process is supplied.
			f.StartSuccessorDispatch()
			beforeRequestRows := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
			stalePolicy := f.Policy
			stalePolicy.Checksum = strings.Repeat("f", 64)
			if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, stalePolicy); err != nil || requested {
				t.Fatal("stale policy CAS acquired a continuation", requested, err)
			}
			foreignSource := f.PlanStore()
			foreignSource.guestReconcile.source = strings.Repeat("f", 40)
			if requested, err := foreignSource.TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err == nil || requested {
				t.Fatal("foreign planner Source acquired a continuation", requested, err)
			}
			if beforeRequestRows != forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") {
				t.Fatal("stale policy or foreign Source request changed the ledger")
			}
			if provider == "aws" {
				continuationTestQuietFailures(t, f, ctx)
			}
			child := continuationTestRequest(t, f, ctx)
			requestedRows := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
			if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested || requestedRows != forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") {
				t.Fatal("duplicate request appended another child", requested, err)
			}
			if child.ID == parent.ID || child.RootAdmissionID != parent.ID || child.ParentAdmissionID != parent.ID || child.DestroyGrantID != receipt.Grant.GrantID || child.Continuation.FailedRunID != parent.RunID || child.Continuation.RequestingRunID != f.RunID.String() || child.Barrier != (CapacityDispatchExecutorBarrier{}) {
				t.Fatal("continuation replaced original ancestry or invented process authority", child)
			}
			continuationTestProofFailures(t, f, child)
			var grantBefore, bindingBefore []byte
			if err := f.DB.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, receipt.Grant.GrantID).Scan(&grantBefore); err != nil {
				t.Fatal(err)
			}
			if err := f.DB.QueryRow(`SELECT original_wire FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&bindingBefore); err != nil {
				t.Fatal(err)
			}
			plan := f.PlanStore()
			type claimResult struct {
				intent  model.CapacityIntent
				handled bool
				err     error
			}
			results := make(chan claimResult, 2)
			var group sync.WaitGroup
			for n := 0; n < 2; n++ {
				group.Add(1)
				go func() {
					defer group.Done()
					i, _, _, h, err := plan.TryClaimGuestRetirementForward(ctx, f.Policy)
					results <- claimResult{i, h, err}
				}()
			}
			group.Wait()
			close(results)
			claimed := 0
			for result := range results {
				if result.err == nil && result.handled {
					claimed++
					f.Intent = result.intent
				}
			}
			if claimed != 1 || f.Intent.FencingToken != oldIntent.FencingToken+1 || f.Intent.LeaseOwner == oldIntent.LeaseOwner || f.Intent.LeaseExpiresAt == nil || !f.Intent.LeaseExpiresAt.After(time.Now()) || f.Intent.RetirementForward.ID != child.ID {
				t.Fatal("competing claims did not yield exactly one fresh fenced owner", claimed, f.Intent)
			}
			finish := f.FinishStore()
			if _, err := oldStore.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID); err == nil {
				t.Fatal("old owner acquired a new read")
			}
			if _, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", ""); err == nil {
				t.Fatal("continuation acquired OFF authority")
			}
			b := f.Spec.MutationBindings[0]
			desired := *b.Slots[f.Pre.Slot-1].DesiredSpec
			desired.Capability, desired.ExpectedResourceID, desired.ExpectedResourceCreatedAt = b.DestroyCapability, receipt.Grant.ExpectedResourceID, receipt.Grant.ExpectedResourceCreatedAt
			if _, err := finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(t, desired)}); err == nil {
				t.Fatal("continuation acquired another DELETE grant")
			}
			callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
			if permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, mutationRedeem(receipt.Grant, uuid.NewString())); err == nil && permit.Mode == "write_once" {
				t.Fatal("settled original DELETE acquired a second write permit")
			}
			var unchanged []byte
			if err := f.DB.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, receipt.Grant.GrantID).Scan(&unchanged); err != nil || string(unchanged) != string(grantBefore) {
				t.Fatal("request/claim/refusals rewrote the original settled grant", err)
			}
			if err := finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Inventory(false)); err != nil {
				t.Fatal("fresh reduced inventory", err)
			}
			tx, err := f.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			x, record, _, err := finish.retirementForwardCurrentTx(ctx, tx, f.Request.Intent.RequestID)
			if err == nil {
				err = finish.retirementForwardFloorTx(ctx, tx, x, record)
			}
			tx.Rollback()
			if !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("parent survivor canaries substituted for fresh child floor", err)
			}
			// Existing helper must create NEW child survivor canaries/inventory,
			// then child absence/Confirm and normal terminal completion.
			forwardTestComplete(t, f, ctx)
			if err := f.DB.QueryRow(`SELECT original_wire FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&unchanged); err != nil || string(unchanged) != string(bindingBefore) {
				t.Fatal("completion replaced the original DELETE eligibility", err)
			}
			var count int
			if err := f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1 AND destroy_grant_id=$2`, f.Request.Intent.RequestID, receipt.Grant.GrantID).Scan(&count); err != nil || count != 1 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("continuation changed original grant identity, failure, journal or clocks", count, err)
			}
		})
	}
	t.Run("requested_survives_unknown_requester_without_claim", func(t *testing.T) {
		f, ctx, _, _ := continuationTestParent(t, "aws", "")
		f.FinishFailedRun("finish-original-retirement")
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		child := continuationTestRequest(t, f, ctx)
		var before []byte
		if err := f.DB.QueryRow(`SELECT original_wire FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='requested'`, child.ID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		// Same-scope UNKNOWN coalesces scheduler admission. A separate
		// scope on the same logical workflow can coexist; it must block
		// this still-valid requester's actual claim through continuation quiet.
		tx, err := f.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = continuationTestBusyDispatch(t, f, ctx, tx, "unknown"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		x, err := f.PlanStore().retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
		if err == nil {
			err = retirementForwardQuietTx(ctx, tx, x, f.RunID.String(), child.DestroyGrantID)
		}
		if err != nil {
			tx.Rollback()
			t.Fatal("closed competing workflow must pass legacy quiet before Store claim", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err = f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("valid requester claimed through a competing logical UNKNOWN", err)
		}
		response := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "failed"}
		// Stop at the real first commit, without its ACK. The existing
		// uncertainty API then retains UNKNOWN; no sealed old ACK is edited.
		if _, err := finishCapacityDispatchFirstCommitOnce(ctx, f.DB, f.job, response, time.Now().UTC(), nil, nil); err != nil {
			t.Fatal("requesting run first return", err)
		}
		if err := markCapacityDispatchFinalizationUnknown(ctx, f.DB, f.job, "declared lost requesting-run ACK"); err != nil {
			t.Fatal("requesting run UNKNOWN", err)
		}
		if _, _, _, _, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy); err == nil {
			t.Fatal("UNKNOWN requester acquired a continuation lease")
		}
		var after []byte
		if err := f.DB.QueryRow(`SELECT original_wire FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='requested'`, child.ID).Scan(&after); err != nil || string(after) != string(before) {
			t.Fatal("requesting-run uncertainty erased or rewrote the durable request", err)
		}
		var admitted int
		if err := f.DB.QueryRow(`SELECT count(*) FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='admitted'`, child.ID).Scan(&admitted); err != nil || admitted != 0 {
			t.Fatal("unknown requester left an admitted child", admitted, err)
		}
	})
	for _, fault := range []string{"wrong_source", "malformed_observer", "open_challenge", "unknown_delete"} {
		t.Run("refusal/"+fault, func(t *testing.T) {
			f, ctx, _, _ := continuationTestParent(t, "aws", fault)
			f.FinishFailedRun("finish-original-retirement")
			f.WaitHistoricalBarrier()
			before := f.PreservedOriginals()
			rows := forwardTestRowCount(t, f, "capacity_guest_retirement_forwards")
			f.StartSuccessorDispatch()
			if requested, err := f.PlanStore().TryRequestGuestRetirementForwardContinuation(ctx, f.Policy); err != nil || requested {
				t.Fatal("ineligible last original became a continuation", requested, err)
			}
			if rows != forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") || !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("refusal rewrote preserved originals")
			}
		})
	}
}

func continuationTestProofFailures(t *testing.T, f *GuestRetirementForwardRecoveryFixture, child GuestRetirementForward) {
	t.Helper()
	valid := func(wire []byte) bool {
		t.Helper()
		var accepted bool
		if err := f.DB.QueryRow(`SELECT public.retirement_forward_continuation_valid($1::jsonb,$2::uuid)`, string(wire), f.Request.Intent.RequestID).Scan(&accepted); err != nil {
			t.Fatal("migration93 proof predicate", err)
		}
		return accepted
	}
	original := failedServingWire(t, child)
	if !valid(original) {
		t.Fatal("migration93 rejected the actual requested proof")
	}
	for _, fault := range []string{"missing_proof", "extra_proof_key", "schema", "failed_run_sha256", "dispatch_sha256", "destroy_grant_sha256", "delete_eligibility_sha256", "pending_read_sha256", "requesting_run_id", "failed_run_id", "dispatch_id", "pending_read_id", "parent_admission_id", "root_admission_id", "destroy_grant_id", "fence"} {
		var record map[string]any
		if err := json.Unmarshal(original, &record); err != nil {
			t.Fatal(err)
		}
		proof := record["continuation"].(map[string]any)
		switch fault {
		case "missing_proof":
			delete(record, "continuation")
		case "extra_proof_key":
			proof["forged_authority"] = true
		case "schema":
			proof[fault] = "future"
		case "parent_admission_id", "root_admission_id", "destroy_grant_id":
			record[fault] = uuid.NewString()
		case "fence":
			record[fault] = child.Fence + 1
		default:
			if strings.HasSuffix(fault, "_sha256") {
				proof[fault] = strings.Repeat("f", 64)
			} else {
				proof[fault] = uuid.NewString()
			}
		}
		if valid(failedServingWire(t, record)) {
			t.Fatal("migration93 accepted a foreign or unclosed proof", fault)
		}
	}
}

// These adversarial storage shapes exist only inside rollback transactions.
// Every original returned dispatch/ACK remains immutable. Real Enqueue creates
// a separate scope with the same logical workflow to exercise global quiet.
func continuationTestQuietFailures(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	for _, fault := range []string{"queued", "unknown", "returned_without_ack", "logical_workflow_busy", "null_run_rejected"} {
		t.Run(fault, func(t *testing.T) {
			tx, err := f.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			store := f.PlanStore()
			x, err := store.retirementForwardSnapshotTx(ctx, tx, f.Request.Intent.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			var destroy string
			if err = tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&destroy); err != nil {
				t.Fatal(err)
			}
			if err = retirementForwardContinuationQuietTx(ctx, tx, x, destroy, f.RunID.String()); err != nil {
				t.Fatal("eligible baseline quiet", err)
			}
			if fault == "null_run_rejected" {
				// M61 itself requires run_id NOT NULL; do not weaken it to
				// manufacture a supposedly valid queued NULL-run fixture.
				_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256) VALUES($1,NULL,$2,$3,$4,$5,'null-run-fixture','declared',$6,$7)`, uuid.New(), CapacityDispatchProtocol, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, string(failedServingWire(t, f.envelope)), capacity.BusinessCreationSHA256(failedServingWire(t, f.envelope)))
				var pgError *pq.Error
				if !errors.As(err, &pgError) || pgError.Code != "23502" || pgError.Column != "run_id" || pgError.Table != "capacity_dispatch_jobs" {
					t.Fatal("expected the exact run_id NOT NULL storage refusal", err)
				}
				return
			}
			err = continuationTestBusyDispatch(t, f, ctx, tx, fault)
			if err != nil {
				t.Fatal("declared blocked storage shape", err)
			}
			if fault == "unknown" || fault == "returned_without_ack" {
				if err = retirementForwardQuietTx(ctx, tx, x, f.RunID.String(), destroy); err != nil {
					t.Fatal("closed workflow must pass legacy quiet to isolate dispatch custody", err)
				}
			}
			if err = retirementForwardContinuationQuietTx(ctx, tx, x, destroy, f.RunID.String()); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("unfinished/unacknowledged logical workflow was treated as quiet", err)
			}
		})
	}
}

func continuationTestBusyDispatch(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, tx *sql.Tx, fault string) error {
	t.Helper()
	var err error
	if fault == "logical_workflow_busy" {
		// An unbound workflow_id still belongs to the same logical
		// workflow and must not disappear through UUID-only joins.
		_, err = tx.ExecContext(ctx, `INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,updated_at) VALUES($1,'running',$2,$3,$4,clock_timestamp(),clock_timestamp())`, uuid.New(), f.Workflow.Metadata.Namespace, f.Workflow.Metadata.Name, f.Workflow.Version)
	} else {
		e := f.envelope
		e.JobID, e.RunID, e.Dimension, e.SourceTick = uuid.New(), uuid.New(), "continuation-busy", uuid.NewString()
		e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.Workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
		e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate, enqueueErr := EnqueueCapacityDispatch(ctx, tx, e); enqueueErr != nil || duplicate {
			t.Fatal("declared competing scoped dispatch", duplicate, enqueueErr)
		}
		if fault != "queued" {
			if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET lease_owner=$2,fencing_token=1,lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, e.JobID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='started',started_at=clock_timestamp() WHERE id=$1`, e.JobID); err != nil {
				t.Fatal(err)
			}
			if fault == "unknown" {
				_, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='unknown' WHERE id=$1`, e.JobID)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='returned',returned_at=clock_timestamp(),return_status='failed' WHERE id=$1`, e.JobID)
			}
			if err != nil {
				return err
			}
			// Close ONLY this newly declared competing workflow. Its job
			// remains UNKNOWN or unacknowledged, isolating dispatch custody
			// from the older busy-workflow predicate. No sealed row is edited.
			_, err = tx.ExecContext(ctx, `UPDATE public.workflow_runs w SET status='failed',finished_at=COALESCE(j.returned_at,clock_timestamp()),updated_at=clock_timestamp() FROM public.capacity_dispatch_jobs j WHERE w.id=$1 AND j.run_id=w.id`, e.RunID)
		}
	}
	return err
}
