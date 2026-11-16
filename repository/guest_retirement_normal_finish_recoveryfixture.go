//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NewGuestRetirementNormalFinishRecoveryFixture declares the short lease and a
// complete ordinary caller BEFORE the first original insert. Tests observe its
// natural expiry; they never edit a retained deadline, ACK, caller or journal.
func NewGuestRetirementNormalFinishRecoveryFixture(t testing.TB, provider string) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(t, provider, 2, 4, 30, false, true)
}

// NewGuestRetirementLateCallerRecoveryFixture fixes the late variant before
// its first caller INSERT and naturally waits for the unchanged original30s
// deadline. The retention context only saves that failed original result.
func NewGuestRetirementLateCallerRecoveryFixture(t testing.TB, provider string) *GuestRetirementForwardRecoveryFixture {
	return newGuestRetirementForwardRecoveryFixture(t, provider, 2, 4, 30, false, false, "late")
}

// FailedOrdinaryNativeOff retains the same prepared/returned boundary as the
// production failure: normal caller success, observed provider return, failed
// qualification, no context failure and no retained accepted plan. This is a
// declared provider operand passed through the real PostgreSQL owner APIs.
func (f *GuestRetirementForwardRecoveryFixture) FailedOrdinaryNativeOff() GuestNativePoweroffReturnV2 {
	f.t.Helper()
	if !f.ordinarySuccess {
		f.t.Fatal("complete ordinary caller fixture required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	read, err := f.FinishStore().PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID)
	if err != nil {
		f.t.Fatal("real original native OFF prepare", err)
	}
	at := time.Now().UTC()
	returned := GuestNativePoweroffReturnV2{Schema: "original_core_guest_native_poweroff_read_return_v2", Challenge: read, Status: "observed", StartedAtCore: at, OriginalReturnedAtCore: at, CallFailed: true}
	if err = f.FinishStore().RecordGuestNativePoweroffV2(ctx, returned); !errors.Is(err, ErrCapacityConflict) {
		f.t.Fatal("failed OFF must retain failure without qualification", err)
	}
	var rows, deletes int
	if err = f.DB.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1),(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`, f.Request.Intent.RequestID).Scan(&rows, &deletes); err != nil || rows != 2 || deletes != 0 {
		f.t.Fatal("closed original OFF pair and no DELETE", rows, deletes, err)
	}
	return returned
}

// ContentRefusedOrdinaryNativeOff supplies an explicit completed RPC with a
// declared non-OFF plan. The real recorder must retain false failure flags and
// prune that refused content; this does not infer the production power state.
func (f *GuestRetirementForwardRecoveryFixture) ContentRefusedOrdinaryNativeOff() GuestNativePoweroffReturnV2 {
	f.t.Helper()
	if !f.ordinarySuccess {
		f.t.Fatal("complete ordinary caller fixture required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	finish := f.FinishStore()
	read, err := finish.PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID)
	if err != nil {
		f.t.Fatal("actual content-refused original OFF prepare", err)
	}
	plan := capacity.RecoveryFixtureNativeOffPlan(f.t, f.Spec, f.Pre, f.Receipt.Enrollment.Statement.Tuple)
	if f.Spec.Profiles[0].Provider == "aws" {
		plan.DesiredSpec.Capability = "observe_ec2_instance"
		plan.RequestSHA256 = f.Spec.MutationBindings[0].Slots[f.Pre.Slot-1].DesiredSpecSHA256
	}
	plan.Server.Status = "running"
	at := time.Now().UTC()
	returned := GuestNativePoweroffReturnV2{Schema: "original_core_guest_native_poweroff_read_return_v2", Challenge: read, Status: "observed", Plan: &plan, StartedAtCore: at, OriginalReturnedAtCore: at}
	if err = finish.RecordGuestNativePoweroffV2(ctx, returned); !errors.Is(err, ErrCapacityConflict) {
		f.t.Fatal("real content refusal must retain its closed return", err)
	}
	var raw, join []byte
	var same bool
	if err = f.DB.QueryRow(`SELECT original_wire,original_native_join_wire,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2'`, f.Request.Intent.RequestID).Scan(&raw, &join, &same); err != nil {
		f.t.Fatal("actual retained content-refused original", err)
	}
	var stored GuestNativePoweroffReturnV2
	want := returned
	want.Plan = nil
	if !same || capacity.DecodeGuestLifecycle(raw, &stored) != nil || !reflect.DeepEqual(stored, want) || stored.CallFailed || stored.OriginalContextFailed || stored.Status != "observed" || stored.Plan != nil || !reflect.DeepEqual(join, failedServingWire(f.t, read)) {
		f.t.Fatal("recorder changed flags, challenge or custody instead of pruning refused Plan")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields["plan"] != nil || string(fields["call_failed"]) != "false" || string(fields["original_context_failed"]) != "false" {
		f.t.Fatal("explicit false flags and absent Plan required in actual original bytes")
	}
	var rows, deletes int
	if err = f.DB.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1),(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`, f.Request.Intent.RequestID).Scan(&rows, &deletes); err != nil || rows != 2 || deletes != 0 {
		f.t.Fatal("exact original pair and zero DELETE", rows, deletes, err)
	}
	return stored
}

// NormalFinishFailedWorkflowResult is the actual seven-step normal-retire /
// failed-finish shape, with the original signed body rather than a forward ID.
// It is supplied before the first dispatch result commit, never as an UPDATE.
func (f *GuestRetirementForwardRecoveryFixture) NormalFinishFailedWorkflowResult() model.RunWorkflowResponse {
	f.t.Helper()
	if !f.ordinarySuccess || len(f.Journal) != 4 || !f.Caller.BodyPersisted || f.Caller.Status != 200 {
		f.t.Fatal("genuine complete original caller and journal required")
	}
	r := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "failed"}
	for _, step := range f.private.steps {
		x := model.WorkflowRunStepResult{ID: step.ID, Kind: "yggdrasil", Operation: step.Use.Operation, Capability: step.Use.Operation, Status: "skipped"}
		switch step.ID {
		case "plan-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"mode": "retire", "generation": f.Intent.Generation, "fencing_token": f.Intent.FencingToken, "lease_owner": f.Intent.LeaseOwner, "preregistration_id": f.Pre.PreregistrationID, "slot": f.Pre.Slot}
		case "retire-original-guest":
			x.Status = "succeeded"
			x.Metadata = map[string]any{"request_id": f.Request.Intent.RequestID, "intent_sha256": capacity.GuestRetirementSHA(f.Request.Intent), "observation": f.Journal[3], "native_poweroff_known": false}
		case "finish-original-retirement":
			x.Status = "failed"
			x.Attempts = 1
			x.Error = "protected original Guest source step unavailable; HOLD and recover by exact GET"
			x.Metadata = map[string]any{"original_guest_refusal_predicate": "original-guest-step-17"}
		}
		r.Steps = append(r.Steps, x)
	}
	return r
}

func (f *GuestRetirementForwardRecoveryFixture) FinishNormalRetirementFailedRun() {
	f.t.Helper()
	if err := FinishCapacityDispatch(context.Background(), f.DB, f.job, f.NormalFinishFailedWorkflowResult(), time.Now().UTC(), nil); err != nil {
		f.t.Fatal("real normal-retire / failed-finish dispatch ACK", err)
	}
}
