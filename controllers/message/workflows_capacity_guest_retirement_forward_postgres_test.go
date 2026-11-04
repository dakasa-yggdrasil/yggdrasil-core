//go:build recoveryfixture && !nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func forwardFixtureInput(f *repository.GuestRetirementForwardRecoveryFixture) guestOriginalStepInput {
	return guestOriginalStepInput{BindingName: f.Spec.MutationBindings[0].Name, Slot: f.Pre.Slot, Generation: f.Intent.Generation, FencingToken: f.Intent.FencingToken, LeaseOwner: f.Intent.LeaseOwner, PreregistrationID: f.Pre.PreregistrationID}
}
func forwardFixtureStep(t *testing.T, f *repository.GuestRetirementForwardRecoveryFixture, id string) model.WorkflowStepSpec {
	t.Helper()
	var w model.WorkflowManifestSpec
	if err := json.Unmarshal(f.Workflow.Spec, &w); err != nil {
		t.Fatal(err)
	}
	for _, step := range w.Steps {
		if step.ID == id {
			return step
		}
	}
	t.Fatal("actual seven-step Source graph missing operation", id)
	return model.WorkflowStepSpec{}
}

func TestGuestRetirementForwardLiveWorkflowDoesNotReplayGuestPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := repository.NewGuestRetirementForwardRecoveryFixture(t, provider, 3, 3)
			before := f.PreservedOriginals()
			// Observe natural closure of the preceding accepted canary windows;
			// this does not rewrite an attempt, lease, counter or ACK.
			var delay float64
			if err := f.DB.QueryRow(`SELECT COALESCE(GREATEST(0,EXTRACT(EPOCH FROM(max(original_deadline)-clock_timestamp()))),0) FROM public.capacity_guest_notify_canary_challenges`).Scan(&delay); err != nil || delay > 6 {
				t.Fatal("bounded original canary windows", delay, err)
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay*float64(time.Second)) + 5*time.Millisecond)
			}
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			input := forwardFixtureInput(f)
			out, err := liveGuestRetirementForward(ctx, f.RetirementStore(), f.Policy, input, f.Request.Intent.RequestID)
			if err != nil {
				t.Logf("later admission observation: %s", f.AdmissionDiagnostics())
				t.Fatal("actual live forward admission", err)
			}
			meta, ok := out.(map[string]any)
			if !ok || meta["request_id"] != f.Request.Intent.RequestID || meta["normal_guest_success"] != false || meta["native_destroy_sent"] != false {
				t.Fatal("live failure fabricated normal success", out)
			}
			// Enter the real retirement controller with no DB client/key for Guest
			// I/O. A correctly owned retained original returns before that path.
			out, err = executeProductionGuestRetirementV2(ctx, nil, f.RetirementStore(), f.Policy, f.Spec, forwardFixtureStep(t, f, "retire-original-guest"), input, f.Spec.GuestRetirementBinding.Members[input.Slot-1], nil)
			if err != nil {
				t.Fatal("retained retirement repeated Guest work", err)
			}
			meta, ok = out.(map[string]any)
			if !ok || meta["guest_command_replayed"] != false {
				t.Fatal("retained retirement lost its distinct disposition", out)
			}
			plan, handled, err := planGuestRetirementForward(ctx, f.PlanStore(), f.Policy, f.Workflow, forwardFixtureStep(t, f, "plan-original-guest"))
			if err != nil || !handled {
				if err != nil {
					t.Logf("later admission observation: %s", f.AdmissionDiagnostics())
				}
				t.Fatal("active live admission fell through to dead-target coverage", err)
			}
			hold, ok := plan.(map[string]any)
			if !ok || hold["mode"] != "hold" {
				t.Fatal("generic plan rearmed a live admission", plan)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("live/historical hook changed original wire evidence")
			}
			var deletes int
			if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings`).Scan(&deletes); err != nil || deletes != 0 {
				t.Fatal("admission/retire hook issued delete authority", deletes, err)
			}
		})
	}
}

func TestGuestRetirementForwardHistoricalPlanClaimsBeforeCoveragePostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := repository.NewGuestRetirementForwardRecoveryFixture(t, provider, 3, 4)
			f.FinishFailedRun("retire-original-guest")
			barrier := f.WaitHistoricalBarrier()
			before := f.PreservedOriginals()
			ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
			defer stop()
			_, err := f.Store.RequestGuestRetirementForwardHistorical(ctx, f.HistoricalRequest(), "collaborator:"+uuid.NewString(), barrier, func(context.Context) error { return nil })
			if err != nil {
				t.Logf("later admission observation: %s", f.AdmissionDiagnostics())
				t.Fatal("declared historical original admission", err)
			}
			f.StartSuccessorDispatch()
			ctx = context.WithValue(ctx, originalGuestReconcileOwnerKey{}, &capacity.OriginalGuestReconcileOwner{})
			out, handled, err := planGuestRetirementForward(ctx, f.PlanStore(), f.Policy, f.Workflow, forwardFixtureStep(t, f, "plan-original-guest"))
			if err != nil || !handled {
				if err != nil {
					t.Logf("later admission observation: %s", f.AdmissionDiagnostics())
				}
				t.Fatal("historical plan did not claim before coverage", err)
			}
			plan, ok := out.(originalGuestReconcilePlan)
			if !ok || plan.Mode != "retire" || plan.Slot != 3 || plan.Generation != f.Intent.Generation || plan.FencingToken != f.Intent.FencingToken+1 || plan.PreregistrationID != f.Pre.PreregistrationID || plan.LeaseOwner == f.Intent.LeaseOwner {
				t.Fatal("historical claim changed generation/target or reused fence", out)
			}
			input := forwardFixtureInput(f)
			input.Generation, input.FencingToken, input.LeaseOwner = plan.Generation, plan.FencingToken, plan.LeaseOwner
			out, err = executeProductionGuestRetirementV2(ctx, nil, f.RetirementStore(), f.Policy, f.Spec, forwardFixtureStep(t, f, "retire-original-guest"), input, f.Spec.GuestRetirementBinding.Members[input.Slot-1], nil)
			if err != nil {
				t.Fatal("historical retire did not select retained request", err)
			}
			meta, ok := out.(map[string]any)
			if !ok || meta["request_id"] != f.Request.Intent.RequestID || meta["guest_command_replayed"] != false || meta["normal_guest_success"] != false {
				t.Fatal("historical claim fabricated Guest ACK", out)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("historical claim changed original signed prefix/frame")
			}
			var deletes int
			if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings`).Scan(&deletes); err != nil || deletes != 0 {
				t.Fatal("plan claim issued provider authority", deletes, err)
			}
		})
	}
}

// The callback is an explicit declared adapter DTO operand. Core's actual
// five-second prepare/return/custody/lease APIs execute against real PG; this
// does not qualify a production registry, provider SDK or native Guest.
func TestGuestRetirementForwardSourceReadClocksPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := repository.NewGuestRetirementForwardLiveWorkflowFixture(t, provider, 3, 3)
			before := f.PreservedOriginals()
			var delay float64
			if err := f.DB.QueryRow(`SELECT COALESCE(GREATEST(0,EXTRACT(EPOCH FROM(max(original_deadline)-clock_timestamp()))),0) FROM public.capacity_guest_notify_canary_challenges`).Scan(&delay); err != nil || delay > 6 {
				t.Fatal("actual preceding canary window", delay, err)
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay*float64(time.Second)) + 5*time.Millisecond)
			}
			ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
			defer stop()
			if _, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err != nil {
				t.Logf("later admission observation: %s", f.AdmissionDiagnostics())
				t.Fatal(err)
			}
			input := forwardFixtureInput(f)
			input.RequestID = f.Request.Intent.RequestID
			ids := []string{}
			for _, status := range []string{"stopping", ""} {
				returned, _, err := sourceGuestRetirementForwardReadWithCall(ctx, f.FinishStore(), input, "off", model.CapacityMutationReceipt{}, func(read context.Context, out *repository.GuestRetirementForwardReadReturn) error {
					deadline, ok := read.Deadline()
					if !ok || deadline.Sub(out.Read.IssuedAtCore) > 5*time.Second || !out.Read.OriginalDeadlineCore.After(out.Read.IssuedAtCore) || out.Read.OriginalDeadlineCore.Sub(out.Read.IssuedAtCore) > 5*time.Second {
						t.Fatal("Source read extended original five-second budget")
					}
					declared := f.NativeOffReturn(out.Read, status)
					out.Status, out.Plan, out.StartedAtCore = declared.Status, declared.Plan, declared.StartedAtCore
					return nil
				})
				if status == "stopping" && !errors.Is(err, repository.ErrGuestRetirementForwardNativePending) || status == "" && err != nil {
					t.Fatal("actual retained native classification", status, err)
				}
				if returned.CallFailed || returned.OriginalContextFailed || returned.StartedAtCore.IsZero() || returned.OriginalReturnedAtCore.Before(returned.StartedAtCore) {
					t.Fatal("successful original read clocks were fabricated")
				}
				ids = append(ids, returned.Read.ReadID)
			}
			t.Run("failed_before_wrapper", func(t *testing.T) {
				returned, _, err := sourceGuestRetirementForwardReadWithCall(ctx, f.FinishStore(), input, "off", model.CapacityMutationReceipt{}, func(read context.Context, out *repository.GuestRetirementForwardReadReturn) error {
					if out.StartedAtCore.IsZero() || out.StartedAtCore.Before(out.Read.IssuedAtCore) {
						t.Fatal("actual start missing before resolution")
					}
					return errors.New("declared unavailable read")
				})
				if err == nil || !returned.CallFailed || returned.OriginalContextFailed || returned.ObserverSourceCommit != "" || len(returned.OriginalObserverReturn) != 0 || returned.OriginalReturnedAtCore.Before(returned.StartedAtCore) {
					t.Fatal("failed read fabricated or discarded provenance")
				}
				var failed bool
				if f.DB.QueryRow(`SELECT original_record->>'call_failed'='true' AND NOT (original_record ? 'observer_source_commit') AND NOT (original_record ? 'original_observer_return') FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, returned.Read.ReadID).Scan(&failed) != nil || !failed {
					t.Fatal("failure without wrapper not retained")
				}
				ids = append(ids, returned.Read.ReadID)
			})
			short, cancel := context.WithTimeout(ctx, time.Second)
			returned, _, err := sourceGuestRetirementForwardReadWithCall(short, f.FinishStore(), input, "off", model.CapacityMutationReceipt{}, func(read context.Context, out *repository.GuestRetirementForwardReadReturn) error {
				out.StartedAtCore = time.Now().UTC()
				<-read.Done()
				// Source must derive these flags after the actual call, not trust
				// a transport's optional boolean or revive its expired timer.
				out.CallFailed, out.OriginalContextFailed = false, false
				return read.Err()
			})
			cancel()
			if err == nil || !returned.CallFailed || !returned.OriginalContextFailed || returned.OriginalReturnedAtCore.Before(returned.Read.OriginalDeadlineCore) {
				t.Fatal("expired original read gained OFF authority", err, returned.CallFailed, returned.OriginalContextFailed)
			}
			ids = append(ids, returned.Read.ReadID)
			seen := map[string]bool{}
			for _, id := range ids {
				if id == "" || seen[id] {
					t.Fatal("a fresh read reused an earlier challenge")
				}
				seen[id] = true
			}
			var retained, failed, grants int
			if err = f.DB.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_guest_retirement_forward_reads WHERE stage='returned'),(SELECT count(*) FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned' AND original_record->>'call_failed'='true' AND original_record->>'original_context_failed'='true'),(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings)`, returned.Read.ReadID).Scan(&retained, &failed, &grants); err != nil || retained != 4 || failed != 1 || grants != 0 {
				t.Fatal("failed actual return was lost or promoted", retained, failed, grants, err)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("new read rewrote old Guest/frame/caller evidence")
			}
		})
	}
}

func TestGuestRetirementForwardOrdinaryReadonlySourceClocksPostgres(t *testing.T) {
	f := repository.NewGuestRetirementOrdinaryRecoveryFixture(t, "aws")
	receipt := f.SettledOrdinaryDestroy()
	before := f.PreservedOriginals()
	input := forwardFixtureInput(f)
	input.RequestID = f.Request.Intent.RequestID
	ids := map[string]bool{}
	for _, mode := range []string{"failed_before_wrapper", "original_timeout", "authenticated_pending", "complete_not_found"} {
		t.Run(mode, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			if mode == "original_timeout" {
				stop()
				ctx, stop = context.WithTimeout(context.Background(), 300*time.Millisecond)
			}
			defer stop()
			var entered time.Time
			returned, proof, pending, err := sourceProductionNativeAbsenceV2WithCall(ctx, f.FinishStore(), input, receipt, func(read context.Context, out *repository.GuestNativeAbsenceReturnV2) error {
				entered = time.Now().UTC()
				if out.StartedAtCore.IsZero() || out.StartedAtCore.After(entered) || out.Challenge.IntentID != input.RequestID {
					t.Fatal("ordinary owning clock/challenge missing before resolution")
				}
				if mode == "failed_before_wrapper" {
					return errOriginalGuestStep
				}
				if mode == "original_timeout" {
					<-read.Done()
					return read.Err()
				}
				declared := f.OrdinaryAbsenceReturn(out.Challenge, receipt)
				declared.Observation.AWSRetirementLifecycle.EC2State = "not_found"
				if mode == "authenticated_pending" {
					declared.Observation.BillableResourcesAbsent, declared.Observation.RetirementComplete = false, false
					declared.Observation.AuxiliaryResources[0].Absent = false
					declared.Observation.HoldReasons = []string{"aws_ebs_volume_still_present"}
				}
				var wrapper repository.GuestRetirementReadonlyReturn
				if json.Unmarshal(declared.OriginalObserverReturn, &wrapper) != nil {
					t.Fatal("declared current wrapper")
				}
				wrapper.Observation = *declared.Observation
				out.Status, out.Observation = declared.Status, declared.Observation
				out.ObserverSourceCommit = declared.ObserverSourceCommit
				out.OriginalObserverReturn, _ = json.Marshal(wrapper)
				return nil
			})
			if returned.Challenge.ReadID == "" || ids[returned.Challenge.ReadID] || returned.StartedAtCore.After(entered) || returned.OriginalReturnedAtCore.Before(entered) || returned.Challenge.OriginalDeadlineCore.Sub(returned.Challenge.IssuedAtCore) > 5*time.Second {
				t.Fatal("ordinary original read identity/clocks reset")
			}
			ids[returned.Challenge.ReadID] = true
			if (err == nil) != (mode == "complete_not_found") || pending != (mode == "authenticated_pending") || proof.ResourceAbsent != (mode == "complete_not_found") || returned.CallFailed != (mode == "failed_before_wrapper" || mode == "original_timeout") || returned.OriginalContextFailed != (mode == "original_timeout") {
				t.Fatal("ordinary pending/failure became success or timing was relabeled", mode, err, pending)
			}
			var raw []byte
			if f.DB.QueryRow(`SELECT original_wire FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 AND original_observation_record->'challenge'->>'read_id'=$2`, receipt.Grant.GrantID, returned.Challenge.ReadID).Scan(&raw) != nil {
				t.Fatal("ordinary failed/late return not retained")
			}
			var stored repository.GuestNativeAbsenceReturnV2
			if capacity.DecodeGuestLifecycle(raw, &stored) != nil || stored.StartedAtCore != returned.StartedAtCore || stored.OriginalReturnedAtCore != returned.OriginalReturnedAtCore || stored.CallFailed != returned.CallFailed || stored.OriginalContextFailed != returned.OriginalContextFailed || !reflect.DeepEqual(stored.OriginalObserverReturn, returned.OriginalObserverReturn) {
				t.Fatal("ordinary storage changed actual clocks/flags/public wrapper")
			}
		})
	}
	var admissions, bindings, readbacks int
	if f.DB.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_guest_retirement_forwards),(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings),(SELECT count(*) FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1)`, receipt.Grant.GrantID).Scan(&admissions, &bindings, &readbacks) != nil || admissions != 0 || bindings != 1 || readbacks != 4 || len(ids) != 4 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
		t.Fatal("ordinary read introduced a forward child/DELETE or changed original Guest evidence")
	}
}
