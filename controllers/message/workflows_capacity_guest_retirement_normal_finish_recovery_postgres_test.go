//go:build recoveryfixture && !nativequalification

package message

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/pressly/goose/v3"
)

// The actual planner must discover normal-finish recovery without a manual
// admission or existing marker, before attempting complete coverage of the
// now-powered-off Guest. Every adapter operand below is explicitly declared;
// actual Core prepare/return/lease/custody APIs run against isolated PG16/17.
func TestGuestRetirementForwardNormalFinishRecoveryPlanPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := repository.NewGuestRetirementNormalFinishRecoveryFixture(t, provider)
			ctx, stop := context.WithTimeout(context.Background(), 150*time.Second)
			defer stop()
			if err := goose.UpToContext(ctx, f.DB, filepath.Join("..", "..", "db", "migrations"), 97); err != nil {
				t.Fatal("isolated normal-finish schema97", err)
			}
			failedOFF := f.FailedOrdinaryNativeOff()
			f.FinishNormalRetirementFailedRun()
			before := f.PreservedOriginals()
			old := f.Intent
			f.WaitHistoricalBarrier()
			f.StartSuccessorDispatch()
			ctx = context.WithValue(ctx, originalGuestReconcileOwnerKey{}, &capacity.OriginalGuestReconcileOwner{})
			out, handled, err := planGuestRetirementForward(ctx, f.PlanStore(), f.Policy, f.Workflow, forwardFixtureStep(t, f, "plan-original-guest"))
			if err != nil || !handled {
				t.Fatal("real plan did not automatically select failed normal finish", out, handled, err, f.AdmissionDiagnostics())
			}
			plan, ok := out.(originalGuestReconcilePlan)
			if !ok || plan.Mode != "retire" || plan.Reason != repository.GuestRetirementForwardNormalFinishRecoveryMode || plan.Generation != old.Generation || plan.FencingToken != old.FencingToken+1 || plan.LeaseOwner == old.LeaseOwner || plan.PreregistrationID != f.Pre.PreregistrationID || plan.Slot != 2 {
				t.Fatal("automatic planner changed original target or reused old authority", out)
			}
			rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
			if err != nil || len(rows) != 2 || rows[0].Mode != repository.GuestRetirementForwardNormalFinishRecoveryMode || rows[0].NormalFinishRecovery == nil || rows[0].Stage != "requested" || rows[1].Stage != "admitted" || rows[1].DestroyGrantID != "" {
				t.Fatal("automatic request/admit lineage is incomplete", rows, err)
			}
			f.HistoricalRequest() // Read the actual claimed epoch; never edit an old timer.
			input := forwardFixtureInput(f)
			// Nil Guest DB/key cannot send a new nonce, retirement POST, withdrawal,
			// drain or poweroff. A retained normal recovery must return before them.
			out, err = executeProductionGuestRetirementV2(ctx, nil, f.RetirementStore(), f.Policy, f.Spec, forwardFixtureStep(t, f, "retire-original-guest"), input, f.Spec.GuestRetirementBinding.Members[input.Slot-1], nil)
			if err != nil {
				t.Fatal("recovery retire hook attempted original Guest work", err)
			}
			metadata, ok := out.(map[string]any)
			if !ok || metadata["request_id"] != f.Request.Intent.RequestID || metadata["guest_command_replayed"] != false || metadata["native_destroy_sent"] != false {
				t.Fatal("recovery hook lost retained original identity", out)
			}
			calls := 0
			finish := f.FinishStore()
			observe := func(status string) error {
				_, _, readErr := sourceGuestRetirementForwardReadWithCall(ctx, finish, input, "off", model.CapacityMutationReceipt{}, func(original context.Context, returned *repository.GuestRetirementForwardReadReturn) error {
					calls++
					deadline, exists := original.Deadline()
					if !exists || original.Err() != nil || !deadline.After(time.Now()) || time.Until(deadline) > 5*time.Second || returned.Read.ReadID == failedOFF.Challenge.ReadID || returned.Read.IssuedAtCore.Before(failedOFF.Challenge.OriginalDeadlineCore) {
						t.Fatal("recovery reused the failed original read/clock")
					}
					*returned = f.NativeOffReturn(returned.Read, status)
					return nil
				})
				return readErr
			}
			if err = observe("stopping"); !errors.Is(err, repository.ErrGuestRetirementForwardNativePending) {
				t.Fatal("new authenticated stopping read must remain pending", err)
			}
			var deletes int
			if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&deletes); err != nil || deletes != 0 {
				t.Fatal("pending fresh OFF issued DELETE", deletes, err)
			}
			if err = observe(""); err != nil || calls != 2 {
				t.Fatal("fresh completed OFF did not qualify under the new owner", calls, err)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("automatic planner/retire/fresh reads changed original success or failed ACK")
			}
			if err = f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&deletes); err != nil || deletes != 0 {
				t.Fatal("OFF qualification bypassed the independent new survivor floor", deletes, err)
			}
		})
	}
}
