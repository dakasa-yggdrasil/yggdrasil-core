package repository

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Exercise the exact waiting decision used by the scheduler owner after its
// unchanged Source authentication and scope/current-intent locks. These are
// real PG79 storage fixtures, not production Guest signatures or Issue proof.
func TestPresendRecoverySchedulerReachabilityPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	for _, name := range []string{"no_recovery_still_waits", "matching_requested_reaches_claim", "foreign_disposal_still_waits", "different_current_fence_refused", "different_current_pre_refused", "different_original_current_refused", "recovery_marker_still_waits", "already_claimed_recovery_still_waits", "non_plan_still_refused"} {
		t.Run(name, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			_, parent, old, disposal, recovery := recoveryStorageFixture(t, tx, ctx, policy)
			p := model.CapacityPolicySpec{Environment: old.Environment, Domain: old.Domain, Dimension: old.Dimension}
			if err := lockMutationScope(ctx, tx, old.Namespace, p); err != nil {
				t.Fatal(err)
			}
			store := CapacityStore{guestReconcile: &guestReconcileSource{step: model.WorkflowStepSpec{Use: model.WorkflowStepUseSpec{Operation: capacity.PlanOriginalGuestOperation}}}}
			before := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)
			var admissionSHA string
			if name != "no_recovery_still_waits" && name != "foreign_disposal_still_waits" {
				var err error
				admissionSHA, err = insertRetirementRecoveryTx(ctx, tx, recovery)
				if err != nil {
					t.Fatal(err)
				}
			}
			current := old
			marker := *old.FailedInstalledDisposal
			current.FailedInstalledDisposal = &marker
			switch name {
			case "foreign_disposal_still_waits":
				_, _, _, _, other := recoveryStorageFixture(t, tx, ctx, policy)
				if _, err := insertRetirementRecoveryTx(ctx, tx, other); err != nil {
					t.Fatal(err)
				}
			case "different_current_fence_refused":
				current.FencingToken++
			case "different_current_pre_refused":
				marker.PreregistrationID = uuid.NewString()
			case "different_original_current_refused":
				current.UpdatedAt = current.UpdatedAt.Add(time.Second)
			case "recovery_marker_still_waits":
				marker.RetirementRecoveryID = recovery.ID
			case "already_claimed_recovery_still_waits":
				current = recoveryClaimStorage(t, tx, ctx, old, recovery, admissionSHA)
			case "non_plan_still_refused":
				store.guestReconcile.step.Use.Operation = capacity.CompleteOriginalGuestOperation
			}
			got, waiting, err := store.failedInstalledGuestDisposalWaitingTx(ctx, tx, current, "")
			switch name {
			case "matching_requested_reaches_claim":
				if err != nil || waiting || got.ID != disposal.ID {
					t.Fatal("explicit79 admission did not reach unchanged claim", waiting, err)
				}
				// Reaching the claim is not claim authorization: an unqualified assessment
				// still fails the complete original claim predicate without any new epoch.
				if _, _, eligible, e := store.claimNeverSentRecoveryTx(ctx, tx, policy, p, old, model.CapacityAssessment{}, time.Now().UTC()); !errors.Is(e, ErrCapacityConflict) || eligible {
					t.Fatal("waiting exception bypassed claim authorization", e)
				}
			case "different_current_fence_refused", "different_current_pre_refused", "different_original_current_refused", "non_plan_still_refused":
				if !errors.Is(err, ErrCapacityConflict) {
					t.Fatal("foreign current or operation accepted", err)
				}
			default:
				if err != nil || !waiting || got.ID != disposal.ID {
					t.Fatal("ordinary claimed disposal escaped hold", waiting, err)
				}
			}
			if !bytes.Equal(before, recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)) {
				t.Fatal("immutable parent or78 claim changed")
			}
			var claimed, issued, intents int
			if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries WHERE id=$1 AND stage='claimed'),(SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries WHERE id=$1 AND stage='issued'),(SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$2)`, recovery.ID, recovery.PreregistrationID).Scan(&claimed, &issued, &intents); err != nil {
				t.Fatal(err)
			}
			expectedClaimed := 0
			if name == "already_claimed_recovery_still_waits" {
				expectedClaimed = 1
			}
			if claimed != expectedClaimed || issued != 0 || intents != 1 {
				t.Fatal("waiting decision minted claim/Guest intent", claimed, issued, intents)
			}
		})
	}
}
