//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func forwardTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(stop)
	return ctx
}
func forwardTestRowCount(t *testing.T, f *GuestRetirementForwardRecoveryFixture, table string) int {
	t.Helper()
	if table != "capacity_guest_retirement_forwards" && table != "capacity_guest_retirement_forward_reads" && table != "capacity_vm_retirement_delete_bindings" {
		t.Fatal("closed count table")
	}
	var n int
	if err := f.DB.QueryRow("SELECT count(*) FROM public." + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Exercise real PostgreSQL admission/typed native reads, survivor canaries,
// normal one-shot grant/redemption/settlement/absence/confirmation and terminal
// transition. Provider/process/metric shapes are DECLARED signed fixture inputs,
// never an actual Guest, SDK, native readiness or useful business qualification.
func TestGuestRetirementForwardLivePostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, tail := range []int{2, 3, 8} {
			t.Run(fmt.Sprintf("%s/tail%d", provider, tail), func(t *testing.T) {
				var f *GuestRetirementForwardRecoveryFixture
				if tail == 2 {
					f = NewGuestRetirementForwardFractionalOriginalFixture(t, provider)
				} else if tail == 8 {
					f = NewGuestRetirementForwardLiveWorkflowFixture(t, provider, tail, 3+(tail%2))
				} else {
					f = NewGuestRetirementForwardRecoveryFixture(t, provider, tail, 3+(tail%2))
				}
				ctx := forwardTestContext(t)
				if tail == 2 {
					nativeDeadline := f.Request.Intent.OriginalDeadline
					if nativeDeadline.Nanosecond()%1000 != 789 {
						t.Fatal("initial signed fractional deadline was not retained")
					}
					rows, err := f.DB.QueryContext(ctx, `SELECT original_deadline,original_deadline<=$2::timestamptz FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1 ORDER BY phase,ordinal`, f.Request.Intent.RequestID, nativeDeadline.Format(time.RFC3339Nano))
					if err != nil {
						t.Fatal(err)
					}
					count, roundedAfterNative := 0, false
					for rows.Next() {
						var pgDeadline time.Time
						var withinSignedPG bool
						if err = rows.Scan(&pgDeadline, &withinSignedPG); err != nil || !withinSignedPG {
							rows.Close()
							t.Fatal("actual PG authority exceeded canonical signed bound", err)
						}
						count++
						roundedAfterNative = roundedAfterNative || pgDeadline.After(nativeDeadline)
					}
					rowErr, closeErr := rows.Err(), rows.Close()
					if rowErr != nil || closeErr != nil || count != 4 || !roundedAfterNative {
						t.Fatal("actual source ingress did not exercise submicrosecond clipping", count, roundedAfterNative, rowErr, closeErr)
					}
				}
				before := f.PreservedOriginals()
				admitted, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
				if err != nil || admitted.Mode != "live" || admitted.Stage != "admitted" || admitted.PreregistrationID != f.Pre.PreregistrationID || admitted.PrefixSHA256 == "" || admitted.OriginalCallerSHA256 == "" {
					t.Fatal("real live admission", admitted, err, f.AdmissionDiagnostics())
				}
				if _, err = f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
					t.Fatal("admission replay overwrote original")
				}
				if _, err = f.Store.PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID); err == nil {
					t.Fatal("partial failed caller acquired unchanged normal-success authority")
				}
				finish := f.FinishStore()
				read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = finish.RecordGuestRetirementForwardRead(ctx, f.NativeOffReturn(read, "stopping")); !errors.Is(err, ErrGuestRetirementForwardNativePending) {
					t.Fatal("authenticated stopping must only HOLD", err)
				}
				if forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 0 {
					t.Fatal("pending OFF authorized DELETE")
				}
				if _, err = finish.AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
					t.Fatal("pending OFF advanced drain")
				}
				forwardTestComplete(t, f, ctx)
				if !reflect.DeepEqual(before, f.PreservedOriginals()) {
					t.Fatal("forward completion rewrote an original birth/caller/nonce/journal/authority frame")
				}
			})
		}
	}
	retirementForwardPreDestroy103Regression(t)
}

func forwardTestSettledDestroy(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, settle bool) model.CapacityMutationReceipt {
	t.Helper()
	finish := f.FinishStore()
	old, found, err := finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		if (old.Grant.State != "settled" && old.Grant.State != "confirmed") || old.Outcome != "accepted" || !old.TransportCompleted {
			t.Fatal("unknown parent destroy cannot be reissued")
		}
		// The accepted owning DELETE may already have removed the target.
		// Only its existing receipt + fresh survivor/absence reads continue.
		f.Canaries("after_retirement_floor")
		if err = finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Inventory(false)); err != nil {
			t.Fatal("known parent DELETE survivor-only refresh", err)
		}
		return old
	}
	read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = finish.RecordGuestRetirementForwardRead(ctx, f.NativeOffReturn(read, "")); err != nil {
		t.Fatal("new source-owned OFF read", err)
	}
	if _, err = finish.AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
		t.Fatal("old before-floor canary replaced new after-admission proof")
	}
	f.Canaries("after_retirement_floor")
	if err = finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Inventory(true)); err != nil {
		t.Fatal("exact current native inventory refresh", err)
	}
	drained, err := finish.AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil || drained.Phase != "drained" {
		t.Fatal("new OFF+all surviving useful members", err)
	}
	f.Intent = drained

	b := f.Spec.MutationBindings[0]
	spec := *b.Slots[f.Pre.Slot-1].DesiredSpec
	spec.Capability = b.DestroyCapability
	spec.ExpectedResourceID = f.Request.Intent.Tuple.ResourceID
	spec.ExpectedResourceCreatedAt = f.Request.Intent.Tuple.CreatedAt
	issue := model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: failedServingWire(t, spec)}
	grant, err := finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, issue)
	if err != nil || grant.State != "issued" || grant.Slot != f.Pre.Slot || grant.ExpectedResourceID != f.Request.Intent.Tuple.ResourceID {
		t.Fatal("exact ordinary owned DELETE grant", grant, err)
	}
	// An issued/unknown operation is already custody. The receipt lookup cannot
	// infer no-send, nor may a second issue mint a new grant for the same tail.
	pending, found, err := finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
	if err != nil || !found || pending.Grant.GrantID != grant.GrantID || pending.Grant.State != "issued" {
		t.Fatal("issued DELETE custody lost", err, f.AdmissionDiagnostics())
	}
	again, err := finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, issue)
	if err == nil && again.GrantID != grant.GrantID {
		t.Fatal("issued DELETE was resent through another grant")
	}
	if _, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", grant.GrantID); err == nil {
		t.Fatal("issued/unknown DELETE produced absence proof")
	}
	if !settle {
		return pending
	}
	callback := CapacityStore{DB: f.DB, ExecutionEnabled: true} // Actual adapter callbacks carry no workflow/source context.
	nonce := uuid.NewString()
	redeem := mutationRedeem(grant, nonce)
	permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, redeem)
	if err != nil || permit.Mode != "write_once" {
		t.Fatal("single actual redemption", err)
	}
	second, secondErr := callback.RedeemMutation(ctx, b.AdapterPrincipalID, redeem)
	if secondErr == nil && second.Mode == "write_once" {
		t.Fatal("redeemed DELETE acquired second write permit")
	}
	settled, err := callback.SettleMutation(ctx, b.AdapterPrincipalID, nonce, f.DestroySettlement(grant, redeem.AttemptID))
	if err != nil || settled.State != "settled" {
		t.Fatal("original destroy return", err)
	}
	receipt, found, err := finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
	if err != nil || !found || receipt.Grant.State != "settled" {
		t.Fatal("actual original settled receipt read", err)
	}
	return receipt
}

func forwardTestComplete(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	_, record, handled, err := f.FinishStore().GuestRetirementForwardOriginal(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil || !handled {
		t.Fatal("current forward owner", err)
	}
	adopted := record.DestroyGrantID != ""
	receipt := forwardTestSettledDestroy(t, f, ctx, true)
	grant := receipt.Grant
	finish := f.FinishStore()
	var read GuestRetirementForwardRead
	read, err = finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := finish.RecordGuestRetirementForwardRead(ctx, f.NativeAbsenceReturn(read, receipt))
	if err != nil || !proof.ResourceAbsent || proof.GrantID != grant.GrantID {
		t.Fatal("actual typed native absence join", err)
	}
	if receipt.Grant.State != "confirmed" {
		if _, err = finish.ConfirmMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, proof); err != nil {
			t.Fatal("normal locked native slot confirmation", err)
		}
	}
	complete, assessment := f.CompletionOperands()
	next, err := complete.AdvanceOriginalGuest(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, "promoted", assessment)
	if err != nil || next.Phase != "promoted" || next.RetirementForward == nil || next.RetirementForward.Stage != "terminal" || next.Assessment.Snapshot.Units != f.Pre.Slot-1 || next.LeaseOwner != "" || next.LeaseExpiresAt != nil {
		t.Fatal("N-1 terminal authority", next, err)
	}
	rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
	if err != nil || len(rows) < 3 || (rows[len(rows)-2].Stage != "off_qualified" && !adopted) || rows[len(rows)-1].Stage != "terminal" || rows[len(rows)-1].DestroyGrantID != grant.GrantID || rows[len(rows)-1].TerminalIntentSHA256 == "" {
		t.Fatal("immutable three-stage ledger", rows, err)
	}
	var slotWire []byte
	if err = f.DB.QueryRow(`SELECT slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=$2`, f.Policy.Metadata.Namespace, f.Pre.Slot).Scan(&slotWire); err != nil {
		t.Fatal(err)
	}
	var slot capacityResourceSlot
	if json.Unmarshal(slotWire, &slot) != nil || !slot.Tombstone || slot.ResourceID != "" {
		t.Fatal("target was not exactly tombstoned")
	}
	for n := 1; n < f.Pre.Slot; n++ {
		var id string
		if err = f.DB.QueryRow(`SELECT resource_id FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=$2`, f.Policy.Metadata.Namespace, n).Scan(&id); err != nil || id != f.members[n-1].reg.Result.Tuple.ResourceID {
			t.Fatal("survivor identity changed", n, err)
		}
	}
	// A committed terminal record is immutable history, not a permanent latch
	// on the next ordinary assessment. Source cooldown/down-hold rules remain.
	normal, err := f.Store.Assess(ctx, f.Policy, assessment)
	if err != nil || normal.RetirementForward != nil {
		t.Fatal("terminal marker blocked the next ordinary assessment", err)
	}

}

// Admission is atomic across both operator callbacks and CAS mismatch. A failed
// second callback must not leave a marker/record, and a replay never rewrites it.
func TestGuestRetirementForwardHistoricalAndAtomicityPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := NewGuestRetirementForwardRecoveryFixture(t, provider, 2, 3)
			f.FinishFailedRun("retire-original-guest")
			barrier := f.WaitHistoricalBarrier()
			ctx := forwardTestContext(t)
			before := f.PreservedOriginals()
			req := f.HistoricalRequest()
			t.Run("readonly_inspection", func(t *testing.T) {
				actor := uuid.NewString()
				if _, err := f.DB.Exec(`INSERT INTO public.collaborators(id,slug,status,display_name,traits) VALUES($1,$2,'active','Declared inspection test human','{"yggdrasil_admin":true}'::jsonb)`, actor, "inspection-human-"+actor); err != nil {
					t.Fatal(err)
				}
				var database string
				if err := f.DB.QueryRow(`SELECT current_database()`).Scan(&database); err != nil {
					t.Fatal(err)
				}
				// Successful inspection must not even ATTEMPT DML. Rollback alone
				// would conceal such an attempt from a before/after row census.
				if _, err := f.DB.Exec(`CREATE FUNCTION public.inspection_reject_dml() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'readonly inspection attempted DML'; END $$;
DO $$ DECLARE r record; BEGIN FOR r IN SELECT c.oid::regclass AS target FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p') LOOP EXECUTE format('CREATE TRIGGER inspection_reject_dml BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION public.inspection_reject_dml()',r.target); END LOOP; END $$;`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := f.DB.Exec(`DO $$ DECLARE r record; BEGIN FOR r IN SELECT c.oid::regclass AS target FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p') LOOP EXECUTE format('DROP TRIGGER inspection_reject_dml ON %s',r.target); END LOOP; END $$; DROP FUNCTION public.inspection_reject_dml();`); err != nil {
						t.Fatal(err)
					}
				}()
				got := f.Store.InspectGuestRetirementForwardHistorical(ctx, req, actor, barrier, barrier.SourceCommit, database)
				if !got.ReadChecksPassed || !got.TypedIntentCAS || !got.RolledBack || got.MutationAttempted || got.AdmissionCreated || got.Stage != "read_checks_complete_no_admission" || got.FailedRunCount != 1 {
					t.Fatalf("readonly inspection: %+v", got)
				}
				stale := req
				stale.IntentSHA256 = strings.Repeat("f", 64)
				got = f.Store.InspectGuestRetirementForwardHistorical(ctx, stale, actor, barrier, barrier.SourceCommit, database)
				if got.ReadChecksPassed || !got.RolledBack || got.Stage != "historical_seven_cas_and_barrier" || got.FailureClass != "validation_refused" {
					t.Fatalf("exact refused read stage: %+v", got)
				}
				if !reflect.DeepEqual(before, f.PreservedOriginals()) || f.HistoricalRequest().IntentSHA256 != req.IntentSHA256 || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 || forwardTestRowCount(t, f, "capacity_guest_retirement_forward_reads") != 0 {
					t.Fatal("inspection changed original, intent or admission ledgers")
				}
			})
			calls := 0
			_, err := f.Store.RequestGuestRetirementForwardHistorical(ctx, req, "collaborator:"+uuid.NewString(), barrier, func(context.Context) error {
				calls++
				if calls == 2 {
					return errors.New("declared revalidation revoked")
				}
				return nil
			})
			if err == nil || calls != 2 || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 {
				t.Fatal("second revalidate failed without full rollback", calls, err, f.AdmissionDiagnostics())
			}
			current := f.HistoricalRequest()
			if current.IntentSHA256 != req.IntentSHA256 {
				t.Fatal("rolled back request changed original intent")
			}
			forged := req
			forged.IntentSHA256 = strings.Repeat("f", 64)
			if _, err = f.Store.RequestGuestRetirementForwardHistorical(ctx, forged, "collaborator:"+uuid.NewString(), barrier, func(context.Context) error { return nil }); err == nil {
				t.Fatal("stale full CAS accepted")
			}
			r, err := f.Store.RequestGuestRetirementForwardHistorical(ctx, req, "collaborator:"+uuid.NewString(), barrier, func(context.Context) error { return nil })
			if err != nil || r.Stage != "requested" || r.Mode != "historical" {
				t.Fatal("actual historical request", err, f.AdmissionDiagnostics())
			}
			f.StartSuccessorDispatch()
			claimed, pre, id, handled, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy)
			if err != nil || !handled || pre != f.Pre.PreregistrationID || id != f.Request.Intent.RequestID || claimed.FencingToken != f.Intent.FencingToken+1 || claimed.Generation != f.Intent.Generation {
				t.Fatal("new child claim fenced exactly once", claimed, err, f.AdmissionDiagnostics())
			}
			f.Intent = claimed
			orig, record, found, err := f.RetirementStore().GuestRetirementForwardOriginal(ctx, f.Policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, id)
			if err != nil || !found || orig.Request.Intent.RequestID != id || record.Mode != "historical" {
				t.Fatal("claim must return old request without Guest command", err)
			}
			forwardTestComplete(t, f, ctx)
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("historical recovery changed retained failed original")
			}
		})
	}
}

func TestGuestRetirementForwardLivePendingHistoricalResumePostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, mode := range []string{"native_pending", "accepted_delete", "confirmed_delete", "unknown_delete"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				f := NewGuestRetirementForwardRecoveryFixture(t, provider, 3, 4)
				ctx := forwardTestContext(t)
				parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
				if err != nil {
					t.Fatal(err, f.AdmissionDiagnostics())
				}
				read, err := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.FinishStore().RecordGuestRetirementForwardRead(ctx, f.NativeOffReturn(read, "stopping")); !errors.Is(err, ErrGuestRetirementForwardNativePending) {
					t.Fatal(err)
				}
				var oldDestroy model.CapacityMutationReceipt
				if mode != "native_pending" {
					oldDestroy = forwardTestSettledDestroy(t, f, ctx, mode != "unknown_delete")
				}
				var confirmedGrantWire []byte
				if mode == "confirmed_delete" {
					finish := f.FinishStore()
					read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", oldDestroy.Grant.GrantID)
					if err != nil {
						t.Fatal(err)
					}
					proof, err := finish.RecordGuestRetirementForwardRead(ctx, f.NativeAbsenceReturn(read, oldDestroy))
					if err != nil {
						t.Fatal("parent genuine absence", err)
					}
					if _, err = finish.ConfirmMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, proof); err != nil {
						t.Fatal("parent genuine confirmation", err)
					}
					oldDestroy, _, err = finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
					if err != nil || oldDestroy.Grant.State != "confirmed" {
						t.Fatal("parent confirmed readback", err)
					}
					if err = f.DB.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, oldDestroy.Grant.GrantID).Scan(&confirmedGrantWire); err != nil {
						t.Fatal(err)
					}
				}
				f.FinishFailedRun("finish-original-retirement")
				barrier := f.WaitHistoricalBarrier()
				before := f.PreservedOriginals()
				req := f.HistoricalRequest()
				child, err := f.Store.RequestGuestRetirementForwardHistorical(ctx, req, "collaborator:"+uuid.NewString(), barrier, func(context.Context) error { return nil })
				if mode == "unknown_delete" {
					if err == nil || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 2 {
						t.Fatal("unknown issued destroy was resumed/reissued", err)
					}
					if !reflect.DeepEqual(before, f.PreservedOriginals()) {
						t.Fatal("unknown parent custody changed")
					}
					return
				}
				if err != nil || child.ID == parent.ID || child.ParentAdmissionID != parent.ID || child.ParentAdmissionSHA256 == "" || child.RootAdmissionID != parent.ID {
					t.Fatal("pending live parent was reset or replayed", child, err)
				}
				f.StartSuccessorDispatch()
				claimed, _, _, handled, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy)
				if err != nil || !handled {
					t.Fatal(err)
				}
				f.Intent = claimed
				forwardTestComplete(t, f, ctx)
				rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
				if err != nil || len(rows) != 5 || rows[0].ID != parent.ID || rows[0].Stage != "admitted" {
					t.Fatal("immutable pending parent was overwritten", rows, err)
				}
				if mode == "accepted_delete" || mode == "confirmed_delete" {
					var n int
					if err := f.DB.QueryRow(`SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1 AND destroy_grant_id=$2`, f.Request.Intent.RequestID, oldDestroy.Grant.GrantID).Scan(&n); err != nil || n != 1 {
						t.Fatal("child did not preserve the one parent DELETE", err)
					}
				}
				if mode == "confirmed_delete" {
					var after []byte
					if err := f.DB.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, oldDestroy.Grant.GrantID).Scan(&after); err != nil || string(after) != string(confirmedGrantWire) {
						t.Fatal("read-only child rewrote parent confirmed grant/proof", err)
					}
				}
				if !reflect.DeepEqual(before, f.PreservedOriginals()) {
					t.Fatal("resume changed original failed frame")
				}
			})
		}
	}
}

func TestGuestRetirementForwardClosedGuardsPostgres(t *testing.T) {
	t.Run("authority_clock", func(t *testing.T) {
		issued := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
		started := issued.Add(time.Millisecond)
		original := issued.Add(4*time.Second + 789*time.Nanosecond)
		pgDeadline := original.Truncate(time.Microsecond).Add(time.Microsecond)
		for _, tc := range []struct {
			name                        string
			started, deadline, observed time.Time
			withinPG, want              bool
		}{
			{"canonical_clipped", started, pgDeadline, original.Add(-time.Nanosecond), true, true},
			{"observed_equal_native", started, pgDeadline, original, true, false},
			{"observed_after_native", started, pgDeadline, original.Add(time.Nanosecond), true, false},
			{"outside_signed_pg", started, pgDeadline, original.Add(-time.Nanosecond), false, false},
			{"budget_over_five", started, started.Add(5*time.Second + time.Nanosecond), original.Add(-time.Nanosecond), true, false},
			{"started_before_issued", issued.Add(-time.Microsecond), pgDeadline, original.Add(-time.Nanosecond), true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := guestForwardAuthorityReadClockValid(tc.started, tc.deadline, tc.withinPG, tc.observed, issued, original); got != tc.want {
					t.Fatal("canonical PG and strict native clock boundary changed", got, tc.want)
				}
			})
		}
	})
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := NewGuestRetirementForwardRecoveryFixture(t, provider, 2, 3)
			ctx := forwardTestContext(t)
			before := f.PreservedOriginals()
			forged := f.Journal[2]
			forged.Signature = strings.Repeat("a", 88)
			if err := f.Store.RecordGuestObservationV2(ctx, f.Request.Intent.RequestID, forged); err == nil {
				t.Fatal("forged retained prefix entered normal ingress")
			}
			for _, kind := range []string{"no_source", "wrong_source", "wrong_generation", "wrong_fence", "wrong_owner", "wrong_request"} {
				t.Run(kind, func(t *testing.T) {
					s := f.RetirementStore()
					g, n, owner, id := f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID
					switch kind {
					case "no_source":
						s = f.Store
					case "wrong_source":
						s = f.Store.WithOriginalGuestRetirement(f.step("retire-original-guest"), strings.Repeat("a", 40))
					case "wrong_generation":
						g++
					case "wrong_fence":
						n++
					case "wrong_owner":
						owner = uuid.NewString()
					case "wrong_request":
						id = uuid.NewString()
					}
					if _, err := s.AdmitGuestRetirementForwardLive(ctx, f.Policy, g, n, owner, id); err == nil {
						t.Fatal("foreign live authority accepted", kind)
					}
					if forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 {
						t.Fatal("refused live call left authority")
					}
				})
			}
			r, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
			if err != nil {
				t.Fatal(err, f.AdmissionDiagnostics())
			}
			for _, kind := range []string{"wrong_tuple", "wrong_binding", "wrong_source", "renewed_deadline", "call_failed", "context_failed", "missing_plan", "late_return"} {
				t.Run(kind, func(t *testing.T) {
					read, err := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
					if err != nil {
						t.Fatal(err)
					}
					ret := f.NativeOffReturn(read, "")
					switch kind {
					case "wrong_tuple":
						ret.Read.Tuple.ResourceID = "foreign"
					case "wrong_binding":
						ret.Read.MutationBindingSHA256 = strings.Repeat("a", 64)
					case "wrong_source":
						ret.Read.AdapterSourceCommit = strings.Repeat("a", 40)
					case "renewed_deadline":
						ret.Read.OriginalDeadlineCore = ret.Read.OriginalDeadlineCore.Add(time.Second)
					case "call_failed":
						ret.CallFailed = true
					case "context_failed":
						ret.OriginalContextFailed = true
					case "missing_plan":
						ret.Plan = nil
					case "late_return":
						ret.OriginalReturnedAtCore = read.OriginalDeadlineCore
					}
					if _, err = f.FinishStore().RecordGuestRetirementForwardRead(ctx, ret); err == nil {
						t.Fatal("forged/uncertain native read accepted", kind)
					}
				})
			}
			rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
			if err != nil || len(rows) != 1 || rows[0].ID != r.ID || rows[0].Stage != "admitted" {
				t.Fatal("uncertain reads manufactured OFF authority", err)
			}
			if forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 0 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("closed guard changed native/original authority")
			}

			// Reconstruct the callback's private scope only from the actual owning
			// DELETE. Forged inputs below are copies in memory; the issued grant,
			// current marker and append-only admission/reads are never rewritten.
			pending := forwardTestSettledDestroy(t, f, ctx, false)
			grant := pending.Grant
			var grantWire []byte
			if err = f.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&grantWire); err != nil {
				t.Fatal(err)
			}
			var original capacityMutationRecord
			if err = json.Unmarshal(grantWire, &original); err != nil {
				t.Fatal(err)
			}
			ledger, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
			if err != nil {
				t.Fatal(err)
			}
			readCount := forwardTestRowCount(t, f, "capacity_guest_retirement_forward_reads")
			checkUnchanged := func(t *testing.T) {
				t.Helper()
				var after []byte
				if err := f.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&after); err != nil || string(after) != string(grantWire) {
					t.Fatal("refused callback changed the issued grant", err)
				}
				rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
				if err != nil || !reflect.DeepEqual(rows, ledger) || forwardTestRowCount(t, f, "capacity_guest_retirement_forward_reads") != readCount || forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 1 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
					t.Fatal("refused callback changed owning ledger or originals", err)
				}
			}
			for _, kind := range []string{"owning_record", "wrong_grant", "wrong_target", "wrong_slot", "wrong_generation", "wrong_fence", "wrong_owner", "wrong_binding"} {
				t.Run("callback_scope/"+kind, func(t *testing.T) {
					record := original
					switch kind {
					case "wrong_grant":
						record.Grant.GrantID = uuid.NewString()
					case "wrong_target":
						record.Grant.ExpectedResourceID = "foreign"
					case "wrong_slot":
						record.Grant.Slot = 1
					case "wrong_generation":
						record.Generation++
					case "wrong_fence":
						record.FencingToken++
					case "wrong_owner":
						record.LeaseOwner = uuid.NewString()
					case "wrong_binding":
						record.Binding.ScopeChecksum = strings.Repeat("a", 64)
					}
					func() {
						tx, err := f.DB.BeginTx(ctx, nil)
						if err != nil {
							t.Fatal(err)
						}
						defer tx.Rollback()
						if err = lockMutationScope(ctx, tx, f.Policy.Metadata.Namespace, f.Spec); err != nil {
							t.Fatal(err)
						}
						if err = lockRetirementForwardBindingsTx(ctx, tx, append([]model.CapacityMutationBinding{original.Binding}, f.Spec.MutationBindings...)); err != nil {
							t.Fatal(err)
						}
						private, err := retirementForwardCallbackContextTx(ctx, tx, record, f.Policy.Metadata.Namespace, f.Spec)
						if kind == "owning_record" {
							if err != nil {
								t.Fatal("exact owning callback scope refused", err)
							}
							if err = guardRetirementForwardSlotTx(private, tx, original.Binding, grant.Slot); err != nil {
								t.Fatal("server-owned callback scope did not authorize its exact slot", err)
							}
						} else if err == nil {
							t.Fatal("foreign callback acquired private scope", kind)
						}
					}()
					checkUnchanged(t)
				})
			}
			for _, kind := range []string{"wrong_principal", "wrong_grant", "wrong_target", "wrong_slot", "wrong_request"} {
				t.Run("callback_redeem/"+kind, func(t *testing.T) {
					r := mutationRedeem(grant, uuid.NewString())
					principal := original.Binding.AdapterPrincipalID
					switch kind {
					case "wrong_principal":
						principal = "foreign"
					case "wrong_grant":
						r.GrantID = uuid.NewString()
					case "wrong_target":
						r.ExpectedResourceID = "foreign"
					case "wrong_slot":
						r.Slot = 1
					case "wrong_request":
						r.RequestSHA256 = strings.Repeat("a", 64)
					}
					callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
					permit, err := callback.RedeemMutation(ctx, principal, r)
					if err == nil || permit.Mode == "write_once" {
						t.Fatal("foreign DB-only callback acquired native permission", kind, err)
					}
					if kind != "wrong_grant" && !errors.Is(err, ErrCapacityMutationAuthorization) {
						t.Fatal("owning callback did not reach the unchanged authorization guard", kind, err)
					}
					checkUnchanged(t)
				})
			}
		})
	}
}

func TestGuestRetirementForwardMissingPrefixPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := NewGuestRetirementForwardRecoveryFixture(t, provider, 2, 2)
			ctx := forwardTestContext(t)
			before := f.PreservedOriginals()
			if _, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
				t.Fatal("incomplete genuine prefix granted forward authority")
			}
			if forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("missing prefix changed originals")
			}
		})
	}
}

func TestGuestRetirementForwardReadonlyFreshCustodyPostgres(t *testing.T) {
	f := NewGuestRetirementForwardRecoveryFixture(t, "aws", 2, 3)
	ctx := forwardTestContext(t)
	before := f.PreservedOriginals()
	if _, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err != nil {
		t.Fatal(err, f.AdmissionDiagnostics())
	}
	receipt := forwardTestSettledDestroy(t, f, ctx, true)
	originalReceipt, _ := json.Marshal(receipt)
	finish := f.FinishStore()
	for _, fault := range []string{"absent_pair", "source_only", "wrapper_only", "wrong_source", "wrong_purpose", "failed_without_wrapper"} {
		t.Run(fault, func(t *testing.T) {
			read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
			if err != nil {
				t.Fatal(err)
			}
			ret := f.NativeAbsenceReturn(read, receipt)
			switch fault {
			case "absent_pair":
				ret.ObserverSourceCommit = ""
				ret.OriginalObserverReturn = nil
			case "source_only":
				ret.OriginalObserverReturn = nil
			case "wrapper_only":
				ret.ObserverSourceCommit = ""
			case "wrong_source":
				ret.ObserverSourceCommit = strings.Repeat("e", 40)
			case "wrong_purpose":
				var v GuestRetirementReadonlyReturn
				_ = json.Unmarshal(ret.OriginalObserverReturn, &v)
				v.Schema = GuestRetirementReadonlyRequestSchema
				ret.OriginalObserverReturn, _ = json.Marshal(v)
			case "failed_without_wrapper":
				ret.ObserverSourceCommit = ""
				ret.OriginalObserverReturn = nil
				ret.Observation = nil
				ret.Status = ""
				ret.CallFailed = true
			}
			if _, err = finish.RecordGuestRetirementForwardRead(ctx, ret); err == nil || errors.Is(err, ErrGuestRetirementForwardNativePending) {
				t.Fatal("invalid read qualified absence or continuation", err)
			}
			var raw []byte
			if f.DB.QueryRow(`SELECT original_wire FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, read.ReadID).Scan(&raw) != nil {
				t.Fatal("actual refusal erased")
			}
			want, _ := json.Marshal(ret)
			if !reflect.DeepEqual(raw, want) {
				t.Fatal("failure custody rewritten")
			}
		})
	}
	read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := finish.RecordGuestRetirementForwardRead(ctx, f.NativeAbsenceReturn(read, receipt))
	if err != nil || !proof.ResourceAbsent {
		t.Fatal("complete matched fresh wrapper refused", err)
	}
	current, found, err := finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
	currentRaw, _ := json.Marshal(current)
	if err != nil || !found || !reflect.DeepEqual(originalReceipt, currentRaw) || forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 1 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
		t.Fatal("read changed old grant/request/original authority")
	}
}

func TestGuestRetirementForwardOrdinaryReadonlyCustodyPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := NewGuestRetirementOrdinaryRecoveryFixture(t, provider)
			before := f.PreservedOriginals()
			receipt := f.SettledOrdinaryDestroy()
			finish := f.FinishStore()
			originalReceipt, _ := json.Marshal(receipt)
			faults := []string{"failed_without_wrapper"}
			if provider == "aws" {
				faults = append(faults, "absent_pair", "source_only", "wrapper_only", "wrong_source", "wrong_purpose", "oversized_pair")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {
					ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					read, err := finish.PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID)
					if err != nil {
						t.Fatal("real ordinary challenge", err)
					}
					ret := f.OrdinaryAbsenceReturn(read, receipt)
					switch fault {
					case "failed_without_wrapper":
						ret.ObserverSourceCommit, ret.OriginalObserverReturn, ret.Observation, ret.Status, ret.CallFailed = "", nil, nil, "", true
					case "absent_pair":
						ret.ObserverSourceCommit, ret.OriginalObserverReturn = "", nil
					case "source_only":
						ret.OriginalObserverReturn = nil
					case "wrapper_only":
						ret.ObserverSourceCommit = ""
					case "wrong_source":
						ret.ObserverSourceCommit = strings.Repeat("e", 40)
					case "wrong_purpose":
						var v GuestRetirementReadonlyReturn
						_ = json.Unmarshal(ret.OriginalObserverReturn, &v)
						v.Schema = GuestRetirementReadonlyRequestSchema
						ret.OriginalObserverReturn, _ = json.Marshal(v)
					case "oversized_pair":
						ret.OriginalObserverReturn = []byte(strings.Repeat(" ", 1<<20))
					}
					proof, recordErr := finish.RecordGuestNativeAbsenceV2(ctx, ret)
					if recordErr == nil || !reflect.DeepEqual(proof, model.CapacityMutationProof{}) {
						t.Fatal("invalid ordinary read returned authority with refusal", fault, recordErr, proof)
					}
					var raw []byte
					err = f.DB.QueryRow(`SELECT original_wire FROM public.capacity_vm_retirement_native_readbacks WHERE destroy_grant_id=$1 AND original_observation_record->'challenge'->>'read_id'=$2`, receipt.Grant.GrantID, read.ReadID).Scan(&raw)
					if fault == "oversized_pair" {
						if !errors.Is(err, sql.ErrNoRows) {
							t.Fatal("existing1MiB cap widened", err)
						}
						return
					}
					ret.Observation = nil // Existing failed-record storage omits unqualified observation.
					want, _ := json.Marshal(ret)
					if err != nil || !reflect.DeepEqual(raw, want) {
						t.Fatal("ordinary failure custody/clocks/pair changed", err)
					}
				})
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			read, err := finish.PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			ret := f.OrdinaryAbsenceReturn(read, receipt)
			if provider == "aws" {
				// Declared SDK result for an explicit empty exact-ID response. The
				// actual raw-reader/SDK path is separately tested by the adapter.
				ret.Observation.AWSRetirementLifecycle.EC2State = "not_found"
				var v GuestRetirementReadonlyReturn
				_ = json.Unmarshal(ret.OriginalObserverReturn, &v)
				v.Observation = *ret.Observation
				ret.OriginalObserverReturn, _ = json.Marshal(v)
			}
			proof, err := finish.RecordGuestNativeAbsenceV2(ctx, ret)
			if err != nil || !proof.ResourceAbsent {
				t.Fatal("matched ordinary absence refused", err)
			}
			current, err := finish.NativeMutationReceipt(ctx, f.Policy, f.Spec.MutationBindings[0], receipt.Grant.GrantID)
			currentRaw, _ := json.Marshal(current)
			if err != nil || !reflect.DeepEqual(originalReceipt, currentRaw) || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 || forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 1 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("ordinary read invented forward admission or rewrote originals", err)
			}
		})
	}
}
