//go:build recoveryfixture && !nativequalification

package repository

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (f *failedServingFixture) setTestIntent(t *testing.T, current model.CapacityIntent) {
	t.Helper()
	f.exec(t, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, f.policy.Metadata.Namespace, string(failedServingWire(t, current)))
}

func (f *failedServingFixture) insertStableEvent(t *testing.T, current model.CapacityIntent) {
	t.Helper()
	f.exec(t, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,$7,'declared-source-stable-survivor')`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, current.Generation, current.FencingToken, current.Phase)
}

func TestFailedServingStableSurvivorBirthAndCurrentEpochPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			for _, phase := range []string{"promoted", "reconciled", "reconciled_partial"} {
				t.Run(phase, func(t *testing.T) {
					f := newFailedServingFixture(t, provider)
					ctx := failedServingContext(t)
					originals := f.preserved(t)
					current := f.intent
					current.Generation += 2
					current.FencingToken += 3
					current.Phase = phase
					f.setTestIntent(t, current)
					f.insertStableEvent(t, current)
					q := failedServingQuarantine(t, f)
					if q.Candidate.Preregistration.Generation >= current.Generation || q.Candidate.Preregistration.Fence >= current.FencingToken || q.HistoricalPromotedCount != 1 || !capacity.ValidDigest(q.CurrentStableEventSHA256) {
						t.Fatal("birth facts conflated with current stable epoch")
					}
					failedServingOff(t, f, q.ID)
					o, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "absence")
					if err != nil {
						t.Fatal(err)
					}
					if _, err = f.store.CompleteFailedServingGuestAbsence(ctx, o, failedServingAbsence(t, o), f.inventory(t, true)); err != nil {
						t.Fatal("legitimate surviving original unusable after another generation", err)
					}
					// Current-event insertion was intentional fixture input. The old
					// birth promotion and every original accepted/useful row stay exact.
					if !reflect.DeepEqual(f.preserved(t), originals) {
						t.Fatal("survivor rewrote birth/useful history")
					}
				})
			}
		})
	}
}

func TestFailedServingEligibilityAndCrossRealmAuthorityPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			baseline := f.intent
			for _, name := range []string{"preparing_unleased", "future_birth_generation", "future_birth_fence", "no_current_stable_event", "current_lease", "floor_degraded", "recovery_only"} {
				t.Run(name, func(t *testing.T) {
					current := baseline
					switch name {
					case "preparing_unleased":
						current.Phase = "preparing"
					case "future_birth_generation":
						current.Generation = f.pre.Generation - 1
					case "future_birth_fence":
						current.FencingToken = f.pre.Fence - 1
					case "no_current_stable_event":
						current.Generation++
						current.FencingToken++
					case "current_lease":
						expires := time.Now().UTC().Add(time.Minute)
						current.LeaseOwner = uuid.NewString()
						current.LeaseExecutorID = uuid.NewString()
						current.LeaseExpiresAt = &expires
					case "floor_degraded":
						current.FloorDegraded = true
					case "recovery_only":
						current.RecoveryOnly = true
					}
					f.setTestIntent(t, current)
					if _, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
						t.Fatal("nonstable/future/current authority admitted", name)
					}
					f.setTestIntent(t, baseline)
				})
			}
			for _, status := range []string{"pending", "running", "failed"} {
				t.Run("live_or_unfinished_workflow_"+status, func(t *testing.T) {
					id := uuid.New()
					f.exec(t, `INSERT INTO public.workflow_runs(id,workflow_id,workflow_namespace,workflow_name,workflow_version,status) VALUES($1,$2,$3,$4,$5,$6)`, id, f.workflow.ID, f.workflow.Metadata.Namespace, f.workflow.Metadata.Name, f.workflow.Version, status)
					if _, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
						t.Fatal("unfinished current workflow admitted")
					}
					f.exec(t, `DELETE FROM public.workflow_runs WHERE id=$1`, id)
				})
			}
			for _, state := range []string{"issued", "redeemed", "settled", "compensating"} {
				t.Run("same_physical_profile_other_realm_"+state, func(t *testing.T) {
					id := uuid.New()
					b := f.p.MutationBindings[0]
					f.exec(t, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,'another-env','another-domain','another-dimension',1,$3,$4,$5,2,$6,'{}'::jsonb,clock_timestamp()-interval '1 hour')`, id, "other-realm-"+uuid.NewString(), b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, state)
					if _, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
						t.Fatal("expired unresolved same-native-profile authority escaped through another realm/slot")
					}
					f.exec(t, `DELETE FROM public.capacity_mutation_grants WHERE id=$1`, id)
				})
			}
			// Any original retirement lineage remains excluded. Expired time is
			// not permission to reinterpret its caller or native effects.
			retirementID := uuid.NewString()
			f.exec(t, `INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7)`, retirementID, f.pre.PreregistrationID, uuid.NewString(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), f.pre.OriginalDeadline, f.pre.ReservedAt)
			if _, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
				t.Fatal("old retirement lineage admitted as a serving-only failure")
			}
			// Original retirement rows are immutable; this is a separate disposable
			// refusal case, so the fixture cannot now be quarantined.
		})
		t.Run(provider+"_live_canary_and_all_slot_guards", func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			step := f.step(t, "refresh-original-membership")
			canaries := f.store.WithOriginalGuestReconcile(f.workflow, step, capacity.CurrentGuestCoreSource(), "refresh", "", f.inventory(t, false), model.CapacityMetricRangeObservation{}).WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
			generation, fence, owner, err := canaries.GuestNotifyMaintenanceEpoch(ctx, f.policy, f.pre.PreregistrationID)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := canaries.IssueGuestNotifyCanaryPublication(ctx, f.policy, generation, fence, owner, f.pre.PreregistrationID, "steady_useful_membership", failedServingKey('c'))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest()); err == nil {
				t.Fatal("LIVE current canary deadline admitted")
			}
			if wait := time.Until(challenge.OriginalDeadline) + 5*time.Millisecond; wait > 0 && wait <= 6*time.Second {
				time.Sleep(wait)
			} else if wait > 6*time.Second {
				t.Fatal("unbounded source challenge")
			}
			failedServingQuarantine(t, f)
			for slot := 1; slot <= 8; slot++ {
				tx, err := f.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				err = lockNativeMutationSlot(ctx, tx, f.p.MutationBindings[0], slot)
				_ = tx.Rollback()
				if err == nil {
					t.Fatal("S1 quarantine escaped through another slot", slot)
				}
			}
		})
	}
}

func TestFailedServingTerminalBeginsNewOrdinaryFloorGenerationPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			originals := f.preserved(t)
			q := failedServingQuarantine(t, f)
			failedServingOff(t, f, q.ID)
			o, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "absence")
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := f.store.CompleteFailedServingGuestAbsence(ctx, o, failedServingAbsence(t, o), f.inventory(t, true))
			if err != nil {
				t.Fatal(err)
			}
			inventory := f.inventory(t, true)
			snapshot, err := capacity.GuestReconcileSnapshot(f.policy, f.p, inventory, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			assessment := model.CapacityAssessment{Snapshot: snapshot}
			ordinary := f.store.WithOriginalGuestReconcile(f.workflow, f.steps[0], capacity.CurrentGuestCoreSource(), "provision", "", inventory, model.CapacityMetricRangeObservation{})
			next, err := ordinary.AssessOriginalGuest(ctx, f.policy, assessment)
			if err != nil || next.Generation != f.intent.Generation+1 || next.Decision.Reason != "protected_floor_recovery" || next.Decision.Units != 1 || next.Phase != "proposed" || next.FailedServingDisposal != nil {
				t.Fatal("terminal was replayed or prevented an independent ordinary floor decision", err)
			}
			next, err = ordinary.Claim(ctx, f.policy, next.Generation, assessment)
			if err != nil || next.FencingToken != f.intent.FencingToken+2 || next.LeaseOwner == "" || next.LeaseExecutorID != f.store.ExecutorID || next.BaselineSnapshot.Units != 0 || next.Phase != "preparing" {
				t.Fatal("new floor generation did not acquire its own ordinary lease", err)
			}
			// Until a new confirmed creation/enrollment/useful pipeline completes,
			// the old life cannot count as replacement membership or promotion.
			adopt := f.inventory(t, false)
			adopt.Members[0].Server.ID = "124"
			if provider == "aws" {
				adopt.Members[0].Server.ID = "i-00000000000000124"
			}
			members := ordinary.WithOriginalGuestReconcile(f.workflow, f.steps[0], capacity.CurrentGuestCoreSource(), "provision", "", adopt, model.CapacityMetricRangeObservation{})
			if _, _, err = members.OriginalGuestReconcileMembers(ctx, f.policy); err == nil {
				t.Fatal("same-name replacement adopted old enrollment")
			}
			failedServingCompleteOrdinaryReplacement(t, f, next)
			rows, err := f.store.ReadFailedServingGuestDisposals(ctx, f.pre.PreregistrationID)
			if err != nil || len(rows) != 3 || rows[2].RecordID != terminal.RecordID || !reflect.DeepEqual(f.preserved(t), originals) {
				t.Fatal("new ordinary decision rewrote serving/disposal originals", err)
			}
			var current model.CapacityIntent
			if json.Unmarshal(f.rawIntent(t), &current) != nil || current.Phase != "promoted" || current.Generation != f.intent.Generation+1 || current.Assessment.Snapshot.Units != 1 || current.FailedServingDisposal != nil || current.LeaseOwner != "" {
				t.Fatal("new useful floor did not belong to a separately completed ordinary life")
			}
			var resource, marker string
			if err = f.db.QueryRow(`SELECT resource_id,COALESCE(slot_record->>'failed_serving_disposal_id','') FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=1`, f.policy.Metadata.Namespace).Scan(&resource, &marker); err != nil || resource == "" || resource == f.reg.Result.Tuple.ResourceID || marker != "" {
				t.Fatal("new confirmed original did not replace terminal marker/tuple", err)
			}
		})
	}
}
