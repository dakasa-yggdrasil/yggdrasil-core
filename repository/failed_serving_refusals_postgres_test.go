//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func failedServingClone[T any](t *testing.T, value T) T {
	t.Helper()
	var out T
	if json.Unmarshal(failedServingWire(t, value), &out) != nil {
		t.Fatal("declared test operand clone")
	}
	return out
}

func failedServingCount(t *testing.T, f *failedServingFixture) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_guest_failed_serving_disposals`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFailedServingQuarantineRequiresCompleteExactFleetPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			before, originals := f.rawIntent(t), f.preserved(t)
			for _, name := range []string{"incomplete", "empty", "two_members", "duplicate_partition", "missing_partition", "wrong_slot", "foreign_tuple", "recreated_tuple", "wrong_profile", "wrong_instance", "foreign_scope", "stale", "future", "fencing_claim", "business_claim", "atomic_claim"} {
				t.Run(name, func(t *testing.T) {
					owner, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest())
					if err != nil {
						t.Fatal(err)
					}
					inv := f.inventory(t, false)
					switch name {
					case "incomplete":
						inv.Complete = false
					case "empty":
						inv = f.inventory(t, true)
					case "two_members":
						inv.Members = append(inv.Members, failedServingClone(t, inv.Members[0]))
						inv.Members[1].Slot = 2
						inv.MissingSlots = []int{3, 4, 5, 6, 7, 8}
					case "duplicate_partition":
						inv.MissingSlots = []int{2, 2, 4, 5, 6, 7, 8}
					case "missing_partition":
						inv.MissingSlots = []int{2, 3, 4, 5, 6, 7}
					case "wrong_slot":
						inv.Members[0].Slot = 2
						inv.MissingSlots = []int{1, 3, 4, 5, 6, 7, 8}
					case "foreign_tuple":
						inv.Members[0].Server.ID = "999"
					case "recreated_tuple":
						inv.Members[0].Server.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
					case "wrong_profile":
						inv.ProfileName = "another-profile"
					case "wrong_instance":
						inv.IntegrationInstanceID = uuid.NewString()
					case "foreign_scope":
						inv.ScopeChecksum = strings.Repeat("f", 64)
					case "stale":
						inv.ObservationStartedAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
						inv.ObservedAt = inv.ObservationStartedAt
					case "future":
						inv.ObservedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
					case "fencing_claim":
						inv.ProviderFencingEvidence = true
					case "business_claim":
						inv.BusinessReadyEvidence = true
					case "atomic_claim":
						inv.AtomicProviderSnapshot = true
					}
					if _, err = f.store.CompleteFailedServingGuestQuarantine(ctx, owner, inv); err == nil {
						t.Fatal("foreign/incomplete inventory admitted")
					}
					if failedServingCount(t, f) != 0 || !reflect.DeepEqual(f.rawIntent(t), before) || !reflect.DeepEqual(f.preserved(t), originals) {
						t.Fatal("refusal changed original facts")
					}
				})
			}
			// Two independently begun observations cannot both commit one frame.
			one, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest())
			if err != nil {
				t.Fatal(err)
			}
			two, err := f.store.BeginFailedServingGuestQuarantine(ctx, f.request(t), failedServingIssuerForTest())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.CompleteFailedServingGuestQuarantine(ctx, one, f.inventory(t, false)); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.CompleteFailedServingGuestQuarantine(ctx, two, f.inventory(t, false)); err == nil || failedServingCount(t, f) != 1 {
				t.Fatal("stale same-frame owner created another admission")
			}
		})
	}
}

func TestFailedServingObservationOwnerAndNativeOffPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			q := failedServingQuarantine(t, f)
			before, originals := f.rawIntent(t), f.preserved(t)
			if _, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "absence"); err == nil {
				t.Fatal("absence began before source-owned OFF")
			}
			for _, mode := range []string{"delete", "poweroff", "OFF", "", "quarantine"} {
				if _, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), mode); err == nil {
					t.Fatal("caller chose a mutating/unknown operation")
				}
			}
			for _, name := range []string{"nil_owner", "different_context", "different_database", "cancelled", "no_deadline", "running", "foreign_tuple", "new_birth", "wrong_operation", "request_hash", "labels", "unverified", "business_claim", "fencing_claim", "compensation"} {
				t.Run(name, func(t *testing.T) {
					callCtx := ctx
					store := f.store
					owner, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "off")
					if err != nil {
						t.Fatal(err)
					}
					plan := f.offPlan(t)
					switch name {
					case "nil_owner":
						owner = nil
					case "different_context":
						callCtx = context.WithValue(ctx, struct{ failedServingTest bool }{true}, true)
					case "different_database":
						store.DB = &sql.DB{}
					case "cancelled":
						var stop context.CancelFunc
						callCtx, stop = context.WithCancel(ctx)
						stop()
					case "no_deadline":
						callCtx = context.Background()
					case "running":
						plan.Server.Status = "running"
					case "foreign_tuple":
						plan.Server.ID = "999"
					case "new_birth":
						plan.Server.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
					case "wrong_operation":
						plan.DesiredSpec.Capability = f.p.MutationBindings[0].DestroyCapability
					case "request_hash":
						plan.RequestSHA256 = strings.Repeat("f", 64)
					case "labels":
						plan.Server.Labels["yggdrasil.io/intent"] = uuid.NewString()
					case "unverified":
						plan.Server.PhysicalSpecVerified = false
					case "business_claim":
						plan.BusinessReadyEvidence = true
					case "fencing_claim":
						plan.ProviderFencingEvidence = true
					case "compensation":
						plan.CompensationOf = uuid.NewString()
					}
					if _, err = store.CompleteFailedServingGuestNativeOff(callCtx, owner, plan); err == nil {
						t.Fatal("invalid owner/content became native OFF")
					}
					if failedServingCount(t, f) != 1 || !reflect.DeepEqual(f.rawIntent(t), before) || !reflect.DeepEqual(f.preserved(t), originals) {
						t.Fatal("OFF refusal changed the quarantined life")
					}
				})
			}
			// A failed read is not a perpetual read lease; another explicit fresh
			// owner may append a real OFF while all prior rows remain immutable.
			first := failedServingOff(t, f, q.ID)
			if _, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "off"); err == nil {
				t.Fatal("successful OFF was replayed instead of exact GET recovery")
			}
			rows, err := f.store.ReadFailedServingGuestDisposals(ctx, f.pre.PreregistrationID)
			if err != nil || len(rows) != 2 || rows[1].RecordID != first.RecordID || failedServingCount(t, f) != 2 || !reflect.DeepEqual(f.rawIntent(t), before) {
				t.Fatal("successful OFF readback lost its immutable original", err)
			}
		})
	}
}

func TestFailedServingAbsenceRequiresAllAuxAndFleetZeroPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := newFailedServingFixture(t, provider)
			ctx := failedServingContext(t)
			q := failedServingQuarantine(t, f)
			failedServingOff(t, f, q.ID)
			before, originals := f.rawIntent(t), f.preserved(t)
			for _, name := range []string{"target_present", "target_incomplete", "aux_inventory_incomplete", "aux_present", "aux_omitted", "raw_body_hash", "missing_native_read", "foreign_original", "future_core_return", "incomplete_fleet", "still_member", "missing_partition", "duplicate_partition", "wrong_profile", "business_claim"} {
				t.Run(name, func(t *testing.T) {
					owner, err := f.store.BeginFailedServingGuestObservation(ctx, f.pre.PreregistrationID, q.ID, failedServingIssuerForTest(), "absence")
					if err != nil {
						t.Fatal(err)
					}
					o, inv := failedServingAbsence(t, owner), f.inventory(t, true)
					switch name {
					case "target_present":
						o.ResourceState = "present"
					case "target_incomplete":
						o.ResourceAbsenceComplete = false
					case "aux_inventory_incomplete":
						o.AuxiliaryInventoryComplete = false
					case "aux_present":
						o.AuxiliaryResources[0].Absent = false
					case "aux_omitted":
						o.AuxiliaryResources = nil
					case "raw_body_hash":
						o.NativeReads[0].ResponseSHA256 = strings.Repeat("f", 64)
					case "missing_native_read":
						o.NativeReads = nil
					case "foreign_original":
						o.RequestSHA256 = strings.Repeat("f", 64)
					case "future_core_return":
						o.ObservationStartedAt = time.Now().UTC().Add(time.Hour)
						o.ObservedAt = o.ObservationStartedAt
					case "incomplete_fleet":
						inv.Complete = false
					case "still_member":
						inv = f.inventory(t, false)
					case "missing_partition":
						inv.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7}
					case "duplicate_partition":
						inv.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7, 7}
					case "wrong_profile":
						inv.ProfileName = "another-profile"
					case "business_claim":
						inv.BusinessReadyEvidence = true
					}
					if _, err = f.store.CompleteFailedServingGuestAbsence(ctx, owner, o, inv); err == nil {
						t.Fatal("target-only/foreign/incomplete evidence tombstoned useful history")
					}
					if failedServingCount(t, f) != 2 || !reflect.DeepEqual(f.rawIntent(t), before) || !reflect.DeepEqual(f.preserved(t), originals) {
						t.Fatal("terminal refusal changed historical facts")
					}
				})
			}
		})
	}
}
