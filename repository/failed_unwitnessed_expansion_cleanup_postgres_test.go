//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Declared recovery fixtures exercise the real M94 PostgreSQL guards and Store
// boundaries. They are not Native/provider execution or production evidence.
func failedCleanupTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func failedCleanupTestIntent(t *testing.T, db *sql.DB, policy model.Manifest, spec model.CapacityPolicySpec) []byte {
	t.Helper()
	var wire []byte
	if err := db.QueryRow(`SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, spec.Environment, spec.Domain, spec.Dimension).Scan(&wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

type failedCleanupTestParent struct {
	grant, sdk []byte
	state      string
	childNull  bool
}

func failedCleanupTestOriginal(t *testing.T, db *sql.DB, grantID string) failedCleanupTestParent {
	t.Helper()
	var out failedCleanupTestParent
	if err := db.QueryRow(`SELECT grant_record::text,(grant_record#>'{settlement,original_provider_create_return}')::text,state,failed_unwitnessed_expansion_cleanup_id IS NULL FROM public.capacity_mutation_grants WHERE id=$1`, grantID).Scan(&out.grant, &out.sdk, &out.state, &out.childNull); err != nil {
		t.Fatal(err)
	}
	if out.state != "settled" || !out.childNull || len(out.sdk) == 0 {
		t.Fatal("fixture lost the original settled SDK parent", out.state, out.childNull)
	}
	return out
}

func failedCleanupTestCounts(t *testing.T, db *sql.DB, a FailedUnwitnessedExpansionCleanup, admissions, events, children int) {
	t.Helper()
	var actualAdmissions, actualEvents, actualChildren int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE grant_id=$1),(SELECT count(*) FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$2),(SELECT count(*) FROM public.capacity_mutation_grants WHERE id=$3)`, a.GrantID, a.ID, a.ChildGrantID).Scan(&actualAdmissions, &actualEvents, &actualChildren); err != nil {
		t.Fatal(err)
	}
	if actualAdmissions != admissions || actualEvents != events || actualChildren != children {
		t.Fatalf("admission/events/actual child grant = %d/%d/%d, want %d/%d/%d", actualAdmissions, actualEvents, actualChildren, admissions, events, children)
	}
}

func failedCleanupTestLedger(t *testing.T, db *sql.DB, a FailedUnwitnessedExpansionCleanup) [][]byte {
	t.Helper()
	rows, err := db.Query(`SELECT original_wire,admission_sha256 FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=$1 UNION ALL SELECT original_wire,event_sha256 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$1 ORDER BY 2`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		var stored string
		if err = rows.Scan(&raw, &stored); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != stored {
			t.Fatal("actual original wire disagrees with its stored SHA")
		}
		out = append(out, append([]byte(nil), raw...))
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFailedUnwitnessedExpansionCleanupPostgresAdmissionOnce(t *testing.T) {
	f := NewFailedExpansionCleanupRecoveryFixture(t)
	ctx := failedCleanupTestContext(t)
	original := failedCleanupTestOriginal(t, f.DB, f.GrantID)
	intentWire := failedCleanupTestIntent(t, f.DB, f.Policy, f.Spec)
	a, err := f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal("real failed-ACK admission", err)
	}
	if a.Schema != FailedUnwitnessedExpansionCleanupSchema || a.GrantID != f.GrantID || a.JobID != f.JobID || a.ID == "" || a.ChildGrantID == "" || a.ChildGrantID == a.GrantID || a.SurvivorCount != 1 || a.Slot != 2 {
		t.Fatal("admission did not reserve one distinct child for the failed tail", a)
	}
	if !bytes.Equal(a.OriginalIntentWire, intentWire) {
		t.Fatal("admission did not retain the exact original PostgreSQL intent text")
	}
	if a.OriginalAuxiliaryKnown {
		t.Fatal("unknown original auxiliary inventory was upgraded by admission")
	}
	failedCleanupTestCounts(t, f.DB, a, 1, 1, 0)
	stored, events, err := f.AdmissionSourceStore.ReadFailedUnwitnessedExpansionCleanup(ctx, f.GrantID)
	if err != nil || !reflect.DeepEqual(stored, a) || len(events) != 1 || events[0].Stage != "requested" || events[0].Sequence != 1 || events[0].ChildGrantID != a.ChildGrantID || events[0].LeaseOwner != "" || events[0].RunID != "" {
		t.Fatal("GET did not return the original requested-only admission", stored, events, err)
	}
	ledger := failedCleanupTestLedger(t, f.DB, a)
	if _, err = f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString()); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("replay was not refused with GET-only conflict", err)
	}
	again, replayEvents, err := f.AdmissionSourceStore.ReadFailedUnwitnessedExpansionCleanup(ctx, f.GrantID)
	if err != nil || !reflect.DeepEqual(again, a) || !reflect.DeepEqual(events, replayEvents) || !reflect.DeepEqual(ledger, failedCleanupTestLedger(t, f.DB, a)) {
		t.Fatal("replay changed the original admission or event bytes", err)
	}
	failedCleanupTestCounts(t, f.DB, a, 1, 1, 0)
	if !reflect.DeepEqual(original, failedCleanupTestOriginal(t, f.DB, f.GrantID)) {
		t.Fatal("admission/replay rewrote parent grant or SDK bytes")
	}
}

func TestFailedUnwitnessedExpansionCleanupPostgresImmutableOriginals(t *testing.T) {
	f := NewFailedExpansionCleanupRecoveryFixture(t)
	ctx := failedCleanupTestContext(t)
	original := failedCleanupTestOriginal(t, f.DB, f.GrantID)
	a, err := f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if a.OriginalAuxiliaryKnown {
		t.Fatal("fixture must retain unknown original auxiliary inventory")
	}
	ledger := failedCleanupTestLedger(t, f.DB, a)
	for name, statement := range map[string]string{
		"admission_update": `UPDATE public.capacity_failed_unwitnessed_expansion_cleanups SET recorded_at=recorded_at+interval '1 microsecond' WHERE id=$1`,
		"admission_delete": `DELETE FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=$1`,
		"event_update":     `UPDATE public.capacity_failed_unwitnessed_expansion_cleanup_events SET stage='terminal' WHERE cleanup_id=$1`,
		"event_delete":     `DELETE FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			_, mutationErr := f.DB.ExecContext(ctx, statement, a.ID)
			var pg *pq.Error
			if !errors.As(mutationErr, &pg) || pg.Code != "P0001" || !strings.Contains(pg.Message, "immutable") {
				t.Fatal("expected the actual immutable trigger, not a syntax/FK refusal", mutationErr)
			}
			if !reflect.DeepEqual(ledger, failedCleanupTestLedger(t, f.DB, a)) {
				t.Fatal("refused DML changed sealed wire or SHA")
			}
			failedCleanupTestCounts(t, f.DB, a, 1, 1, 0)
		})
	}
	if !reflect.DeepEqual(original, failedCleanupTestOriginal(t, f.DB, f.GrantID)) {
		t.Fatal("immutable ledger checks changed original parent or unknown auxiliary inventory")
	}
}

func TestFailedUnwitnessedExpansionCleanupPostgresOwnerAndWriteGates(t *testing.T) {
	f := NewFailedExpansionCleanupRecoveryFixture(t)
	ctx := failedCleanupTestContext(t)
	original := failedCleanupTestOriginal(t, f.DB, f.GrantID)
	a, err := f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	plan := f.PlanStore()
	if plan.failedExpansionOwner != nil {
		t.Fatal("fixture installed private cleanup authority before a real claim")
	}
	owned, current, selected, found, err := plan.TryClaimFailedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found || selected.ID != a.ID {
		t.Fatal("real Source plan did not claim the requested admission", found, err)
	}
	if owned.failedExpansionOwner == nil || owned.failedExpansionOwner.id != a.ID {
		t.Fatal("real claim did not install its private cleanup selector")
	}
	if current.Generation != f.Intent.Generation || current.FencingToken != f.Intent.FencingToken+1 || current.LeaseOwner == "" || current.LeaseOwner == f.Intent.LeaseOwner || current.LeaseExecutorID != plan.ExecutorID || current.LeaseExpiresAt == nil || f.Intent.LeaseExpiresAt == nil || !current.LeaseExpiresAt.After(*f.Intent.LeaseExpiresAt) {
		t.Fatal("claim did not establish a distinct real ownership epoch", current)
	}
	decision := f.Intent.Decision
	decision.Reason = FailedUnwitnessedExpansionCleanupMode
	if !reflect.DeepEqual(current.BaselineSnapshot, f.Intent.BaselineSnapshot) || !reflect.DeepEqual(current.Assessment, f.Intent.Assessment) || !reflect.DeepEqual(current.Decision, decision) || current.Decision.Units != 2 {
		t.Fatal("cleanup changed the original N1 assessment or N2 decision")
	}
	_, events, err := f.AdmissionSourceStore.ReadFailedUnwitnessedExpansionCleanup(ctx, f.GrantID)
	if err != nil || len(events) != 2 || events[1].Stage != "claimed" || events[1].RunID != plan.OriginalRunID.String() || events[1].LeaseOwner != current.LeaseOwner || events[1].FencingToken != current.FencingToken || events[1].LeaseExpiresAt == nil || !events[1].LeaseExpiresAt.Equal(*current.LeaseExpiresAt) {
		t.Fatal("real claim event does not bind the current run/fence/lease", events, err)
	}
	claimedWire := failedCleanupTestIntent(t, f.DB, f.Policy, f.Spec)
	for name, tuple := range map[string]struct {
		generation, fence int64
		owner             string
	}{
		"foreign_owner":  {current.Generation, current.FencingToken, uuid.NewString()},
		"old_generation": {current.Generation - 1, current.FencingToken, current.LeaseOwner},
		"old_fence":      {current.Generation, current.FencingToken - 1, current.LeaseOwner},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok, bindErr := owned.BindFailedExpansionCleanup(ctx, f.Policy, tuple.generation, tuple.fence, tuple.owner); !ok || !errors.Is(bindErr, ErrCapacityConflict) {
				t.Fatal("foreign tuple bound cleanup authority", ok, bindErr)
			}
		})
	}
	retirement := f.RetirementStore()
	bound, same, ok, err := retirement.BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !ok || same.ID != a.ID {
		t.Fatal("exact current claim could not bind", ok, err)
	}
	if _, err = bound.IssueFailedExpansionDestroy(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("destroy was not refused at the missing inventory/fresh-floor boundary", err)
	}
	if err = bound.MarkFailedExpansionPossibleSend(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("possible-send was not refused without an issued child", err)
	}
	finish := f.FinishStore()
	finish, same, ok, err = finish.BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !ok || same.ID != a.ID {
		t.Fatal("current finish Source could not bind the real claim", ok, err)
	}
	if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("completion was not refused without SDK receipt/fresh strict absence", err)
	}
	if _, receiptFound, receiptErr := finish.FailedExpansionDestroyReceipt(ctx, f.Policy); receiptErr != nil || receiptFound {
		t.Fatal("current no-child claim invented a destroy receipt", receiptFound, receiptErr)
	}
	if _, _, _, _, err = plan.TryClaimFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityLease) {
		t.Fatal("repeat claim was not refused while original current owner is live", err)
	}
	if !bytes.Equal(claimedWire, failedCleanupTestIntent(t, f.DB, f.Policy, f.Spec)) {
		t.Fatal("refused writes/reclaim renewed or changed the current lease")
	}
	failedCleanupTestCounts(t, f.DB, a, 1, 2, 0)
	if !reflect.DeepEqual(original, failedCleanupTestOriginal(t, f.DB, f.GrantID)) {
		t.Fatal("gated cleanup writes changed the original settled create/SDK bytes")
	}
}
