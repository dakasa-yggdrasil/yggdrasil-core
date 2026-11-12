//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

func normalFinishMigrate97(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) {
	t.Helper()
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if err := goose.UpToContext(ctx, f.DB, migrations, 96); err != nil {
		t.Fatal("actual predecessor schema96", err)
	}
	var before []byte
	if strings.HasSuffix(t.Name(), "/aws") {
		before = normalFinishCatalog(t, f)
	}
	if err := goose.UpToContext(ctx, f.DB, migrations, 97); err != nil {
		t.Fatal("isolated existing fixture migrations through97", err)
	}
	if version, err := goose.GetDBVersion(f.DB); err != nil || version != 97 {
		t.Fatal("exact isolated schema97 required", version, err)
	}
	if before != nil {
		normalFinishCatalog97Artifact(t, f, before)
	}
}

func normalFinishCatalog(t *testing.T, f *GuestRetirementForwardRecoveryFixture) []byte {
	t.Helper()
	var raw []byte
	if err := f.DB.QueryRow(`SELECT jsonb_build_object(
 'server_version_num',current_setting('server_version_num')::int,
 'functions',(SELECT jsonb_object_agg(p.proname,pg_get_functiondef(p.oid) ORDER BY p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('guard_retirement_forward','retirement_forward_continuation_valid','retirement_forward_continuation_quiet','retirement_forward_normal_finish_recovery_valid')),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('name',c.conname,'validated',c.convalidated,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY c.conname) FROM pg_constraint c WHERE c.conrelid='public.capacity_guest_retirement_forwards'::regclass AND c.contype='c'))::text`).Scan(&raw); err != nil {
		t.Fatal("actual PostgreSQL named predicates and complete function deparse", err)
	}
	return raw
}

func normalFinishCatalog97Artifact(t *testing.T, f *GuestRetirementForwardRecoveryFixture, before []byte) {
	t.Helper()
	after := normalFinishCatalog(t, f)
	type constraint struct {
		Name       string `json:"name"`
		Validated  bool   `json:"validated"`
		Definition string `json:"definition"`
	}
	type catalog struct {
		Version     int               `json:"server_version_num"`
		Functions   map[string]string `json:"functions"`
		Constraints []constraint      `json:"constraints"`
	}
	var old, next catalog
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || old.Version != next.Version || (next.Version/10000 != 16 && next.Version/10000 != 17) {
		t.Fatal("real PG16/17 before/after catalog required")
	}
	for _, name := range []string{"retirement_forward_continuation_valid", "retirement_forward_continuation_quiet"} {
		if old.Functions[name] == "" || old.Functions[name] != next.Functions[name] {
			t.Fatal("schema97 rewrote historical schema96 continuation semantics", name)
		}
	}
	if old.Functions["retirement_forward_normal_finish_recovery_valid"] != "" || next.Functions["retirement_forward_normal_finish_recovery_valid"] == "" || old.Functions["guard_retirement_forward"] == next.Functions["guard_retirement_forward"] {
		t.Fatal("additive normal-finish validator and explicit guard change required")
	}
	byName := map[string]constraint{}
	for _, c := range next.Constraints {
		byName[c.Name] = c
	}
	for _, c := range old.Constraints {
		if c.Name == "retirement_forward_mode93" {
			if _, exists := byName[c.Name]; exists {
				t.Fatal("old mode93 predicate was retained alongside replacement")
			}
			continue
		}
		if got, exists := byName[c.Name]; !exists || got != c || !got.Validated {
			t.Fatal("historical checked constraint drift", c.Name)
		}
	}
	newChecks := 0
	for _, c := range next.Constraints {
		if c.Name == "retirement_forward_mode97" || c.Name == "retirement_forward_normal_finish97" {
			if !c.Validated || c.Definition == "" {
				t.Fatal("unvalidated new schema97 predicate", c.Name)
			}
			newChecks++
		}
	}
	if newChecks != 2 {
		t.Fatal("exact new mode97 and normal_finish97 constraints required", newChecks)
	}
	logs := os.Getenv("RETIREMENT_FORWARD_LOGS")
	if logs == "" {
		return // Artifact emission uses the existing owning workflow directory.
	}
	put := func(name string, raw []byte) map[string]any {
		path := filepath.Join(logs, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("exclusive real PG catalog original", err)
		}
		if _, err = file.Write(raw); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"path": path, "sha256": capacity.BusinessCreationSHA256(raw), "bytes": len(raw)}
	}
	beforeRef := put("M97-PG-BEFORE96-CATALOG.original.json", before)
	afterRef := put("M97-PG-AFTER97-CATALOG.original.json", after)
	migrationPath := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations", "00097_guest_retirement_normal_finish_recovery.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"schema": "normal_finish_recovery_schema97_pg_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "postgres_major": next.Version / 10000, "fixture_only": true, "native_authority": false, "before96_ref": beforeRef, "after97_ref": afterRef, "migration97_sha256": capacity.BusinessCreationSHA256(migration), "old_continuation_functions_unchanged": true, "old_continuation_constraints_unchanged": true, "old_mode93_absent": true, "new_mode97_and_normal_finish97_validated": true}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	put("M97-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", append(raw, '\n'))
	t.Logf("actual schema97 PG catalog originals retained: before=%s after=%s", beforeRef["sha256"], afterRef["sha256"])
}

func normalFinishRefused(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, why string) {
	t.Helper()
	requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy)
	if requested || err != nil && !errors.Is(err, ErrCapacityConflict) && !errors.Is(err, ErrCapacityLease) {
		t.Fatal(why, requested, err)
	}
}

func normalFinishNativeOriginalSHA(t *testing.T, f *GuestRetirementForwardRecoveryFixture) string {
	t.Helper()
	var raw []byte
	if err := f.DB.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY recorded_at,id),'[]'::jsonb)::text FROM public.capacity_guest_original_native_poweroff_reads x WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return capacity.BusinessCreationSHA256(raw)
}

func normalFinishNoDelete(t *testing.T, f *GuestRetirementForwardRecoveryFixture) {
	t.Helper()
	if n := forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings"); n != 0 {
		t.Fatal("unqualified normal-finish recovery issued DELETE", n)
	}
}

func normalFinishProofRefusals(t *testing.T, f *GuestRetirementForwardRecoveryFixture, row GuestRetirementForward) {
	t.Helper()
	original := failedServingWire(t, row)
	valid := func(raw []byte) bool {
		var accepted bool
		if err := f.DB.QueryRow(`SELECT public.retirement_forward_normal_finish_recovery_valid($1::jsonb,$2::uuid)`, string(raw), f.Request.Intent.RequestID).Scan(&accepted); err != nil {
			t.Fatal("actual schema97 proof validator", err)
		}
		return accepted
	}
	if !valid(original) {
		t.Fatal("actual schema97 rejected its retained immutable proof")
	}
	for _, fault := range []string{"missing_proof", "extra_proof_key", "failed_run_id", "failed_run_sha256", "missing_ACK", "wrong_ACK", "native_off_read_id", "native_off_prepared_sha256", "native_off_return_sha256", "live_original_context", "live_original_lease"} {
		var candidate map[string]any
		if err := json.Unmarshal(original, &candidate); err != nil {
			t.Fatal(err)
		}
		proof := candidate["normal_finish_recovery"].(map[string]any)
		switch fault {
		case "missing_proof":
			delete(candidate, "normal_finish_recovery")
		case "extra_proof_key":
			proof["replacement_native_off"] = true
		case "missing_ACK":
			proof["failed_finish_ack_at"] = nil
		case "wrong_ACK":
			proof["failed_finish_ack_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		case "live_original_context":
			proof["original_context_deadline"] = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		case "live_original_lease":
			proof["original_lease_expires_at"] = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		default:
			if strings.HasSuffix(fault, "_sha256") {
				proof[fault] = strings.Repeat("f", 64)
			} else {
				proof[fault] = uuid.NewString()
			}
		}
		if valid(failedServingWire(t, candidate)) {
			t.Fatal("schema97 accepted missing, forged or live failure custody", fault)
		}
	}
	normalFinishNoDelete(t, f)
}

func normalFinishRequestAndClaim(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context) GuestRetirementForward {
	t.Helper()
	old := f.Intent
	requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy)
	if err != nil || !requested {
		t.Fatal("automatic same-process normal-finish request", requested, err, f.AdmissionDiagnostics())
	}
	rows, err := f.Store.ReadGuestRetirementForwards(ctx, f.Pre.PreregistrationID)
	if err != nil || len(rows) != 1 || rows[0].Mode != GuestRetirementForwardNormalFinishRecoveryMode || rows[0].Stage != "requested" || rows[0].NormalFinishRecovery == nil || rows[0].DestroyGrantID != "" {
		t.Fatal("distinct normal-success proof and zero old DELETE", rows, err)
	}
	r := rows[0]
	raw, err := json.Marshal(r.NormalFinishRecovery)
	var proof map[string]any
	if err != nil || json.Unmarshal(raw, &proof) != nil || len(proof) != 10 || proof["schema"] != GuestRetirementForwardNormalFinishRecoverySchema || proof["failed_run_id"] != f.originalRunID.String() || proof["requesting_run_id"] != f.RunID.String() || proof["native_off_read_id"] == "" {
		t.Fatal("exact closed original failure proof", string(raw), err)
	}
	if again, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || again || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 1 {
		t.Fatal("automatic request replay created a second owner", again, err)
	}
	normalFinishProofRefusals(t, f, r)
	claimed, pre, request, handled, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy)
	if err != nil || !handled || pre != f.Pre.PreregistrationID || request != f.Request.Intent.RequestID || claimed.Generation != old.Generation || claimed.FencingToken != old.FencingToken+1 || claimed.LeaseOwner == old.LeaseOwner || claimed.LeaseExpiresAt == nil || !claimed.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("fresh owning fence without changing original generation/target", claimed, err)
	}
	f.Intent = claimed
	normalFinishNoDelete(t, f)
	return r
}

// Real disposable PG16/17 lifecycle, with declared Guest/provider operands.
// Neither a process restart nor a manual operator admission is used. Original
// caller success is retained as success; failed finish is retained as failure.
func TestGuestRetirementForwardNormalFinishRecoveryPostgres(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := NewGuestRetirementNormalFinishRecoveryFixture(t, provider)
			ctx, stop := context.WithTimeout(context.Background(), 150*time.Second)
			defer stop()
			normalFinishMigrate97(t, f, ctx)
			var preflightSHA string
			var finalizedWire []byte
			if err := f.DB.QueryRow(`SELECT r.intent_sha256,(convert_from(n.original_wire,'UTF8')::json->'final_request'->'intent')::text FROM public.capacity_vm_retirement_intents r JOIN public.capacity_vm_retirement_original_returns n ON n.intent_id=r.id AND n.sequence=1 AND n.kind='production_clock_nonce_v2' WHERE r.id=$1`, f.Request.Intent.RequestID).Scan(&preflightSHA, &finalizedWire); err != nil || preflightSHA == capacity.GuestRetirementSHA(f.Request.Intent) || !reflect.DeepEqual(finalizedWire, failedServingWire(t, f.Request.Intent)) || capacity.BusinessCreationSHA256(finalizedWire) != capacity.GuestRetirementSHA(f.Request.Intent) {
				t.Fatal("real PG finalized nonce token must preserve exact canonical Go intent, separately from immutable preflight SHA", err)
			}
			failedOFF := f.FailedOrdinaryNativeOff()
			// The unchanged partial/failed-caller mode must still reject normal200.
			if _, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
				t.Fatal("normal200 was relabelled as the old partial-caller failure")
			}
			f.FinishNormalRetirementFailedRun()
			before, nativeBefore := f.PreservedOriginals(), normalFinishNativeOriginalSHA(t, f)
			f.WaitHistoricalBarrier()
			f.StartSuccessorDispatch()
			requested := normalFinishRequestAndClaim(t, f, ctx)
			var proof map[string]any
			proofRaw, _ := json.Marshal(requested.NormalFinishRecovery)
			if json.Unmarshal(proofRaw, &proof) != nil || proof["native_off_read_id"] != failedOFF.Challenge.ReadID {
				t.Fatal("new proof lost the actual failed original OFF pair")
			}
			finish := f.FinishStore()
			// A new failed OFF and a foreign native tuple remain retained
			// diagnostics. Neither may authorize the first DELETE.
			read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
			if err != nil {
				t.Fatal(err)
			}
			bad := f.NativeOffReturn(read, "")
			bad.CallFailed, bad.Plan = true, nil
			if _, err = finish.RecordGuestRetirementForwardRead(ctx, bad); err == nil {
				t.Fatal("failed fresh OFF became qualified")
			}
			if _, err = finish.AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
				t.Fatal("failed fresh OFF advanced drain")
			}
			normalFinishNoDelete(t, f)
			read, err = finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
			if err != nil {
				t.Fatal(err)
			}
			foreign := f.NativeOffReturn(read, "")
			foreign.Plan.Server.ID = "wrong-native-resource"
			if _, err = finish.RecordGuestRetirementForwardRead(ctx, foreign); err == nil {
				t.Fatal("foreign fresh OFF tuple became qualified")
			}
			normalFinishNoDelete(t, f)
			forwardTestComplete(t, f, ctx)
			if !reflect.DeepEqual(before, f.PreservedOriginals()) || nativeBefore != normalFinishNativeOriginalSHA(t, f) {
				t.Fatal("recovery rewrote original success, failed ACK, timers or failed OFF")
			}
			var grants, confirmed, settledAttempts int
			if err = f.DB.QueryRow(`SELECT count(*),count(*) FILTER(WHERE g.state='confirmed'),count(*) FILTER(WHERE g.grant_record->>'attempt_id'<>'' AND g.grant_record->'settlement' IS NOT NULL) FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1`, f.Request.Intent.RequestID).Scan(&grants, &confirmed, &settledAttempts); err != nil || grants != 1 || confirmed != 1 || settledAttempts != 1 {
				t.Fatal("one grant / one redeemed attempt / one settlement only", grants, confirmed, settledAttempts, err)
			}
		})
	}

	t.Run("missing_ACK_then_live_lease", func(t *testing.T) {
		f := NewGuestRetirementNormalFinishRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 150*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		f.FailedOrdinaryNativeOff()
		committed, err := finishCapacityDispatchFirstCommitOnce(ctx, f.DB, f.job, f.NormalFinishFailedWorkflowResult(), time.Now().UTC(), nil, nil)
		if err != nil || committed.current.FinalizationAckAt != nil {
			t.Fatal("real failed original return without ACK", err)
		}
		preReadMissingACKCoalesces(t, f, ctx, f.job)
		if requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || requested {
			t.Fatal("missing original ACK authorized recovery", requested, err)
		}
		normalFinishNoDelete(t, f)
		if err = acknowledgeCapacityDispatchFinalization(ctx, f.DB, committed.current); err != nil {
			t.Fatal("actual original failed ACK", err)
		}
		f.StartSuccessorDispatch()
		if requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || requested || f.Intent.LeaseExpiresAt == nil || !f.Intent.LeaseExpiresAt.After(time.Now()) {
			t.Fatal("new real planner adopted a still-live original lease/context", requested, err)
		}
		if err = FinishCapacityDispatch(ctx, f.DB, f.job, preReadWorkflowResult(f, f.Intent, "", "failed", "plan-original-guest"), time.Now().UTC(), nil); err != nil {
			t.Fatal("truthful unclaimed planner finalization", err)
		}
		var contextDeadline time.Time
		if err = f.DB.QueryRow(`SELECT original_context_deadline FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, f.Request.Intent.RequestID).Scan(&contextDeadline); err != nil || !contextDeadline.After(*f.Intent.LeaseExpiresAt) {
			t.Fatal("declared independent original context must outlive initial lease", contextDeadline, err)
		}
		if wait := time.Until(*f.Intent.LeaseExpiresAt) + 5*time.Millisecond; wait > 0 {
			time.Sleep(wait)
		}
		if !time.Now().Before(contextDeadline) {
			t.Fatal("fixture missed the real lease-expired / original-context-live boundary")
		}
		f.StartSuccessorDispatch()
		normalFinishRefused(t, f, ctx, "expired lease replaced an original context that is still live")
		if err = FinishCapacityDispatch(ctx, f.DB, f.job, preReadWorkflowResult(f, f.Intent, "", "failed", "plan-original-guest"), time.Now().UTC(), nil); err != nil {
			t.Fatal("truthful original-context-live planner refusal ACK", err)
		}
		before := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		normalFinishRequestAndClaim(t, f, ctx)
		if !reflect.DeepEqual(before, f.PreservedOriginals()) {
			t.Fatal("waiting for natural expiry altered old history")
		}
	})

	t.Run("normal_origin_settled_then_pre_read_continuation", func(t *testing.T) {
		f := NewGuestRetirementNormalFinishRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 210*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		f.FailedOrdinaryNativeOff()
		f.FinishNormalRetirementFailedRun()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		root := normalFinishRequestAndClaim(t, f, ctx)
		receipt := forwardTestSettledDestroy(t, f, ctx, true)
		read, err := f.FinishStore().PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "absence", receipt.Grant.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.FinishStore().RecordGuestRetirementForwardRead(ctx, continuationTestPending(t, f, read, receipt)); !errors.Is(err, ErrGuestRetirementForwardNativePending) {
			t.Fatal("normal-origin owning DELETE needs genuine retained Pending", err)
		}
		f.FinishFailedRun("finish-original-retirement")
		originals := f.PreservedOriginals()
		var settlement, binding []byte
		if err = f.DB.QueryRow(`SELECT (g.grant_record->'settlement')::text,b.original_wire FROM public.capacity_mutation_grants g JOIN public.capacity_vm_retirement_delete_bindings b ON b.destroy_grant_id=g.id WHERE b.intent_id=$1`, f.Request.Intent.RequestID).Scan(&settlement, &binding); err != nil {
			t.Fatal(err)
		}
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		if requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || requested {
			t.Fatal("no-DELETE prober blocked or reopened owning settled continuation", requested, err)
		}
		first := continuationTestRequest(t, f, ctx)
		if first.RootAdmissionID != root.ID || first.DestroyGrantID != receipt.Grant.GrantID || !reflect.DeepEqual(first.NormalFinishRecovery, root.NormalFinishRecovery) || first.Continuation.Schema != GuestRetirementForwardContinuationSchema {
			t.Fatal("schema93 child lost successful-caller origin or same settled DELETE", first)
		}
		preReadClaim(t, f, ctx, first)
		if rows := preReadOwnRows(t, f, first.ID); rows != 0 {
			t.Fatal("declared inventory-before-Prepare failure unexpectedly read native", rows)
		}
		f.FinishFailedRun("finish-original-retirement")
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		second := continuationTestRequest(t, f, ctx)
		if second.RootAdmissionID != root.ID || second.ParentAdmissionID != first.ID || second.DestroyGrantID != receipt.Grant.GrantID || second.Continuation.Schema != GuestRetirementForwardPreReadContinuationSchema || !reflect.DeepEqual(second.NormalFinishRecovery, root.NormalFinishRecovery) || preReadOwnRows(t, f, first.ID) != 0 {
			t.Fatal("schema96 pre-read child relabelled normal success or old DELETE", second)
		}
		preReadClaim(t, f, ctx, second)
		forwardTestComplete(t, f, ctx)
		var actualSettlement, actualBinding []byte
		if err = f.DB.QueryRow(`SELECT (g.grant_record->'settlement')::text,b.original_wire FROM public.capacity_mutation_grants g JOIN public.capacity_vm_retirement_delete_bindings b ON b.destroy_grant_id=g.id WHERE b.intent_id=$1`, f.Request.Intent.RequestID).Scan(&actualSettlement, &actualBinding); err != nil || !reflect.DeepEqual(settlement, actualSettlement) || !reflect.DeepEqual(binding, actualBinding) || forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 1 || !reflect.DeepEqual(originals, f.PreservedOriginals()) {
			t.Fatal("continuation changed original success, settled SDK result or one DELETE custody", err)
		}
	})

	t.Run("ambiguous_failed_ACK", func(t *testing.T) {
		f := NewGuestRetirementNormalFinishRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		f.FailedOrdinaryNativeOff()
		f.FinishNormalRetirementFailedRun()
		// Two separately finalized declared workflow operands claim the same
		// original epoch. No retained row is updated and no Guest call is made.
		// Ambiguous ownership must not be resolved by picking the newest ACK.
		preReadStartNextTick(t, f)
		f.FinishNormalRetirementFailedRun()
		before := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		normalFinishRefused(t, f, ctx, "ambiguous exact-epoch failed ACK selected a preferred owner")
		if forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
			t.Fatal("ambiguous failed ACK changed admission or original history")
		}
		normalFinishNoDelete(t, f)
	})

	t.Run("open_original_native_read", func(t *testing.T) {
		f := NewGuestRetirementNormalFinishRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		if _, err := f.FinishStore().PrepareGuestNativePoweroffReadV2(ctx, f.Request.Intent.RequestID); err != nil {
			t.Fatal("real prepared original native read", err)
		}
		f.FinishNormalRetirementFailedRun()
		before := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		normalFinishRefused(t, f, ctx, "unreturned original read became absence or OFF authority")
		if !reflect.DeepEqual(before, f.PreservedOriginals()) || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 {
			t.Fatal("open-read refusal mutated authority")
		}
		normalFinishNoDelete(t, f)
	})

	t.Run("prior_DELETE", func(t *testing.T) {
		f := NewGuestRetirementNormalFinishRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		f.FailedOrdinaryNativeOff()
		receipt := f.SettledOrdinaryDestroy()
		f.FinishNormalRetirementFailedRun()
		before := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		if receipt.Grant.State != "settled" {
			t.Fatal("declared genuine previous DELETE settlement missing")
		}
		normalFinishRefused(t, f, ctx, "already-owned DELETE was reclassified for another first DELETE")
		if forwardTestRowCount(t, f, "capacity_vm_retirement_delete_bindings") != 1 || !reflect.DeepEqual(before, f.PreservedOriginals()) {
			t.Fatal("prior owning DELETE or original history changed")
		}
	})

	t.Run("partial_caller_stays_in_old_lane", func(t *testing.T) {
		f := NewGuestRetirementForwardRecoveryFixture(t, "aws", 2, 4)
		ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		f.FinishFailedRun("retire-original-guest")
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		if requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || requested {
			t.Fatal("partial failed caller became normal-success recovery", requested, err)
		}
		normalFinishNoDelete(t, f)
	})

	t.Run("late_original_caller_stays_in_old_lane", func(t *testing.T) {
		f := NewGuestRetirementLateCallerRecoveryFixture(t, "aws")
		ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		normalFinishMigrate97(t, f, ctx)
		if f.Caller.BodyPersisted || !f.Caller.OriginalContextFailed || !f.Caller.DriverReturnedAt.After(f.Request.Intent.OriginalDeadline) || f.Caller.Status != 200 {
			t.Fatal("late HTTP200 was promoted to a normal original success")
		}
		f.FinishFailedRun("retire-original-guest")
		before := f.PreservedOriginals()
		f.WaitHistoricalBarrier()
		f.StartSuccessorDispatch()
		if requested, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); err != nil || requested {
			t.Fatal("authentic late original caller entered the normal-success lane", requested, err)
		}
		if !reflect.DeepEqual(before, f.PreservedOriginals()) {
			t.Fatal("late caller refusal rewrote its original deadline or result")
		}
		normalFinishNoDelete(t, f)
	})
	retirementForwardClosedFailedRead102Regression(t)
}
