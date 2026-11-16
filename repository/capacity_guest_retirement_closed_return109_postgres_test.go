//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// Reuses the existing Hetzner child and its already-owned fixture. The fixture
// mutex remains owned until that child cleanup; no second constructor runs.
func normalFinishClosedReturn109Prepare(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, returned GuestNativePoweroffReturnV2) []byte {
	t.Helper()
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if err := goose.UpToContext(ctx, f.DB, migrations, 108); err != nil {
		t.Fatal("closed-return actual predecessor108", err)
	}
	before := installedReadinessCatalog(t, f.DB)
	// Read the real original pair without modifying any stored bytes to
	// manufacture the new custody branch.
	tx, err := f.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	x, err := f.PlanStore().retirementForwardSnapshotForNormalFinishTx(ctx, tx, f.Request.Intent.RequestID, true)
	if err != nil {
		tx.Rollback()
		t.Fatal("real content-refused snapshot", err)
	}
	prepared, _, _, recordedAt, err := normalFinishClosedOffFailureTx(ctx, tx, x)
	if err != nil || !reflect.DeepEqual(prepared, returned.Challenge) {
		tx.Rollback()
		t.Fatal("explicit false completed return must be closed custody", err)
	}
	var preparedAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT recorded_at FROM public.capacity_guest_original_native_poweroff_reads WHERE id=$1`, prepared.ReadID).Scan(&preparedAt); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	normalFinishClosedReturn109Refusals(t, x, prepared, returned, *f.NativeOffReturn(GuestRetirementForwardRead{}, "").Plan, preparedAt, recordedAt)
	if handled, err := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, f.Policy); handled || err == nil || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 {
		t.Fatal("unchanged schema108 must refuse the new custody shape atomically", handled, err)
	}
	normalFinishNoDelete(t, f)
	if err = goose.UpToContext(ctx, f.DB, migrations, 109); err != nil {
		t.Fatal("actual closed-return migration109", err)
	}
	after := installedReadinessCatalog(t, f.DB)
	normalFinish109Catalog(t, before, after)
	if logs := os.Getenv("RETIREMENT_FORWARD_LOGS"); logs != "" {
		for name, raw := range map[string][]byte{"M109-PG-BEFORE108-CATALOG.original.json": before, "M109-PG-AFTER109-CATALOG.original.json": after} {
			file, err := os.OpenFile(filepath.Join(logs, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal("exclusive whole109 catalog original", err)
			}
			if n, err := file.Write(raw); err != nil || n != len(raw) {
				file.Close()
				t.Fatal("whole109 catalog original", n, err)
			}
			if err := file.Sync(); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = goose.DownContext(ctx, f.DB, migrations); err != nil || !bytes.Equal(before, installedReadinessCatalog(t, f.DB)) {
		t.Fatal("unused109 Down must restore the complete108 catalog/history", err)
	}
	if err = goose.UpToContext(ctx, f.DB, migrations, 109); err != nil {
		t.Fatal("actual109 after unused Down", err)
	}
	after = installedReadinessCatalog(t, f.DB)
	foreign := f.Policy
	foreign.Metadata.Namespace = "foreign-normal-finish"
	if handled, _ := f.PlanStore().TryRequestGuestRetirementNormalFinishRecovery(ctx, foreign); handled || forwardTestRowCount(t, f, "capacity_guest_retirement_forwards") != 0 {
		t.Fatal("foreign namespace created closed-return custody")
	}
	return after
}

func normalFinishClosedReturn109Claimed(t *testing.T, f *GuestRetirementForwardRecoveryFixture, ctx context.Context, after []byte) {
	t.Helper()
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if err := goose.DownContext(ctx, f.DB, migrations); err == nil {
		t.Fatal("used explicit-false custody permitted downgrade")
	}
	if version, err := goose.GetDBVersion(f.DB); err != nil || version != 109 || !bytes.Equal(after, installedReadinessCatalog(t, f.DB)) {
		t.Fatal("refused used Down changed schema109", version, err)
	}
	if _, err := f.FinishStore().AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID); err == nil {
		t.Fatal("old content-refused return became native-OFF proof")
	}
	normalFinishNoDelete(t, f)
}

func normalFinishClosedReturn109Refusals(t *testing.T, x retirementForwardSnapshot, prepared GuestNativePoweroffReadV2, returned GuestNativePoweroffReturnV2, plan model.CapacityVMFleetPlan, preparedAt, returnedAt time.Time) {
	t.Helper()
	accept := func(p GuestNativePoweroffReadV2, r GuestNativePoweroffReturnV2, pa, ra time.Time) bool {
		var decoded GuestNativePoweroffReturnV2
		return capacity.DecodeGuestLifecycle(failedServingWire(t, r), &decoded) == nil && normalFinishClosedOffFailureContent(x, p, decoded, pa, ra)
	}
	if !accept(prepared, returned, preparedAt, returnedAt) {
		t.Fatal("real explicit-false content refusal is not closed custody")
	}
	for _, status := range []string{"", "observed"} {
		old := returned
		old.CallFailed, old.Status = true, status
		if !accept(prepared, old, preparedAt, returnedAt) {
			t.Fatal("historical transport-failed return no longer closes custody", status)
		}
	}
	for _, fault := range []string{"empty_status", "invalid_status", "context_failed", "plan_present", "schema", "read_schema", "read_id", "intent", "intent_sha", "caller_sha", "binding_sha", "source", "tuple", "challenge", "zero_issued", "over_5s", "start_before_issue", "return_before_start", "deadline_boundary", "after_record", "record_before_prepare", "record_after_now"} {
		p, r, pa, ra := prepared, returned, preparedAt, returnedAt
		switch fault {
		case "empty_status":
			r.Status = ""
		case "invalid_status":
			r.Status = "unknown"
		case "context_failed":
			r.OriginalContextFailed = true
		case "plan_present":
			r.Plan = &plan
		case "schema":
			r.Schema = "foreign_return"
		case "read_schema":
			p.Schema = "foreign_read"
		case "read_id":
			p.ReadID = ""
		case "intent":
			p.IntentID = uuid.NewString()
		case "intent_sha":
			p.IntentSHA256 = strings.Repeat("f", 64)
		case "caller_sha":
			p.OriginalCallerSHA256 = strings.Repeat("f", 64)
		case "binding_sha":
			p.MutationBindingSHA256 = strings.Repeat("f", 64)
		case "source":
			p.AdapterSourceCommit = strings.Repeat("f", 40)
		case "tuple":
			p.Tuple.ResourceID = "foreign-native-resource"
		case "challenge":
			r.Challenge.ReadID = uuid.NewString()
		case "zero_issued":
			p.IssuedAtCore = time.Time{}
		case "over_5s":
			p.OriginalDeadlineCore = p.IssuedAtCore.Add(5*time.Second + time.Nanosecond)
		case "start_before_issue":
			r.StartedAtCore = p.IssuedAtCore.Add(-time.Nanosecond)
		case "return_before_start":
			r.OriginalReturnedAtCore = r.StartedAtCore.Add(-time.Nanosecond)
		case "deadline_boundary":
			r.OriginalReturnedAtCore = p.OriginalDeadlineCore
		case "after_record":
			r.OriginalReturnedAtCore = ra.Add(time.Nanosecond)
		case "record_before_prepare":
			pa = ra.Add(time.Nanosecond)
		case "record_after_now":
			ra = x.now.Add(time.Nanosecond)
		}
		if fault != "challenge" {
			r.Challenge = p
		}
		var decoded GuestNativePoweroffReturnV2
		if capacity.DecodeGuestLifecycle(failedServingWire(t, r), &decoded) != nil {
			t.Fatal("typed negative did not reach the custody content guard", fault)
		}
		if normalFinishClosedOffFailureContent(x, p, decoded, pa, ra) {
			t.Fatal("unsafe completed-return custody accepted", fault)
		}
	}
	for _, fault := range []string{"missing_call_failed", "null_call_failed", "string_call_failed", "missing_context", "null_context", "string_context", "missing_status", "null_status", "bool_status", "null_plan"} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(failedServingWire(t, returned), &fields) != nil {
			t.Fatal("actual closed return JSON")
		}
		switch fault {
		case "missing_call_failed":
			delete(fields, "call_failed")
		case "null_call_failed":
			fields["call_failed"] = json.RawMessage(`null`)
		case "string_call_failed":
			fields["call_failed"] = json.RawMessage(`"false"`)
		case "missing_context":
			delete(fields, "original_context_failed")
		case "null_context":
			fields["original_context_failed"] = json.RawMessage(`null`)
		case "string_context":
			fields["original_context_failed"] = json.RawMessage(`"false"`)
		case "missing_status":
			delete(fields, "status")
		case "null_status":
			fields["status"] = json.RawMessage(`null`)
		case "bool_status":
			fields["status"] = json.RawMessage(`false`)
		case "null_plan":
			fields["plan"] = json.RawMessage(`null`)
		}
		var decoded GuestNativePoweroffReturnV2
		if capacity.DecodeGuestLifecycle(failedServingWire(t, fields), &decoded) == nil {
			t.Fatal("missing, null or wrongly typed original fact accepted", fault)
		}
	}
}

func normalFinish109Catalog(t *testing.T, before, after []byte) {
	t.Helper()
	var old, next map[string]json.RawMessage
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || len(old) != len(next) {
		t.Fatal("actual whole108/109 catalog required")
	}
	for key, value := range old {
		if key != "functions" && key != "history_wire" && !bytes.Equal(value, next[key]) {
			t.Fatal("109 changed unrelated catalog", key)
		}
	}
	var a, b []map[string]json.RawMessage
	if json.Unmarshal(old["functions"], &a) != nil || json.Unmarshal(next["functions"], &b) != nil || len(a) != len(b) {
		t.Fatal("109 added or removed a function")
	}
	changed := 0
	for n, row := range a {
		if !reflect.DeepEqual(row, b[n]) {
			if string(row["name"]) != `"retirement_forward_normal_finish_recovery_valid"` || !bytes.Equal(row["name"], b[n]["name"]) || !bytes.Equal(row["arguments"], b[n]["arguments"]) {
				t.Fatal("109 changed unrelated function", string(row["name"]))
			}
			changed++
		}
	}
	var oldWire, newWire string
	var oldHistory, newHistory []map[string]any
	if json.Unmarshal(old["history_wire"], &oldWire) != nil || json.Unmarshal(next["history_wire"], &newWire) != nil || json.Unmarshal([]byte(oldWire), &oldHistory) != nil || json.Unmarshal([]byte(newWire), &newHistory) != nil || len(newHistory) != len(oldHistory)+1 || !reflect.DeepEqual(oldHistory, newHistory[:len(oldHistory)]) || oldHistory[len(oldHistory)-1]["version_id"] != float64(108) || newHistory[len(oldHistory)]["version_id"] != float64(109) || newHistory[len(oldHistory)]["is_applied"] != true || changed != 1 {
		t.Fatal("109 must replace one predicate and append only history109", changed)
	}
}
