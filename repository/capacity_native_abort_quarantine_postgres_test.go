package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This file is a real PostgreSQL 16/17 CI regression, never an in-memory model.
// The positive fixture issues and redeems the real recovery child, retains its
// original result seed with NULL ACKs, and waits for its original short deadline.
// No command/request/proof/identity/deadline is rewritten to manufacture expiry.
type abortQuarantinePGFixture struct {
	abortRecoveryPGFixture
	child    model.CapacityNativeCommand
	permit   model.CapacityNativeAuthorityPermit
	token    string
	storeQ   CapacityStore
	bindingQ model.CapacityNativeAbortQuarantineBinding
}

func abortQuarantinePGSetup(t *testing.T, beforeExpiry func(*testing.T, *abortQuarantinePGFixture)) abortQuarantinePGFixture {
	t.Helper()
	f := abortRecoveryPGSetup(t, false)
	var version int
	if err := f.db.QueryRow(`SHOW server_version_num`).Scan(&version); err != nil || version < 160000 || version >= 180000 {
		t.Fatalf("PostgreSQL 16 or 17 required, got %d: %v", version, err)
	}
	abortRecoveryPGResume(t, &f)
	// A context deadline is a supported issuance input. It becomes the original,
	// immutable command deadline and the real redemption seed's original_deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	child, token, err := f.store.IssueNativePreRegistrationAbortRecovery(ctx, f.policy, f.intent, f.bindingRecovery, f.observation)
	if err != nil {
		t.Fatal("issue real short-lived recovery child", err)
	}
	permit, err := f.store.RedeemNativePreRegistrationAbort(ctx, child.AdapterPrincipalID, abortRecoveryPGRedeem(f, child, token))
	if err != nil {
		t.Fatal("redeem real recovery child", err)
	}
	if err = f.store.MarkNativeCommandUncertain(ctx, child.CommandID); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = f.db.QueryRow(`SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, child.CommandID).Scan(&raw); err != nil || json.Unmarshal(raw, &child) != nil {
		t.Fatal("retained uncertain child unavailable", err)
	}
	q := abortQuarantinePGFixture{abortRecoveryPGFixture: f, child: child, permit: permit, token: token}
	q.bindingQ = model.CapacityNativeAbortQuarantineBinding{Schema: capacity.NativeAbortQuarantineSchema, Confirmation: "QUARANTINE ONLY EXACT UNCERTAIN CHILD", Native: f.bindingRecovery.Native, ParentCommandID: f.parent.CommandID.String(), CommandID: child.CommandID.String(), ExpectedIntentFencingToken: f.intent.FencingToken}
	workflow := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "quarantine-human", abortQuarantinePGWorkflow(q.bindingQ))
	q.storeQ = f.store
	q.storeQ.WorkflowID = workflow.ID
	q.storeQ.ExecutorID = uuid.NewString()
	// Shorten only the current mutable lease to the already-issued child's actual
	// deadline. Its fencing token, owner, command, proof and result seed stay exact.
	if _, err = f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, child.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if beforeExpiry != nil {
		beforeExpiry(t, &q)
	}
	// This finite wait executes only in the remote PostgreSQL CI job. Observe the
	// database clock rather than assuming the host and server clocks agree.
	waitUntil := time.Now().Add(8 * time.Second)
	for {
		var expired bool
		if err = f.db.QueryRow(`SELECT clock_timestamp()>$1`, child.ExpiresAt).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatal("original issued command deadline did not expire within finite CI bound")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return q
}

func abortQuarantinePGWorkflow(b model.CapacityNativeAbortQuarantineBinding) map[string]any {
	return map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": map[string]any{"rbac": map[string]any{"namespace": "fixed", "name": "quarantine-human-only"}}, "steps": []any{map[string]any{"id": "quarantine-once", "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}, "use": map[string]any{"kind": "yggdrasil", "operation": capacity.QuarantineUncertainNativeBirth}, "with": map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
}

func abortQuarantinePGAbsence(f abortQuarantinePGFixture) model.AdapterCapacityPodUnregisteredTerminalResponse {
	// A fresh server observation is actual name absence, not a deletion attribution
	// or a recycled terminal witness carrying the old UID/protection/receipt.
	return model.AdapterCapacityPodUnregisteredTerminalResponse{Operation: capacity.ObserveNativeUnregisteredTerminal, Status: "observed", Observation: model.NativePreRegistrationAbortObservation{NativeTerminationObservation: model.NativeTerminationObservation{BindingName: f.bindingQ.Native.BindingName, Namespace: f.bindingQ.Native.Namespace, PodName: f.bindingQ.Native.PodName, State: "absent", Reason: "native_name_absent", ObservedAt: time.Now().UTC()}}, Metadata: map[string]any{"atomic_snapshot": false, "useful_capacity_known": false, "physical_capacity_released": false, "sdk_lane_witness": false}}
}

func abortQuarantinePGClassify(t *testing.T, f abortQuarantinePGFixture) model.CapacityNativeUnsettledCounts {
	t.Helper()
	counts, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(f))
	if err != nil || counts != (model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1}) {
		t.Fatalf("exact expired uncertain child must classify as raw=1 quarantine=1 active=0: %+v %v", counts, err)
	}
	return counts
}

func abortQuarantinePGSnapshot(t *testing.T, f abortQuarantinePGFixture) [][]byte {
	t.Helper()
	var out [][]byte
	for _, capture := range []struct {
		query string
		args  []any
	}{
		{`SELECT row_to_json(a) FROM public.capacity_native_command_archive a WHERE id=$1`, []any{f.parent.CommandID}},
		{`SELECT row_to_json(c) FROM public.capacity_native_commands c WHERE id=$1`, []any{f.child.CommandID}},
		{`SELECT json_agg(i ORDER BY id) FROM public.capacity_native_command_identities i WHERE id IN($1,$2)`, []any{f.parent.CommandID, f.child.CommandID}},
		{`SELECT row_to_json(r) FROM public.capacity_native_release_results r WHERE command_id=$1`, []any{f.child.CommandID}},
	} {
		// Capture full original SQL rows, including every private custody field.
		var raw []byte
		if err := f.db.QueryRow(capture.query, capture.args...).Scan(&raw); err != nil {
			t.Fatal("original custody snapshot", err)
		}
		out = append(out, raw)
	}
	return out
}

func abortQuarantinePGCounts(t *testing.T, f abortQuarantinePGFixture, want model.CapacityNativeUnsettledCounts) {
	t.Helper()
	got, err := f.storeQ.NativeUnsettledCounts(context.Background(), f.policy)
	if err != nil || got != want {
		t.Fatalf("unsettled count mismatch: got %+v want %+v: %v", got, want, err)
	}
}

func abortQuarantinePGHeld(t *testing.T, f abortQuarantinePGFixture) {
	t.Helper()
	if _, err := f.storeQ.NativeUnsettledCounts(context.Background(), f.policy); err == nil {
		t.Fatal("corrupt retained quarantine custody was silently excluded instead of HOLD")
	}
	if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), f.policy, f.child.CommandID); err == nil || ok {
		t.Fatal("invalid receipt reported valid administrative quarantine")
	}
}

func TestCapacityNativeAbortQuarantinePreservesOriginalPostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, func(t *testing.T, f *abortQuarantinePGFixture) {
		if _, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(*f)); err == nil {
			t.Fatal("unexpired original command/lease classified")
		}
	})
	before := abortQuarantinePGSnapshot(t, f)
	abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, ActiveUnsettled: 1})
	counts := abortQuarantinePGClassify(t, f)
	after := abortQuarantinePGSnapshot(t, f)
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("original parent/child/identity/result-seed snapshot %d changed", i)
		}
	}
	var hot, archived, ids, seeds, receipts, unresolved int
	if err := f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1 AND state='uncertain'),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$2),(SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$3),(SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1 AND adapter_result IS NULL AND adapter_result_sha256 IS NULL AND adapter_ack_at IS NULL AND caller_ack_at IS NULL),(SELECT count(*) FROM public.capacity_native_abort_quarantines WHERE command_id=$1),(SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$4 AND state IN('issued','redeemed','uncertain'))`, f.child.CommandID, f.parent.CommandID, f.bindingQ.Native.PodUID, f.policy.Metadata.Namespace).Scan(&hot, &archived, &ids, &seeds, &receipts, &unresolved); err != nil || hot != 1 || archived != 1 || ids != 2 || seeds != 1 || receipts != 1 || unresolved != 1 {
		t.Fatalf("append-only quarantine lost raw HOT uncertainty/NULL ACKs: %d %d %d %d %d %d: %v", hot, archived, ids, seeds, receipts, unresolved, err)
	}
	var raw []byte
	var digest string
	if err := f.db.QueryRow(`SELECT quarantine_record,record_sha256 FROM public.capacity_native_abort_quarantines WHERE command_id=$1`, f.child.CommandID).Scan(&raw, &digest); err != nil || digest != nativeCanonicalArchiveSHA(raw) {
		t.Fatal("separate immutable receipt custody missing", err)
	}
	var receipt model.CapacityNativeAbortQuarantine
	if capacity.DecodeNativeCapacity(raw, &receipt) != nil || receipt.Binding != f.bindingQ || receipt.History != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 2, HotCommands: 1, ArchivedCommands: 1}) || receipt.CommandRecordSHA256 == "" || receipt.ParentRecordSHA256 == "" || receipt.ResultSeedSHA256 == "" {
		t.Fatal("receipt omitted exact original binding/history/private custody digests")
	}
	for _, query := range []string{`UPDATE public.capacity_native_abort_quarantines SET record_sha256=repeat('0',64) WHERE command_id=$1`, `DELETE FROM public.capacity_native_abort_quarantines WHERE command_id=$1`} {
		if _, err := f.db.Exec(query, f.child.CommandID); err == nil {
			t.Fatal("administrative receipt was mutable")
		}
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_release_results SET attempt_id='00000000-0000-4000-8000-000000000001' WHERE command_id=$1`,
		`UPDATE public.capacity_native_release_results SET protocol='foreign_protocol' WHERE command_id=$1`,
		`UPDATE public.capacity_native_release_results SET adapter_source_commit=repeat('0',40) WHERE command_id=$1`,
		`UPDATE public.capacity_native_release_results SET return_nonce_sha256=repeat('0',64) WHERE command_id=$1`,
		`UPDATE public.capacity_native_release_results SET original_deadline=original_deadline+interval '1 second' WHERE command_id=$1`,
		`DELETE FROM public.capacity_native_release_results WHERE command_id=$1`,
	} {
		if _, err := f.db.Exec(query, f.child.CommandID); err == nil {
			t.Fatal("private original redemption seed custody was mutable")
		}
	}
	if _, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(f)); err == nil {
		t.Fatal("duplicate administrative receipt accepted")
	}
	abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
	if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), f.policy, f.child.CommandID); err != nil || !ok {
		t.Fatal("valid immutable receipt could not be revalidated", err)
	}
	public, err := json.Marshal(counts)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.token, f.permit.ReturnNonce, f.child.AuthorityTokenSHA256, "authority_token", "return_nonce", "original_result", "record_sha256", "adapter_result"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("private custody entered public count metadata")
		}
	}
}

func TestCapacityNativeAbortQuarantineDuplicatePostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, nil)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(f)); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent duplicate classifications succeeded %d times", successes.Load())
	}
	abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
}

func TestCapacityNativeAbortQuarantineHumanBoundaryPostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, nil)
	for _, mode := range []string{"async", "nonmanual", "retry", "timeout", "extra_step", "extra_step_field", "other_operation", "dynamic_binding", "wrong_operator", "admission_only", "execution_disabled"} {
		t.Run(mode, func(t *testing.T) {
			workflow := abortQuarantinePGWorkflow(f.bindingQ)
			steps := workflow["steps"].([]any)
			step := steps[0].(map[string]any)
			store := f.storeQ
			switch mode {
			case "async":
				workflow["dispatch_mode"] = "async"
			case "nonmanual":
				workflow["trigger"] = map[string]any{"mode": "schedule"}
			case "retry":
				step["retry"] = map[string]any{"max_attempts": 2}
			case "timeout":
				step["timeout_seconds"] = 89
			case "extra_step":
				workflow["steps"] = append(steps, step)
			case "extra_step_field":
				step["when"] = "true"
			case "other_operation":
				step["use"] = map[string]any{"kind": "yggdrasil", "operation": nativeAbortRecoveryOperation}
			case "dynamic_binding":
				step["with"] = map[string]any{"binding": "{{ inputs.binding }}", "confirmation": "{{ inputs.confirmation }}"}
			case "wrong_operator":
				store.ExecutorPowerOperator = uuid.NewString()
			case "admission_only":
				store.AdmissionOnly = true
			case "execution_disabled":
				store.ExecutionEnabled = false
			}
			wf := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "quarantine-negative-"+mode, workflow)
			store.WorkflowID = wf.ID
			if _, err := store.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(f)); err == nil {
				t.Fatal("nonliteral or unauthorized human administrative workflow accepted")
			}
		})
	}
	for _, mode := range []string{"same_name_replacement", "present_unprotected", "protected", "ready", "old_observation", "receipt_digest", "missing_metadata", "extra_metadata"} {
		t.Run(mode, func(t *testing.T) {
			absence := abortQuarantinePGAbsence(f)
			switch mode {
			case "same_name_replacement":
				absence.Observation.PodUID = uuid.NewString()
			case "present_unprotected":
				absence.Observation.State, absence.Observation.Reason = "unprotected", "native_capacity_finalizer_absent"
			case "protected":
				absence.Observation.Protected = true
			case "ready":
				absence.Observation.AdmissionReady = true
			case "old_observation":
				absence.Observation.ObservedAt = time.Now().UTC().Add(-time.Duration(f.p.MaxEvidenceAgeSeconds+1) * time.Second)
			case "receipt_digest":
				absence.Observation.ReceiptSHA256 = strings.Repeat("e", 64)
			case "missing_metadata":
				delete(absence.Metadata, "atomic_snapshot")
			case "extra_metadata":
				absence.Metadata["credential"] = "not-public"
			}
			if _, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, absence); err == nil {
				t.Fatal("nonabsence, stale or nonclosed observation accepted")
			}
		})
	}
	abortQuarantinePGClassify(t, f)
}

func TestCapacityNativeAbortQuarantineReceiptDigestPostgres(t *testing.T) {
	for _, mode := range []string{"wrong_digest", "wrong_history", "foreign_binding", "unknown_receipt_field"} {
		t.Run(mode, func(t *testing.T) {
			f := abortQuarantinePGSetup(t, nil)
			ctx := context.Background()
			tx, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var now time.Time
			if err = tx.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			_, parentSHA, childSHA, seedSHA, err := nativeAbortQuarantineFacts(ctx, tx, f.policy, f.p, f.bindingQ, now, false)
			if err != nil {
				t.Fatal("unmodified real fixture must satisfy full quarantine custody", err)
			}
			observation := abortQuarantinePGAbsence(f)
			observation.Observation.ObservedAt = now
			receipt := model.CapacityNativeAbortQuarantine{Schema: capacity.NativeAbortQuarantineSchema, Binding: f.bindingQ, WorkflowID: f.storeQ.WorkflowID.String(), ExecutorID: f.storeQ.ExecutorID, OperatorID: f.bindingQ.Native.OperatorID, Observation: observation, History: model.CapacityNativeAbortZeroHistory{CommandIdentities: 2, HotCommands: 1, ArchivedCommands: 1}, ParentRecordSHA256: parentSHA, CommandRecordSHA256: childSHA, ResultSeedSHA256: seedSHA, LeaseExpiredAt: f.child.ExpiresAt, QuarantinedAt: now}
			if mode == "wrong_history" {
				receipt.History.Lifetimes = 1
			}
			if mode == "foreign_binding" {
				receipt.Binding.Native.PodUID = uuid.NewString()
			}
			raw, err := nativeAbortCanonical(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown_receipt_field" {
				var object map[string]json.RawMessage
				if err = json.Unmarshal(raw, &object); err != nil {
					t.Fatal(err)
				}
				object["unexpected"] = json.RawMessage(`true`)
				raw, err = nativeAbortCanonical(object)
				if err != nil {
					t.Fatal(err)
				}
			}
			digest := nativeCanonicalArchiveSHA(raw)
			if mode == "wrong_digest" {
				digest = strings.Repeat("0", 64)
			}
			// Insert a corrupt receipt as new forensic input. Never UPDATE a real
			// receipt, disable its trigger, or alter original command/seed facts.
			if _, err = tx.Exec(`INSERT INTO public.capacity_native_abort_quarantines(command_id,subject_uid,namespace,environment,domain,dimension,record_sha256,quarantine_record)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, f.child.CommandID, f.bindingQ.Native.PodUID, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, digest, raw); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			abortQuarantinePGHeld(t, f)
		})
	}
}

func TestCapacityNativeAbortQuarantineCustodyRevalidationPostgres(t *testing.T) {
	for _, mode := range []string{"missing_child", "moved_child_scope", "changed_child_state", "changed_child_request", "unknown_child_field", "duplicate_parent_hot", "foreign_identity", "foreign_hot_lifetime", "foreign_archived_lifetime", "foreign_legacy_checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			f := abortQuarantinePGSetup(t, nil)
			abortQuarantinePGClassify(t, f)
			var query string
			var args []any
			switch mode {
			case "missing_child":
				query, args = `DELETE FROM public.capacity_native_commands WHERE id=$1`, []any{f.child.CommandID}
			case "moved_child_scope":
				query, args = `UPDATE public.capacity_native_commands SET namespace=$2 WHERE id=$1`, []any{f.child.CommandID, "foreign-" + uuid.NewString()}
			case "changed_child_state":
				query, args = `UPDATE public.capacity_native_commands SET state='confirmed',command_record=jsonb_set(command_record,'{state}','"confirmed"') WHERE id=$1`, []any{f.child.CommandID}
			case "changed_child_request":
				query, args = `UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{request,proof,lineage,prior_state}','"issued"') WHERE id=$1`, []any{f.child.CommandID}
			case "unknown_child_field":
				// A typed re-marshal would erase this unknown field. The actual raw
				// retained body must be bound, including all original/extra bytes.
				query, args = `UPDATE public.capacity_native_commands SET command_record=command_record||'{"unexpected_custody_field":"drift"}'::jsonb WHERE id=$1`, []any{f.child.CommandID}
			case "duplicate_parent_hot":
				query, args = `INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record) SELECT i.id,i.namespace,i.environment,i.domain,i.dimension,i.generation,i.operation,i.subject_uid,i.phase,i.sequence,'uncertain',i.authority_token_sha256,a.command_record FROM public.capacity_native_command_identities i JOIN public.capacity_native_command_archive a ON a.id=i.id WHERE i.id=$1`, []any{f.parent.CommandID}
			case "foreign_identity":
				query, args = `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,3,$10,$11)`, []any{uuid.New(), "foreign-" + uuid.NewString(), f.p.Environment, f.p.Domain, f.p.Dimension, f.intent.Generation, f.child.Operation, f.bindingQ.Native.PodUID, f.child.Phase, nativeArchiveSHA([]byte(uuid.NewString())), nativeArchiveSHA([]byte(uuid.NewString()))}
			case "foreign_hot_lifetime":
				// Presence of any global lifetime is itself forbidden. These rows
				// deliberately model corrupted foreign custody, not a valid birth.
				query, args = `INSERT INTO public.capacity_native_lifetimes(namespace,environment,domain,dimension,pod_uid,origin_generation,checkpoint_record)VALUES($1,$2,$3,$4,$5,1,'{}')`, []any{"foreign-" + uuid.NewString(), f.p.Environment, f.p.Domain, f.p.Dimension, f.bindingQ.Native.PodUID}
			case "foreign_archived_lifetime":
				query, args = `INSERT INTO public.capacity_native_lifetime_archive(namespace,environment,domain,dimension,pod_uid,origin_generation,origin_sha256,bundle_sha256,bundle_record)VALUES($1,$2,$3,$4,$5,1,$6,$7,'{}')`, []any{"foreign-" + uuid.NewString(), f.p.Environment, f.p.Domain, f.p.Dimension, f.bindingQ.Native.PodUID, strings.Repeat("a", 64), strings.Repeat("b", 64)}
			case "foreign_legacy_checkpoint":
				query, args = `INSERT INTO public.capacity_native_pod_checkpoints(namespace,environment,domain,dimension,generation,pod_uid,checkpoint_record)VALUES($1,$2,$3,$4,1,$5,'{}')`, []any{"foreign-" + uuid.NewString(), f.p.Environment, f.p.Domain, f.p.Dimension, f.bindingQ.Native.PodUID}
			}
			if _, err := f.db.Exec(query, args...); err != nil {
				t.Fatal("inject independent custody corruption without disabling immutability", err)
			}
			abortQuarantinePGHeld(t, f)
		})
	}
}

func TestCapacityNativeAbortQuarantineResultArrivalPostgres(t *testing.T) {
	t.Run("real_original_adapter_result_before_classification", func(t *testing.T) {
		f := abortQuarantinePGSetup(t, func(t *testing.T, f *abortQuarantinePGFixture) {
			if err := f.store.RecordNativePreRegistrationAbortResult(context.Background(), f.child.AdapterPrincipalID, abortPGResult(f.abortPGFixture, f.child, f.permit)); err != nil {
				t.Fatal("real authenticated original adapter result", err)
			}
		})
		if _, err := f.storeQ.QuarantineNativeUncertainAbort(context.Background(), f.policy, f.bindingQ, abortQuarantinePGAbsence(f)); err == nil {
			t.Fatal("known original adapter result was classified as absent")
		}
		abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, ActiveUnsettled: 1})
	})
	t.Run("late_durable_adapter_result_invalidates_exclusion", func(t *testing.T) {
		f := abortQuarantinePGSetup(t, nil)
		abortQuarantinePGClassify(t, f)
		if err := f.store.RecordNativePreRegistrationAbortResult(context.Background(), f.child.AdapterPrincipalID, abortPGResult(f.abortPGFixture, f.child, f.permit)); err == nil {
			t.Fatal("expired adapter callback accepted")
		}
		// Reproduce a late durable monotonic result/ACK arrival directly in the
		// seed ledger. Do not fabricate child.OriginalResult or a caller return.
		result := abortPGResult(f.abortPGFixture, f.child, f.permit)
		result.ReturnNonce = ""
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.Exec(`UPDATE public.capacity_native_release_results SET adapter_result=$2,adapter_result_sha256=$3,adapter_ack_at=clock_timestamp() WHERE command_id=$1`, f.child.CommandID, raw, nativeCanonicalArchiveSHA(raw)); err != nil {
			t.Fatal(err)
		}
		abortQuarantinePGHeld(t, f)
	})
	t.Run("caller_ack_alone_invalidates_exclusion", func(t *testing.T) {
		f := abortQuarantinePGSetup(t, nil)
		abortQuarantinePGClassify(t, f)
		if _, err := f.db.Exec(`UPDATE public.capacity_native_release_results SET caller_ack_at=clock_timestamp() WHERE command_id=$1`, f.child.CommandID); err != nil {
			t.Fatal(err)
		}
		abortQuarantinePGHeld(t, f)
	})
}

func TestCapacityNativeAbortQuarantineOtherUIDProgressPostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, nil)
	abortQuarantinePGClassify(t, f)
	t.Run("permanent_receipt_survives_source_evidence_age", func(t *testing.T) {
		var raw []byte
		if f.db.QueryRow(`SELECT quarantine_record FROM public.capacity_native_abort_quarantines WHERE command_id=$1`, f.child.CommandID).Scan(&raw) != nil {
			t.Fatal("immutable quarantine receipt unavailable")
		}
		var q model.CapacityNativeAbortQuarantine
		if capacity.DecodeNativeCapacity(raw, &q) != nil {
			t.Fatal("immutable receipt invalid")
		}
		staleAt := q.Observation.Observation.ObservedAt.Add(time.Duration(f.p.MaxEvidenceAgeSeconds+1) * time.Second)
		deadline := time.Now().Add(time.Duration(f.p.MaxEvidenceAgeSeconds+5) * time.Second)
		for {
			var old bool
			if f.db.QueryRow(`SELECT clock_timestamp()>$1`, staleAt).Scan(&old) != nil {
				t.Fatal("database clock unavailable")
			}
			if old {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("finite native-evidence age did not elapse")
			}
			time.Sleep(20 * time.Millisecond)
		}
		// Creation required fresh evidence. Its immutable historical truth does not
		// expire; current child/seed/history custody is still checked on every use.
		abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
	})
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nativeActiveUnsettledTx(ctx, tx, f.policy, f.p, f.bindingQ.Native.PodUID)
	tx.Rollback()
	if err == nil {
		t.Fatal("original quarantined UID used its own active-blocker exclusion")
	}
	// Resume the real ordinary lease after the expired administrative subject.
	intent, err := f.ordinary.ResumeNativeExecution(ctx, f.policy, f.intent.Generation)
	if err != nil {
		t.Fatal("resume ordinary native execution", err)
	}
	boot := nativeLifetimeBoot(f.p)
	cp, err := f.ordinary.RegisterNativeLifetime(ctx, f.policy, intent, boot)
	if err != nil {
		t.Fatal("another UID remained blocked by valid administrative quarantine", err)
	}
	// At this point there is no unrelated active command to mask the UID fence.
	same := nativeLifetimeBoot(f.p)
	same.Observation.PodUID, same.Admission.PodUID = f.bindingQ.Native.PodUID, f.bindingQ.Native.PodUID
	if _, err = f.ordinary.RegisterNativeLifetime(ctx, f.policy, intent, same); err == nil {
		t.Fatal("original quarantined UID registered again in its scope")
	}
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(cp.Challenge, &challenge) != nil {
		t.Fatal("real registration challenge unavailable")
	}
	no := false
	request := model.AdapterEnsureCapacityPodDrainRequest{BindingName: f.p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodResourceVersion: cp.PodResourceVersion, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "protect", DryRun: &no}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command, token, err := f.ordinary.IssueNativeCommand(ctx, f.policy, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw)
	if err != nil || command.CommandID == f.child.CommandID {
		t.Fatal("another UID could not issue its own real native command", err)
	}
	abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 2, ActiveUnsettled: 1, Quarantined: 1})
	if _, err = f.ordinary.RegisterNativeLifetime(ctx, f.policy, intent, nativeLifetimeBoot(f.p)); err == nil {
		t.Fatal("active work for another UID was hidden by quarantine count")
	}
	nativeLifetimeRedeem(t, f.ordinary, f.p, command, token)
	current := boot.Observation
	current.PodResourceVersion = "11"
	current.ObservedAt = time.Now().UTC()
	if err = f.ordinary.ConfirmNativeCommand(ctx, f.policy, intent, command.CommandID, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: current}); err != nil {
		t.Fatal("other UID original protect command did not confirm", err)
	}
	if err = f.ordinary.CompleteNativeReservationDecision(ctx, f.policy, intent); err != nil {
		t.Fatal("other UID reservation could not complete after historical quarantine and fresh fence", err)
	}
	abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
	// Reuse of the old UID is always refused, in this scope and in a foreign
	// one; a receipt never grants that original subject another birth authority.
	other := abortPGSetup(t, false)
	foreign := nativeLifetimeBoot(other.p)
	foreign.Observation.PodUID, foreign.Admission.PodUID = f.bindingQ.Native.PodUID, f.bindingQ.Native.PodUID
	if _, err = other.ordinary.RegisterNativeLifetime(ctx, other.policy, other.intent, foreign); err == nil {
		t.Fatal("original quarantined UID registered again across scopes")
	}
	if _, _, err = f.store.IssueNativePreRegistrationAbortRecovery(ctx, f.policy, f.intent, f.bindingRecovery, f.observation); err == nil {
		t.Fatal("quarantine minted a third original-UID authority")
	}
}

func TestCapacityNativeAbortQuarantineLocksPostgres(t *testing.T) {
	t.Run("registration_serializes_on_original_global_uid", func(t *testing.T) {
		f := abortQuarantinePGSetup(t, nil)
		other := abortPGSetup(t, false)
		boot := nativeLifetimeBoot(other.p)
		boot.Observation.PodUID, boot.Admission.PodUID = f.bindingQ.Native.PodUID, f.bindingQ.Native.PodUID
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		blocker, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback()
		if err = nativeAbortUIDLock(ctx, blocker, f.bindingQ.Native.PodUID); err != nil {
			t.Fatal(err)
		}
		classified, registered := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := f.storeQ.QuarantineNativeUncertainAbort(ctx, f.policy, f.bindingQ, abortQuarantinePGAbsence(f))
			classified <- err
		}()
		abortQuarantinePGWaitUID(t, f.db, f.bindingQ.Native.PodUID, 1)
		go func() {
			_, err := other.ordinary.RegisterNativeLifetime(ctx, other.policy, other.intent, boot)
			registered <- err
		}()
		abortQuarantinePGWaitUID(t, f.db, f.bindingQ.Native.PodUID, 2)
		if err = blocker.Commit(); err != nil {
			t.Fatal(err)
		}
		if err = <-classified; err != nil {
			t.Fatal("first quarantine writer failed", err)
		}
		if err = <-registered; err == nil {
			t.Fatal("foreign concurrent registration acquired permanently denied original UID")
		}
		abortQuarantinePGCounts(t, f, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
	})
	t.Run("classification_waits_for_original_result_seed_writer", func(t *testing.T) {
		f := abortQuarantinePGSetup(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		writer, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Rollback()
		var pid int
		if err = writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.ExecContext(ctx, `UPDATE public.capacity_native_release_results SET adapter_ack_at=clock_timestamp() WHERE command_id=$1`, f.child.CommandID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := f.storeQ.QuarantineNativeUncertainAbort(ctx, f.policy, f.bindingQ, abortQuarantinePGAbsence(f))
			done <- err
		}()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var waiting int
			if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting > 0 {
				break
			}
			select {
			case err = <-done:
				t.Fatalf("classification skipped the locked original result seed: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("classification never waited for locked original result seed")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err = writer.Commit(); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("classification ignored committed concurrent original adapter ACK")
		}
		var n int
		if err = f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_abort_quarantines WHERE command_id=$1`, f.child.CommandID).Scan(&n); err != nil || n != 0 {
			t.Fatal("failed concurrent classification retained a receipt", err)
		}
	})
}

func abortQuarantinePGWaitUID(t *testing.T, db *sql.DB, uid string, want int) {
	t.Helper()
	key, err := json.Marshal([]string{"capacity-bound-native-uid", uid})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err = db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid`, string(key)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(fmt.Sprintf("original global UID lock waiters did not reach %d", want))
}
