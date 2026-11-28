package repository

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// These tests exercise migration 122 on PostgreSQL, not the member runtime.
// Parent/policy/Attempt FKs come from actual Claim/Reserve; Node/Pod UUIDs and
// private row contexts are explicitly synthetic SQL fixtures, never grants or
// physical/Kubernetes observations. No provider, SDK or member Store is called.
type nativeMemberDDLTestData struct {
	db       *sql.DB
	attempts [2]model.CapacityNativeWorkerAttempt
	realm    string
	now      time.Time
}

func nativeMemberDDLFixture(t *testing.T) nativeMemberDDLTestData {
	t.Helper()
	f, workers, _, auth := nativeAttemptFixture(t)
	data := nativeMemberDDLTestData{db: f.db, realm: f.p.NativeWorkerPoolBinding.RealmUID, now: time.Now().UTC().Truncate(time.Microsecond)}
	for i := range data.attempts {
		a, err := workers.Reserve(t.Context(), f.policy, auth)
		if err != nil || a.PolicyID != f.policy.ID || a.Namespace != f.policy.Metadata.Namespace || a.State != "reserved" {
			t.Fatal("real reserved Attempt FK prerequisite", err)
		}
		data.attempts[i] = a
	}
	return data
}

func nativeMemberDDLJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type nativeMemberDDLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type nativeMemberDDLPermitRow struct {
	id, plan, subject uuid.UUID
	a                 model.CapacityNativeWorkerAttempt
	state             string
	context, record   map[string]any
	created           time.Time
}

func nativeMemberDDLPlan(t *testing.T, d nativeMemberDDLTestData, a model.CapacityNativeWorkerAttempt, kind, state string, subject uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	identity := map[string]any{"schema": "synthetic_member_sql_identity_v1", "attempt_id": a.ID.String(), "subject_uid": subject.String()}
	record := map[string]any{"identity": identity, "state": state, "revision": 1}
	_, err := d.db.ExecContext(t.Context(), `INSERT INTO public.capacity_native_worker_member_plans(id,attempt_id,policy_id,namespace,kind,mode,subject_uid,state,revision,identity,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'never_admitted',$6,$7,1,$8,$9,$10,$10)`, id, a.ID, a.PolicyID, a.Namespace, kind, subject, state, nativeMemberDDLJSON(t, identity), nativeMemberDDLJSON(t, record), d.now)
	if err != nil {
		t.Fatal("SQL plan fixture refused", err)
	}
	return id
}

func nativeMemberDDLPermit(d nativeMemberDDLTestData, a model.CapacityNativeWorkerAttempt, plan uuid.UUID, action, capability string, subject, node uuid.UUID, state string) nativeMemberDDLPermitRow {
	id := uuid.New()
	// Expiry is deliberate: SQL history/custody does not become reusable by
	// time. This raw row is not a successful runtime Issue or Redeem.
	c := map[string]any{
		"schema": "native_worker_member_context_v1", "permit_id": id.String(), "plan_id": plan.String(), "attempt_id": a.ID.String(), "policy_id": a.PolicyID.String(), "action": action, "mode": "never_admitted",
		"core_source_commit": strings.Repeat("a", 40), "realm_uid": d.realm, "pool_uid": a.PoolUID, "epoch": a.PoolEpoch,
		"policy_checksum": strings.TrimPrefix(a.PolicyChecksum, "sha256:"), "birth_sha256": strings.Repeat("b", 64), "bootstrap_policy_sha256": strings.Repeat("c", 64),
		"actor":           map[string]any{"capability": capability, "source_commit": strings.Repeat("d", 40), "scope_sha256": strings.Repeat("e", 64)},
		"observer":        map[string]any{"source_commit": strings.Repeat("f", 40), "scope_sha256": strings.Repeat("1", 64)},
		"registry_sha256": "", "placement_fence_sha256": "", "admission_receipt_sha256": "", "drain_evidence_sha256": "", "useful_capacity_evidence_sha256": "", "physical_absence_evidence_sha256": "", "node_absence_evidence_sha256": "",
		"node": map[string]any{"uid": node.String(), "name": "nw-synthetic-" + node.String()[:8], "resource_version": "11"}, "not_after": d.now.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	if action == "bind_pod" || action == "evict_pod" {
		c["pod"] = map[string]any{"uid": subject.String(), "name": "nw-synthetic-pod", "namespace": a.Namespace, "resource_version": "21"}
	}
	return nativeMemberDDLPermitRow{id: id, plan: plan, subject: subject, a: a, state: state, context: c, record: map[string]any{"context": c, "state": state, "revision": 1}, created: d.now}
}

func nativeMemberDDLInsert(ctx context.Context, db nativeMemberDDLExecutor, row nativeMemberDDLPermitRow) error {
	c, err := json.Marshal(row.context)
	if err != nil {
		return err
	}
	r, err := json.Marshal(row.record)
	if err != nil {
		return err
	}
	actor := row.context["actor"].(map[string]any)
	_, err = db.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_member_permits(id,plan_id,attempt_id,policy_id,namespace,action,capability,subject_uid,state,revision,context,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$12)`, row.id, row.plan, row.a.ID, row.a.PolicyID, row.a.Namespace, row.context["action"], actor["capability"], row.subject, row.state, string(c), string(r), row.created)
	return err
}

func nativeMemberDDLUpdate(ctx context.Context, db nativeMemberDDLExecutor, id uuid.UUID, state string, patch map[string]any) error {
	if patch == nil {
		patch = map[string]any{}
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE public.capacity_native_worker_member_permits SET state=$2,revision=revision+1,record=(record||$3::jsonb)||jsonb_build_object('state',$2::text,'revision',revision+1),updated_at=clock_timestamp() WHERE id=$1`, id, state, string(raw))
	return err
}

func nativeMemberDDLCode(t *testing.T, err error, code string) *pq.Error {
	t.Helper()
	var pg *pq.Error
	if !errors.As(err, &pg) || string(pg.Code) != code {
		t.Fatalf("expected PostgreSQL %s guard, got %T: %v", code, err, err)
	}
	return pg
}

func TestNativeMemberPostgresRealmPodBarrierSurvivesScopeAndExpiry(t *testing.T) {
	d := nativeMemberDDLFixture(t)
	pod := uuid.New()
	rows := make([]nativeMemberDDLPermitRow, 2)
	for i, a := range d.attempts {
		plan := nativeMemberDDLPlan(t, d, a, "placement", "active", pod)
		rows[i] = nativeMemberDDLPermit(d, a, plan, "bind_pod", "ensure_native_worker_pod_placement", pod, uuid.New(), "issued")
	}
	// The second Attempt/Node/pool/epoch cannot sidestep the realm+Pod key.
	// Pool/epoch variants are SQL adversaries, not runtime-qualified contexts.
	rows[1].context["pool_uid"], rows[1].context["epoch"] = uuid.NewString(), d.attempts[1].PoolEpoch+1
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	type result struct {
		index int
		err   error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := range rows {
		go func(i int) {
			tx, err := d.db.BeginTx(ctx, nil)
			ready.Done()
			if err != nil {
				results <- result{i, err}
				return
			}
			defer tx.Rollback()
			<-start
			err = nativeMemberDDLInsert(ctx, tx, rows[i])
			if err == nil {
				err = tx.Commit()
			}
			results <- result{i, err}
		}(i)
	}
	ready.Wait()
	close(start)
	winner, loser := -1, -1
	for range rows {
		r := <-results
		if r.err == nil {
			if winner != -1 {
				t.Fatal("two different Attempts exposed Bind for the same realm/Pod")
			}
			winner = r.index
		} else {
			pg := nativeMemberDDLCode(t, r.err, "23505")
			if pg.Constraint != "capacity_native_worker_member_one_realm_bind" {
				t.Fatal("race was refused by an unrelated key", pg.Constraint)
			}
			loser = r.index
		}
	}
	if winner < 0 || loser < 0 {
		t.Fatal("race must have exactly one committed winner and one realm-key loser")
	}
	id := rows[winner].id
	for _, transition := range []struct {
		state string
		patch map[string]any
	}{{"issued", map[string]any{"dispatch_started_at": d.now.Format(time.RFC3339Nano)}}, {"redeemed", map[string]any{"settlement_token_sha256": strings.Repeat("2", 64)}}, {"unknown", map[string]any{}}} {
		if err := nativeMemberDDLUpdate(t.Context(), d.db, id, transition.state, transition.patch); err != nil {
			t.Fatal("fixture history transition failed", transition.state, err)
		}
	}
	var expired bool
	if err := d.db.QueryRowContext(t.Context(), `SELECT (context->>'not_after')::timestamptz<clock_timestamp() AND state='unknown' FROM public.capacity_native_worker_member_permits WHERE id=$1`, id).Scan(&expired); err != nil || !expired {
		t.Fatal("UNKNOWN history must be genuinely past its immutable deadline", err)
	}
	pg := nativeMemberDDLCode(t, nativeMemberDDLInsert(t.Context(), d.db, rows[loser]), "23505")
	if pg.Constraint != "capacity_native_worker_member_one_realm_bind" {
		t.Fatal("expiry did not preserve the same realm barrier", pg.Constraint)
	}
	for _, field := range []string{"realm_uid", "pool_uid"} {
		for _, variant := range []string{"missing", "null", "zero", "malformed"} {
			t.Run(field+"/"+variant, func(t *testing.T) {
				subject := uuid.New()
				plan := nativeMemberDDLPlan(t, d, d.attempts[0], "placement", "active", subject)
				row := nativeMemberDDLPermit(d, d.attempts[0], plan, "bind_pod", "ensure_native_worker_pod_placement", subject, uuid.New(), "issued")
				switch variant {
				case "missing":
					delete(row.context, field)
				case "null":
					row.context[field] = nil
				case "zero":
					row.context[field] = uuid.Nil.String()
				case "malformed":
					row.context[field] = "not-a-canonical-uuid"
				}
				nativeMemberDDLCode(t, nativeMemberDDLInsert(t.Context(), d.db, row), "23514")
			})
		}
	}
}

func TestNativeMemberPostgresPreflightAndPreparingNeverExposeMutation(t *testing.T) {
	d := nativeMemberDDLFixture(t)
	a, node := d.attempts[0], uuid.New()
	plan := nativeMemberDDLPlan(t, d, a, "read_preflight", "preparing", node)
	seed := nativeMemberDDLPermit(d, a, plan, "cordon", "ensure_native_worker_pool_member", node, node, "preparing")
	if err := nativeMemberDDLInsert(t.Context(), d.db, seed); err != nil {
		t.Fatal("read-only preflight seed refused", err)
	}
	for _, state := range []string{"issued", "redeemed", "received", "unknown", "observed"} {
		nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, seed.id, state, nil), "P0001")
	}
	for _, key := range []string{"settlement_token_sha256", "original", "dispatch_started_at", "redeemed_at"} {
		nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, seed.id, "preparing", map[string]any{key: ""}), "P0001")
	}
	if err := nativeMemberDDLUpdate(t.Context(), d.db, seed.id, "no_effect", nil); err != nil {
		t.Fatal("preflight cannot close without exposure", err)
	}
	for _, key := range []string{"settlement_token_sha256", "original", "dispatch_started_at", "redeemed_at"} {
		nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, seed.id, "no_effect", map[string]any{key: ""}), "P0001")
	}
	issued := nativeMemberDDLPermit(d, a, plan, "cordon", "ensure_native_worker_pool_member", node, node, "issued")
	nativeMemberDDLCode(t, nativeMemberDDLInsert(t.Context(), d.db, issued), "P0001")
	// A final Context always gets its own UUID. Replacing the selecting seed's
	// Node RV, even coherently in both JSON columns, cannot promote it in place.
	pod := uuid.New()
	placement := nativeMemberDDLPlan(t, d, a, "placement", "active", pod)
	selecting := nativeMemberDDLPermit(d, a, placement, "bind_pod", "ensure_native_worker_pod_placement", pod, node, "preparing")
	if err := nativeMemberDDLInsert(t.Context(), d.db, selecting); err != nil {
		t.Fatal(err)
	}
	nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, selecting.id, "issued", nil), "P0001")
	_, err := d.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_permits SET context=jsonb_set(context,'{node,resource_version}','"12"'::jsonb),revision=revision+1,record=jsonb_set(jsonb_set(record,'{context,node,resource_version}','"12"'::jsonb),'{revision}',to_jsonb(revision+1)) WHERE id=$1`, selecting.id)
	nativeMemberDDLCode(t, err, "P0001")
	if err = nativeMemberDDLUpdate(t.Context(), d.db, selecting.id, "no_effect", nil); err != nil {
		t.Fatal(err)
	}
	final := nativeMemberDDLPermit(d, a, placement, "bind_pod", "ensure_native_worker_pod_placement", pod, node, "issued")
	final.context["node"].(map[string]any)["resource_version"] = "12"
	if final.id == selecting.id {
		t.Fatal("separate UUID fixture accidentally reused the selecting seed")
	}
	if err = nativeMemberDDLInsert(t.Context(), d.db, final); err != nil {
		t.Fatal("new final Context UUID refused", err)
	}
	var seeds, finals int
	if err = d.db.QueryRowContext(t.Context(), `SELECT count(*) FILTER(WHERE state='no_effect'),count(*) FILTER(WHERE state='issued') FROM public.capacity_native_worker_member_permits WHERE plan_id=$1`, placement).Scan(&seeds, &finals); err != nil || seeds != 1 || finals != 1 {
		t.Fatal("selection history was rewritten instead of retained", seeds, finals, err)
	}
}

func nativeMemberDDLCipher(t *testing.T, plaintext string) map[string]any {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonceID := uuid.New()
	nonce := append([]byte(nil), nonceID[:aead.NonceSize()]...)
	sealed := aead.Seal(nil, nonce, []byte(plaintext), []byte("synthetic-sql-custody-only"))
	return map[string]any{"nonce": base64.StdEncoding.EncodeToString(nonce), "ciphertext": base64.StdEncoding.EncodeToString(sealed)}
}

func TestNativeMemberPostgresLateEncryptedCustodyAndEventsAreImmutable(t *testing.T) {
	d := nativeMemberDDLFixture(t)
	a, node := d.attempts[0], uuid.New()
	plan := nativeMemberDDLPlan(t, d, a, "retirement", "active", node)
	row := nativeMemberDDLPermit(d, a, plan, "cordon", "ensure_native_worker_pool_member", node, node, "issued")
	for key, value := range map[string]any{"settlement_token_sha256": strings.Repeat("2", 64), "original": nativeMemberDDLCipher(t, "synthetic-preinsert-original")} {
		injected := row
		injected.record = map[string]any{"context": row.context, "state": "issued", "revision": 1, key: value}
		nativeMemberDDLCode(t, nativeMemberDDLInsert(t.Context(), d.db, injected), "P0001")
	}
	if err := nativeMemberDDLInsert(t.Context(), d.db, row); err != nil {
		t.Fatal(err)
	}
	dispatched := d.now.Format(time.RFC3339Nano)
	tokenSHA := strings.Repeat("2", 64)
	if err := nativeMemberDDLUpdate(t.Context(), d.db, row.id, "issued", map[string]any{"dispatch_started_at": dispatched}); err != nil {
		t.Fatal("first private dispatch latch refused", err)
	}
	if err := nativeMemberDDLUpdate(t.Context(), d.db, row.id, "redeemed", map[string]any{"settlement_token_sha256": tokenSHA}); err != nil {
		t.Fatal(err)
	}
	// Use a legal nonterminal next state so a terminal-state guard cannot mask
	// mutable token/dispatch authority. Every failed statement must roll back.
	for _, patch := range []map[string]any{{"settlement_token_sha256": strings.Repeat("3", 64)}, {"dispatch_started_at": d.now.Add(time.Second).Format(time.RFC3339Nano)}} {
		nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, row.id, "unknown", patch), "P0001")
	}
	_, err := d.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_permits SET state='unknown',revision=revision+1,record=(record-'dispatch_started_at')||jsonb_build_object('state','unknown','revision',revision+1) WHERE id=$1`, row.id)
	nativeMemberDDLCode(t, err, "P0001")
	if err = nativeMemberDDLUpdate(t.Context(), d.db, row.id, "unknown", nil); err != nil {
		t.Fatal(err)
	}
	if err = nativeMemberDDLUpdate(t.Context(), d.db, row.id, "observed", nil); err != nil {
		t.Fatal(err)
	}
	const privateMarker = "synthetic-private-original-not-public"
	original := nativeMemberDDLCipher(t, privateMarker)
	// The first original may arrive after both deadline and observed truth.
	// It adds custody only: same terminal state and immutable token/dispatch.
	if err = nativeMemberDDLUpdate(t.Context(), d.db, row.id, "observed", map[string]any{"original": original}); err != nil {
		t.Fatal("first late encrypted original refused", err)
	}
	if err = nativeMemberDDLUpdate(t.Context(), d.db, row.id, "observed", map[string]any{"original": original}); err != nil {
		t.Fatal("identical original changed history", err)
	}
	for _, replacement := range []any{nil, map[string]any{"nonce": original["nonce"], "ciphertext": "changed"}, map[string]any{"nonce": "changed", "ciphertext": original["ciphertext"]}} {
		nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, row.id, "observed", map[string]any{"original": replacement}), "P0001")
	}
	_, err = d.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_permits SET revision=revision+1,record=jsonb_set(record-'original','{revision}',to_jsonb(revision+1)) WHERE id=$1`, row.id)
	nativeMemberDDLCode(t, err, "P0001")
	nativeMemberDDLCode(t, nativeMemberDDLUpdate(t.Context(), d.db, row.id, "issued", nil), "P0001")
	var state, storedToken, storedDispatch, storedOriginal, storedRecord string
	var expired bool
	if err = d.db.QueryRowContext(t.Context(), `SELECT state,record->>'settlement_token_sha256',record->>'dispatch_started_at',record->'original',record,(context->>'not_after')::timestamptz<clock_timestamp() FROM public.capacity_native_worker_member_permits WHERE id=$1`, row.id).Scan(&state, &storedToken, &storedDispatch, &storedOriginal, &storedRecord, &expired); err != nil || state != "observed" || storedToken != tokenSHA || storedDispatch != dispatched || !expired {
		t.Fatal("late custody renewed or lost immutable authority", err)
	}
	var storedCipher map[string]string
	if err = json.Unmarshal([]byte(storedOriginal), &storedCipher); err != nil || storedCipher["nonce"] != original["nonce"] || storedCipher["ciphertext"] != original["ciphertext"] || len(storedCipher) != 2 {
		t.Fatal("stored encrypted envelope changed", err)
	}
	if strings.Contains(storedRecord, privateMarker) || strings.Contains(storedRecord, fmt.Sprintf("%x", sha256.Sum256([]byte(privateMarker)))) {
		t.Fatal("raw original or its digest was stored in clear")
	}
	readID := uuid.New()
	contextSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(nativeMemberDDLJSON(t, row.context))))
	observer := row.context["observer"].(map[string]any)
	readRecord := map[string]any{"read_id": readID.String(), "permit_id": row.id.String(), "context_sha256": contextSHA, "subject_node_uid": node.String(), "sdk_source_commit": observer["source_commit"], "scope_sha256": observer["scope_sha256"], "kind": "kubelet_configz", "created_at": d.now.Format(time.RFC3339Nano)}
	insertRead := func() error {
		_, e := d.db.ExecContext(t.Context(), `INSERT INTO public.capacity_native_worker_member_reads(id,permit_id,policy_id,namespace,context_sha256,endpoint_kind,source_commit,scope_sha256,subject_node_uid,state,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'kubelet_configz',$6,$7,$8,'issued',$9,$10,$10)`, readID, row.id, a.PolicyID, a.Namespace, contextSHA, observer["source_commit"], observer["scope_sha256"], node, nativeMemberDDLJSON(t, readRecord), d.now)
		return e
	}
	readCipher := nativeMemberDDLCipher(t, "synthetic-private-configz-not-public")
	readRecord["private_original"] = readCipher
	nativeMemberDDLCode(t, insertRead(), "P0001")
	delete(readRecord, "private_original")
	err = insertRead()
	if err != nil {
		t.Fatal("read-only historical custody issuance refused", err)
	}
	_, err = d.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_reads SET state='captured',record=record||jsonb_build_object('private_original',$2::jsonb),updated_at=clock_timestamp() WHERE id=$1`, readID, nativeMemberDDLJSON(t, readCipher))
	if err != nil {
		t.Fatal("first late read original refused", err)
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_worker_member_reads SET record=record-'private_original' WHERE id=$1`,
		`UPDATE public.capacity_native_worker_member_reads SET record=record||'{"private_original":{"nonce":"changed","ciphertext":"changed"}}'::jsonb WHERE id=$1`,
		`DELETE FROM public.capacity_native_worker_member_reads WHERE id=$1`,
	} {
		_, err = d.db.ExecContext(t.Context(), query, readID)
		nativeMemberDDLCode(t, err, "P0001")
	}
	var captured string
	if err = d.db.QueryRowContext(t.Context(), `SELECT record->'private_original' FROM public.capacity_native_worker_member_reads WHERE id=$1 AND state='captured'`, readID).Scan(&captured); err != nil {
		t.Fatal(err)
	}
	var actualReadCipher map[string]string
	if json.Unmarshal([]byte(captured), &actualReadCipher) != nil || actualReadCipher["nonce"] != readCipher["nonce"] || actualReadCipher["ciphertext"] != readCipher["ciphertext"] || len(actualReadCipher) != 2 {
		t.Fatal("read ciphertext history changed")
	}
	for _, kind := range []string{"original_captured", "read_captured"} {
		_, err = d.db.ExecContext(t.Context(), `INSERT INTO public.capacity_native_worker_member_events(plan_id,permit_id,read_id,policy_id,namespace,kind,record,created_at) VALUES($1,$2,$3,$4,$5,$6,'{"schema":"synthetic_private_member_event_v1","state":"captured"}',$7)`, plan, row.id, readID, a.PolicyID, a.Namespace, kind, d.now)
		if err != nil {
			t.Fatal("append-only fixture event refused", err)
		}
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_worker_member_events SET record=record||'{"changed":true}'::jsonb WHERE plan_id=$1`,
		`DELETE FROM public.capacity_native_worker_member_events WHERE plan_id=$1`,
		`UPDATE public.capacity_native_worker_member_plans SET identity=identity||'{"changed":true}'::jsonb,revision=revision+1,record=jsonb_set(jsonb_set(record,'{identity}',identity||'{"changed":true}'::jsonb),'{revision}',to_jsonb(revision+1)) WHERE id=$1`,
		`DELETE FROM public.capacity_native_worker_member_plans WHERE id=$1`,
	} {
		_, err = d.db.ExecContext(t.Context(), query, plan)
		nativeMemberDDLCode(t, err, "P0001")
	}
	_, err = d.db.ExecContext(t.Context(), `DELETE FROM public.capacity_native_worker_member_permits WHERE id=$1`, row.id)
	nativeMemberDDLCode(t, err, "P0001")
	var events int
	if err = d.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_native_worker_member_events WHERE plan_id=$1`, plan).Scan(&events); err != nil || events != 2 {
		t.Fatal("append-only event history changed", events, err)
	}
}

func TestNativeMemberPostgresDownRefusesHistoryAndEmptyRestores121(t *testing.T) {
	t.Run("retained-read-only-no-effect-history", func(t *testing.T) {
		d := nativeMemberDDLFixture(t)
		a, node := d.attempts[0], uuid.New()
		plan := nativeMemberDDLPlan(t, d, a, "read_preflight", "preparing", node)
		row := nativeMemberDDLPermit(d, a, plan, "cordon", "ensure_native_worker_pool_member", node, node, "preparing")
		if err := nativeMemberDDLInsert(t.Context(), d.db, row); err != nil {
			t.Fatal(err)
		}
		if err := nativeMemberDDLUpdate(t.Context(), d.db, row.id, "no_effect", nil); err != nil {
			t.Fatal(err)
		}
		_, err := d.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_plans SET state='cancelled',revision=revision+1,record=record||jsonb_build_object('state','cancelled','revision',revision+1),updated_at=clock_timestamp() WHERE id=$1`, plan)
		if err != nil {
			t.Fatal(err)
		}
		err = goose.DownTo(d.db, "../db/migrations", 121)
		pg := nativeMemberDDLCode(t, err, "P0001")
		if pg.Message != "native member plans and private custody cannot be discarded" {
			t.Fatal("Down did not refuse at the explicit history guard", pg.Message)
		}
		version, err := goose.GetDBVersion(d.db)
		if err != nil || version != 122 {
			t.Fatal("failed Down changed schema version", version, err)
		}
		for _, table := range []string{"plans", "permits", "reads", "events"} {
			var name sql.NullString
			if err := d.db.QueryRowContext(t.Context(), `SELECT to_regclass($1)::text`, "public.capacity_native_worker_member_"+table).Scan(&name); err != nil || !name.Valid {
				t.Fatal("history refusal dropped a member table", table, err)
			}
		}
		for _, guard := range []string{"plan", "permit", "read", "event"} {
			var name sql.NullString
			if err := d.db.QueryRowContext(t.Context(), `SELECT to_regprocedure($1)::text`, "public.capacity_native_worker_member_"+guard+"_guard()").Scan(&name); err != nil || !name.Valid {
				t.Fatal("history refusal dropped a member guard", guard, err)
			}
		}
		_, err = d.db.ExecContext(t.Context(), `DELETE FROM public.capacity_native_worker_member_permits WHERE id=$1`, row.id)
		nativeMemberDDLCode(t, err, "P0001")
		var retained int
		if err = d.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_native_worker_member_permits WHERE id=$1 AND state='no_effect'`, row.id).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("Down erased never-exposed read-only history", retained, err)
		}
	})
	t.Run("empty-member-ledger", func(t *testing.T) {
		db := nativeAttemptDatabase(t)
		if version, err := goose.GetDBVersion(db); err != nil || version != 122 {
			t.Fatal("empty Down must begin at migration 122", version, err)
		}
		guards := map[string]string{}
		for _, name := range []string{"capacity_native_worker_attempt_guard", "capacity_native_worker_execution_dispatch_guard", "capacity_native_worker_readiness_run_guard"} {
			var definition string
			if err := db.QueryRowContext(t.Context(), `SELECT pg_get_functiondef(to_regprocedure($1))`, "public."+name+"()").Scan(&definition); err != nil {
				t.Fatal("prior guard missing before Down", name, err)
			}
			guards[name] = definition
		}
		if err := goose.DownTo(db, "../db/migrations", 121); err != nil {
			t.Fatal("empty member Down refused", err)
		}
		version, err := goose.GetDBVersion(db)
		if err != nil || version != 121 {
			t.Fatal("empty Down did not restore 121", version, err)
		}
		for _, table := range []string{"plans", "permits", "reads", "events"} {
			var name sql.NullString
			if err := db.QueryRowContext(t.Context(), `SELECT to_regclass($1)::text`, "public.capacity_native_worker_member_"+table).Scan(&name); err != nil || name.Valid {
				t.Fatal("empty Down retained member table", table, err)
			}
		}
		for _, guard := range []string{"plan", "permit", "read", "event"} {
			var name sql.NullString
			if err := db.QueryRowContext(t.Context(), `SELECT to_regprocedure($1)::text`, "public.capacity_native_worker_member_"+guard+"_guard()").Scan(&name); err != nil || name.Valid {
				t.Fatal("empty Down retained member guard", guard, err)
			}
		}
		for name, before := range guards {
			var after string
			if err := db.QueryRowContext(t.Context(), `SELECT pg_get_functiondef(to_regprocedure($1))`, "public."+name+"()").Scan(&after); err != nil || after != before {
				t.Fatal("Down changed a guard from migration 121 or earlier", name, err)
			}
		}
	})
}
