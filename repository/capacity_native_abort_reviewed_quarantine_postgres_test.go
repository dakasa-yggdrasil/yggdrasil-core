package repository

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Every case retains a genuinely issued/redeemed uncertain original and its
// immutable quarantine. Only the DIFFERENT failed target has zero history.
func reviewedAbortPGSetup(t *testing.T) (abortQuarantinePGFixture, abortPGFixture) {
	t.Helper()
	q := abortQuarantinePGSetup(t, nil)
	abortQuarantinePGClassify(t, q)
	f := q.abortPGFixture
	var ref model.CapacityNativeAbortQuarantineReference
	if err := f.db.QueryRow(`SELECT command_id,subject_uid,record_sha256 FROM public.capacity_native_abort_quarantines WHERE command_id=$1`, q.child.CommandID).Scan(&ref.CommandID, &ref.SubjectUID, &ref.RecordSHA256); err != nil {
		t.Fatal(err)
	}
	f.binding.Schema = capacity.NativePreRegistrationAbortReviewedQuarantineSchema
	f.binding.PodUID, f.binding.PodName, f.binding.ReplicaSetUID = uuid.NewString(), "api-new-failed", uuid.NewString()
	f.binding.ReviewedQuarantines = &model.CapacityNativeAbortQuarantineReview{Receipts: []model.CapacityNativeAbortQuarantineReference{ref}}
	f.binding.Confirmation = "ABORT ONLY REVIEWED DIFFERENT FAILED BIRTH"
	f.observation.PodUID, f.observation.PodName, f.observation.ReplicaSetUID = f.binding.PodUID, f.binding.PodName, f.binding.ReplicaSetUID
	f.observation.ObservedAt = time.Now().UTC()
	f.store.ExecutorID = uuid.NewString()
	wf := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "abort-reviewed-human", abortPGWorkflow(f.binding))
	f.store.WorkflowID = wf.ID
	var err error
	f.intent, err = f.store.ResumeNativePreRegistrationAbort(context.Background(), f.policy, f.binding)
	if err != nil {
		t.Fatal("reviewed different-target lease", err)
	}
	return q, f
}

func reviewedAbortPGRebind(t *testing.T, f *abortPGFixture) {
	t.Helper()
	wf := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "abort-reviewed-human", abortPGWorkflow(f.binding))
	f.store.WorkflowID = wf.ID
}

func reviewedAbortPGUnknown(t *testing.T, f abortPGFixture) {
	t.Helper()
	hash := nativeArchiveSHA([]byte(uuid.NewString()))
	if _, err := f.db.Exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,phase,sequence,subject_uid,state,authority_token_sha256,command_record)VALUES($1,$2,$3,$4,$5,1,'foreign','protect',1,$6,'uncertain',$7,'{}')`, uuid.New(), f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, uuid.NewString(), hash); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityNativeAbortReviewedQuarantineOriginalPostgres(t *testing.T) {
	q, f := reviewedAbortPGSetup(t)
	before := abortQuarantinePGSnapshot(t, q)
	var receiptBefore []byte
	if err := f.db.QueryRow(`SELECT row_to_json(q) FROM public.capacity_native_abort_quarantines q WHERE command_id=$1`, q.child.CommandID).Scan(&receiptBefore); err != nil {
		t.Fatal(err)
	}
	c, token := abortPGIssue(t, f)
	var request model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	if capacity.DecodeNativeCapacity(c.Request, &request) != nil || request.Proof.ScopeUnsettledCommands != 1 || request.Proof.ReviewedQuarantineCounts == nil || *request.Proof.ReviewedQuarantineCounts != (model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1}) || c.ReleaseProtocol != capacity.NativePreRegistrationAbortReviewedQuarantineProtocol {
		t.Fatal("honest new proof/protocol missing")
	}
	ctx := context.Background()
	permit, err := f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token))
	if err != nil || permit.ReleaseProtocol != c.ReleaseProtocol {
		t.Fatal("exact own-issued row did not redeem", err)
	}
	if _, err = f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token)); err == nil {
		t.Fatal("manual authority redeemed twice")
	}
	response := abortPGRemoval(f)
	if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, true) == nil {
		t.Fatal("missing independent original callback confirmed")
	}
	if err = f.store.RecordNativePreRegistrationAbortResult(ctx, f.binding.AdapterPrincipalID, abortPGResult(f, c, permit)); err != nil {
		t.Fatal("original v2 callback", err)
	}
	if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, false) == nil {
		t.Fatal("missing human caller transport join confirmed")
	}
	if err = f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, true); err != nil {
		t.Fatal(err)
	}
	if err = f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID); err != nil {
		t.Fatal(err)
	}
	got, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID)
	if err != nil || !present || got.CommandID != c.CommandID || got.State != "confirmed" {
		t.Fatal("confirmed v2 archive/identity custody unavailable", err)
	}
	abortPGNoCheckpoint(t, f)
	abortQuarantinePGCounts(t, q, model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1})
	if !reflect.DeepEqual(before, abortQuarantinePGSnapshot(t, q)) {
		t.Fatal("new abort rewrote original unknown/request/result-seed/NULL ACK custody")
	}
	var receiptAfter []byte
	if err = f.db.QueryRow(`SELECT row_to_json(q) FROM public.capacity_native_abort_quarantines q WHERE command_id=$1`, q.child.CommandID).Scan(&receiptAfter); err != nil || !bytes.Equal(receiptBefore, receiptAfter) {
		t.Fatal("original quarantine receipt changed", err)
	}
	if _, _, err = f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation); err == nil {
		t.Fatal("archived target received new authority")
	}
}

func TestCapacityNativeAbortReviewedQuarantineIssueRefusalPostgres(t *testing.T) {
	for _, mode := range []string{"legacy_raw_one", "missing_review", "wrong_digest", "wrong_subject", "missing_receipt", "extra_reference", "same_target", "wrong_human", "target_lifetime", "target_archive", "target_legacy", "target_identity", "target_hot", "target_command_archive", "scope_active"} {
		t.Run(mode, func(t *testing.T) {
			q, f := reviewedAbortPGSetup(t)
			before := abortQuarantinePGSnapshot(t, q)
			uid, id, hash := f.binding.PodUID, uuid.New(), nativeArchiveSHA([]byte(uuid.NewString()))
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := f.db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			identity := func() {
				exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,'foreign','foreign','foreign','foreign',1,'foreign',$2,'protect',1,$3,$3)`, id, uid, hash)
			}
			switch mode {
			case "legacy_raw_one":
				f.binding.Schema, f.binding.ReviewedQuarantines = capacity.NativePreRegistrationAbortSchema, nil
			case "missing_review":
				f.binding.ReviewedQuarantines = nil
			case "wrong_digest":
				f.binding.ReviewedQuarantines.Receipts[0].RecordSHA256 = strings.Repeat("0", 64)
			case "wrong_subject":
				f.binding.ReviewedQuarantines.Receipts[0].SubjectUID = uuid.NewString()
			case "missing_receipt":
				f.binding.ReviewedQuarantines.Receipts[0].CommandID = uuid.NewString()
			case "extra_reference":
				f.binding.ReviewedQuarantines.Receipts = append(f.binding.ReviewedQuarantines.Receipts, model.CapacityNativeAbortQuarantineReference{CommandID: "ffffffff-ffff-4fff-bfff-ffffffffffff", SubjectUID: uuid.NewString(), RecordSHA256: hash})
			case "same_target":
				f.binding.ReviewedQuarantines.Receipts[0].SubjectUID = f.binding.PodUID
			case "wrong_human":
				f.store.ExecutorPowerOperator = uuid.NewString()
			case "target_lifetime":
				exec(`INSERT INTO public.capacity_native_lifetimes VALUES('foreign','foreign','foreign','foreign',$1,1,'{}',clock_timestamp())`, uid)
			case "target_archive":
				exec(`INSERT INTO public.capacity_native_lifetime_archive VALUES('foreign','foreign','foreign','foreign',$1,1,$2,$2,'{}',clock_timestamp())`, uid, hash)
			case "target_legacy":
				exec(`INSERT INTO public.capacity_native_pod_checkpoints VALUES('foreign','foreign','foreign','foreign',1,$1,'{}',clock_timestamp())`, uid)
			case "target_identity":
				identity()
			case "target_hot":
				exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,phase,sequence,subject_uid,state,authority_token_sha256,command_record)VALUES($1,'foreign','foreign','foreign','foreign',1,'foreign','protect',1,$2,'confirmed',$3,'{}')`, id, uid, hash)
			case "target_command_archive":
				identity()
				exec(`INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)VALUES($1,$2,'{}')`, id, hash)
			case "scope_active":
				reviewedAbortPGUnknown(t, f)
			}
			reviewedAbortPGRebind(t, &f)
			if _, _, err := f.store.IssueNativePreRegistrationAbort(context.Background(), f.policy, f.intent, f.binding, f.observation); err == nil {
				t.Fatal("unreviewed/active/global-history evidence authorized mutation")
			}
			var n int
			if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1 AND operation=$2`, uid, capacity.DestroyNativeUnregisteredProtection).Scan(&n); err != nil || n != 0 {
				t.Fatal("refusal retained new abort identity", err)
			}
			if !reflect.DeepEqual(before, abortQuarantinePGSnapshot(t, q)) {
				t.Fatal("refusal changed original custody")
			}
		})
	}
}

func TestCapacityNativeAbortReviewedQuarantineRedeemRevalidationPostgres(t *testing.T) {
	for _, mode := range []string{"late_ack", "missing_child", "changed_child_request", "scope_active", "target_history", "extra_receipt", "own_sql_state", "own_sql_scope"} {
		t.Run(mode, func(t *testing.T) {
			q, f := reviewedAbortPGSetup(t)
			c, token := abortPGIssue(t, f)
			var query string
			var args []any
			switch mode {
			case "late_ack":
				query, args = `UPDATE public.capacity_native_release_results SET caller_ack_at=clock_timestamp() WHERE command_id=$1`, []any{q.child.CommandID}
			case "missing_child":
				query, args = `DELETE FROM public.capacity_native_commands WHERE id=$1`, []any{q.child.CommandID}
			case "changed_child_request":
				query, args = `UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{request,proof,lineage,prior_state}','"issued"') WHERE id=$1`, []any{q.child.CommandID}
			case "scope_active":
				reviewedAbortPGUnknown(t, f)
			case "own_sql_state":
				reviewedAbortPGUnknown(t, f)
				query, args = `UPDATE public.capacity_native_commands SET state='confirmed' WHERE id=$1`, []any{c.CommandID}
			case "own_sql_scope":
				reviewedAbortPGUnknown(t, f)
				query, args = `UPDATE public.capacity_native_commands SET namespace='foreign' WHERE id=$1`, []any{c.CommandID}
			case "target_history":
				query, args = `INSERT INTO public.capacity_native_pod_checkpoints VALUES('foreign','foreign','foreign','foreign',1,$1,'{}',clock_timestamp())`, []any{f.binding.PodUID}
			case "extra_receipt":
				query, args = `WITH added AS (INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,'foreign','foreign','foreign','foreign',1,'foreign',$2,'protect',1,$4,$4) RETURNING id) INSERT INTO public.capacity_native_abort_quarantines(command_id,subject_uid,namespace,environment,domain,dimension,record_sha256,quarantine_record) SELECT added.id,$2,q.namespace,q.environment,q.domain,q.dimension,q.record_sha256,q.quarantine_record FROM added CROSS JOIN public.capacity_native_abort_quarantines q WHERE q.command_id=$3`, []any{uuid.New(), uuid.NewString(), q.child.CommandID, nativeArchiveSHA([]byte(uuid.NewString()))}
			}
			if query != "" {
				if _, err := f.db.Exec(query, args...); err != nil {
					t.Fatal("inject later independent custody fact", err)
				}
			}
			if _, err := f.store.RedeemNativePreRegistrationAbort(context.Background(), f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token)); err == nil {
				t.Fatal("later custody/active/history change did not HOLD")
			}
			var state string
			var seeds int
			wantState := "issued"
			if mode == "own_sql_state" {
				wantState = "confirmed"
			}
			if err := f.db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&state); err != nil || state != wantState {
				t.Fatal("refused redemption changed command", err)
			}
			if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1`, c.CommandID).Scan(&seeds); err != nil || seeds != 0 {
				t.Fatal("refused redemption minted result nonce", err)
			}
		})
	}
}

func TestCapacityNativeAbortReviewedQuarantineOriginalWriterLockPostgres(t *testing.T) {
	q, f := reviewedAbortPGSetup(t)
	c, token := abortPGIssue(t, f)
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var ignored string
	if err = tx.QueryRow(`SELECT command_id::text FROM public.capacity_native_release_results WHERE command_id=$1 FOR UPDATE`, q.child.CommandID).Scan(&ignored); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token))
		done <- e
	}()
	select {
	case e := <-done:
		t.Fatal("redemption passed original result writer lock", e)
	case <-time.After(75 * time.Millisecond):
	}
	if _, err = tx.Exec(`UPDATE public.capacity_native_release_results SET caller_ack_at=clock_timestamp() WHERE command_id=$1`, q.child.CommandID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("redemption ignored original ACK committed while waiting")
	}
	var state string
	if err = f.db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&state); err != nil || state != "issued" {
		t.Fatal("blocked redemption consumed original authority", err)
	}
}
