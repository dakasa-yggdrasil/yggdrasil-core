package repository

import (
	"context"
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

type abortRecoveryPGFixture struct {
	abortPGFixture
	bindingRecovery model.CapacityNativeAbortRecoveryBinding
	parent          model.CapacityNativeCommand
	parentToken     string
	oldIdentity     []byte
}

// Seed the original historical command before inserting its immutable identity.
// No test rewrites an issued identity or waits for a real lease to expire.
func abortRecoveryPGSetup(t *testing.T, old8 bool) abortRecoveryPGFixture {
	t.Helper()
	f := abortPGSetup(t, old8)
	ctx := context.Background()
	created := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	observed := f.observation
	start, finish, deleting := created.Add(-time.Minute), created.Add(-2*time.Second), created.Add(-3*time.Second)
	observed.StartedAt, observed.FinishedAt, observed.DeletionRequestedAt = &start, &finish, &deleting
	observed.ObservedAt = created.Add(-time.Second)
	f.observation = observed
	no := false
	proof := model.CapacityNativeAbortProof{Schema: capacity.NativePreRegistrationAbortSchema, Binding: f.binding, Observation: observed, FencingToken: f.intent.FencingToken, AuthoredAt: created}
	if capacity.ValidateNativeAbortProof(f.policy, f.p, proof, created) != nil {
		t.Fatal("historical parent proof invalid")
	}
	request := model.AdapterDestroyCapacityPodUnregisteredProtectionRequest{ExpectedPodUID: f.binding.PodUID, ExpectedPodResourceVersion: observed.PodResourceVersion, Proof: proof, DryRun: &no}
	raw, err := nativeAbortCanonical(request)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	parent := model.CapacityNativeCommand{CommandID: uuid.New(), PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, WorkflowID: f.store.WorkflowID, Namespace: f.intent.Namespace, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, IntentGeneration: f.intent.Generation, FencingToken: f.intent.FencingToken, LeaseOwner: f.intent.LeaseOwner, ExecutorID: f.store.ExecutorID, Adapter: f.binding.Adapter, AdapterPrincipalID: f.binding.AdapterPrincipalID, Operation: capacity.DestroyNativeUnregisteredProtection, Phase: capacity.NativePreRegistrationAbortPhase, Sequence: 1, Request: raw, RequestSHA256: nativeArchiveSHA(raw), State: "uncertain", AuthorityTokenSHA256: nativeArchiveSHA([]byte(token)), CreatedAt: created, ExpiresAt: created.Add(time.Minute), UpdatedAt: created, OriginPolicy: append(json.RawMessage(nil), f.policy.Spec...), OriginPolicySHA256: nativeCanonicalArchiveSHA(f.policy.Spec), ReleaseProtocol: capacity.NativePreRegistrationAbortProtocol, AdapterSourceCommit: f.binding.AdapterSourceCommit}
	record, err := json.Marshal(parent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = lockNativeBoundOwner(ctx, tx, f.policy, f.p, f.binding.PodUID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, parent.CommandID, parent.Namespace, parent.Environment, parent.Domain, parent.Dimension, parent.IntentGeneration, parent.Operation, f.binding.PodUID, parent.Phase, parent.Sequence, parent.AuthorityTokenSHA256, parent.RequestSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, parent.CommandID, parent.Namespace, parent.Environment, parent.Domain, parent.Dimension, parent.IntentGeneration, parent.Operation, f.binding.PodUID, parent.Phase, parent.Sequence, parent.State, parent.AuthorityTokenSHA256, record, parent.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().UTC().Add(-time.Second)
	if _, err = tx.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, expired.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	typ := abortPGCreate(t, f.db, parent.Namespace, "integration_type", "recovery-type", map[string]any{"provider": "kubernetes"})
	instance := abortPGCreate(t, f.db, parent.Namespace, "integration_instance", "recovery-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	b := model.CapacityNativeAbortRecoveryBinding{Schema: capacity.NativePreRegistrationAbortRecoverySchema, Native: f.binding, ParentCommandID: parent.CommandID.String(), ParentFencingToken: parent.FencingToken, ParentExpiresAt: parent.ExpiresAt, ExpectedIntentFencingToken: parent.FencingToken}
	b.Native.Adapter = model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), InstanceChecksum: instance.Checksum, TypeChecksum: typ.Checksum}
	b.Native.AdapterSourceCommit = strings.Repeat("c", 40)
	b.Native.AdapterPrincipalID = "recovery-adapter"
	workflow := map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": map[string]any{"rbac": map[string]any{"namespace": parent.Namespace, "name": "recovery-human"}}, "steps": []any{map[string]any{"id": "recover-once", "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}, "use": map[string]any{"kind": "yggdrasil", "operation": nativeAbortRecoveryOperation}, "with": map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
	wf := abortPGCreate(t, f.db, parent.Namespace, "workflow", "recover-human", workflow)
	f.store.WorkflowID, f.store.ExecutorID = wf.ID, uuid.NewString()
	f.store.ExecutorPowerOperator = b.Native.OperatorID
	f.observation.ObservedAt = time.Now().UTC()
	var identity []byte
	if f.db.QueryRow(`SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, parent.CommandID).Scan(&identity) != nil {
		t.Fatal("parent identity unavailable")
	}
	return abortRecoveryPGFixture{f, b, parent, token, identity}
}
func abortRecoveryPGResume(t *testing.T, f *abortRecoveryPGFixture) {
	t.Helper()
	intent, err := f.store.ResumeNativePreRegistrationAbortRecovery(context.Background(), f.policy, f.bindingRecovery)
	if err != nil {
		t.Fatal("reserve recovery lease", err)
	}
	if intent.FencingToken != f.bindingRecovery.ExpectedIntentFencingToken+1 || intent.LeaseOwner == f.parent.LeaseOwner {
		t.Fatal("original lease authority reused")
	}
	f.intent = intent
	f.observation.ObservedAt = time.Now().UTC()
}
func abortRecoveryPGIssue(t *testing.T, f abortRecoveryPGFixture) (model.CapacityNativeCommand, string) {
	t.Helper()
	child, token, err := f.store.IssueNativePreRegistrationAbortRecovery(context.Background(), f.policy, f.intent, f.bindingRecovery, f.observation)
	if err != nil {
		t.Fatal("issue recovery child", err)
	}
	return child, token
}
func abortRecoveryPGParent(t *testing.T, f abortRecoveryPGFixture, discharged bool) {
	t.Helper()
	var raw, identity []byte
	var hot, archive int
	if f.db.QueryRow(`SELECT command_record FROM public.capacity_native_commands WHERE id=$1 UNION ALL SELECT command_record FROM public.capacity_native_command_archive WHERE id=$1`, f.parent.CommandID).Scan(&raw) != nil || f.db.QueryRow(`SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, f.parent.CommandID).Scan(&identity) != nil {
		t.Fatal("parent custody lost")
	}
	var parent model.CapacityNativeCommand
	if json.Unmarshal(raw, &parent) != nil {
		t.Fatal("parent body invalid")
	}
	expected := "uncertain"
	if discharged {
		expected = "refused_no_redemption"
	}
	if parent.State != expected || !nativeAbortRecoveryNoEffect(parent) {
		t.Fatal("administrative disposition fabricated native effect")
	}
	original := f.parent
	parent.State, parent.UpdatedAt = original.State, original.UpdatedAt
	after, e1 := json.Marshal(parent)
	before, e2 := json.Marshal(original)
	if e1 != nil || e2 != nil || nativeCanonicalArchiveSHA(after) != nativeCanonicalArchiveSHA(before) || nativeCanonicalArchiveSHA(identity) != nativeCanonicalArchiveSHA(f.oldIdentity) {
		t.Fatal("original immutable facts changed")
	}
	if f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1)`, f.parent.CommandID).Scan(&hot, &archive) != nil || (!discharged && (hot != 1 || archive != 0)) || (discharged && (hot != 0 || archive != 1)) {
		t.Fatal("parent HOT/archive placement false")
	}
}
func abortRecoveryPGRedeem(f abortRecoveryPGFixture, c model.CapacityNativeCommand, token string) model.CapacityNativeAuthorityRedeemRequest {
	return model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, ReleaseProtocol: c.ReleaseProtocol, AdapterSourceCommit: c.AdapterSourceCommit}
}

func TestCapacityNativeAbortUnredeemedRecoverySelectionPostgres(t *testing.T) {
	f := abortPGSetup(t, false)
	identity := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,'protect',2,$9,$10)`, identity, f.intent.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.intent.Generation, capacity.EnsureNativePodDrain, f.binding.PodUID, nativeArchiveSHA([]byte(uuid.NewString())), nativeArchiveSHA([]byte("original-normal-command"))); err != nil {
		t.Fatal(err)
	}
	if _, present, err := f.store.LoadNativePreRegistrationAbort(context.Background(), f.policy, f.binding.PodUID); err != nil || present {
		t.Fatal("ordinary native sequence-2 history was misclassified as abort recovery")
	}
}

func TestCapacityNativeAbortUnredeemedRecoveryPostgres(t *testing.T) {
	ctx := context.Background()
	t.Run("exact_parent_archive_fresh_child_dual_return_old8_unchanged", func(t *testing.T) {
		f := abortRecoveryPGSetup(t, true)
		var old []byte
		if f.db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&old) != nil {
			t.Fatal("old8 unavailable")
		}
		abortRecoveryPGResume(t, &f)
		abortRecoveryPGParent(t, f, false)
		child, token := abortRecoveryPGIssue(t, f)
		abortRecoveryPGParent(t, f, true)
		if child.Sequence != 2 || child.CommandID == f.parent.CommandID || child.AuthorityTokenSHA256 == f.parent.AuthorityTokenSHA256 || !child.ExpiresAt.After(f.parent.ExpiresAt) {
			t.Fatal("successor reused old authority")
		}
		var request model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
		if capacity.DecodeNativeCapacity(child.Request, &request) != nil || request.Proof.History != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, ArchivedCommands: 1}) || request.Proof.ScopeUnsettledCommands != 0 || request.Proof.Lineage.PriorState != "uncertain" || !request.Proof.Lineage.DispositionAt.Equal(child.CreatedAt) {
			t.Fatal("recovery history or lineage was fabricated")
		}
		public, _ := json.Marshal(request.Proof)
		for _, private := range []string{f.parentToken, token, f.parent.AuthorityTokenSHA256, child.AuthorityTokenSHA256, "authority_token_sha256", "original_result", "return_nonce"} {
			if strings.Contains(string(public), private) {
				t.Fatal("private custody entered public proof")
			}
		}
		if _, err := f.store.RedeemNativePreRegistrationAbort(ctx, f.parent.AdapterPrincipalID, abortRecoveryPGRedeem(f, f.parent, f.parentToken)); err == nil {
			t.Fatal("archived parent redeemed")
		}
		permit, err := f.store.RedeemNativePreRegistrationAbort(ctx, child.AdapterPrincipalID, abortRecoveryPGRedeem(f, child, token))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.RedeemNativePreRegistrationAbort(ctx, child.AdapterPrincipalID, abortRecoveryPGRedeem(f, child, token)); err == nil {
			t.Fatal("child redeemed twice")
		}
		if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, child.CommandID, abortPGRemoval(f.abortPGFixture), true) == nil {
			t.Fatal("missing original result accepted")
		}
		if err = f.store.RecordNativePreRegistrationAbortResult(ctx, child.AdapterPrincipalID, abortPGResult(f.abortPGFixture, child, permit)); err != nil {
			t.Fatal(err)
		}
		if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, child.CommandID, abortPGRemoval(f.abortPGFixture), false) == nil {
			t.Fatal("missing original caller join accepted")
		}
		if err = f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, child.CommandID, abortPGRemoval(f.abortPGFixture), true); err != nil {
			t.Fatal(err)
		}
		if err = f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, child.CommandID); err != nil {
			t.Fatal(err)
		}
		got, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID)
		if err != nil || !present || got.CommandID != child.CommandID || got.State != "confirmed" {
			t.Fatal("archived pair custody refused", err)
		}
		var ids, hot, archives, pending int
		if f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),(SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1),(SELECT count(*) FROM public.capacity_native_command_archive a JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1),(SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$2 AND state IN('issued','redeemed','uncertain'))`, f.binding.PodUID, f.policy.Metadata.Namespace).Scan(&ids, &hot, &archives, &pending) != nil || ids != 2 || hot != 0 || archives != 2 || pending != 0 {
			t.Fatal("terminal pair retained scope blocker or lost real history")
		}
		var unchanged []byte
		if f.db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&unchanged) != nil || nativeCanonicalArchiveSHA(old) != nativeCanonicalArchiveSHA(unchanged) {
			t.Fatal("old8 changed")
		}
		if _, _, err = f.store.IssueNativePreRegistrationAbortRecovery(ctx, f.policy, f.intent, f.bindingRecovery, f.observation); err == nil {
			t.Fatal("third authority issued")
		}
	})
	t.Run("reservation_only_leaves_uncertain_parent", func(t *testing.T) {
		f := abortRecoveryPGSetup(t, false)
		abortRecoveryPGResume(t, &f)
		abortRecoveryPGParent(t, f, false)
		var n int
		if f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1`, f.binding.PodUID).Scan(&n) != nil || n != 1 {
			t.Fatal("reservation issued authority")
		}
	})
	t.Run("duplicate_issue_and_late_parent_redemption", func(t *testing.T) {
		f := abortRecoveryPGSetup(t, false)
		abortRecoveryPGResume(t, &f)
		var successes atomic.Int32
		var wg sync.WaitGroup
		for n := 0; n < 2; n++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := f.store.IssueNativePreRegistrationAbortRecovery(ctx, f.policy, f.intent, f.bindingRecovery, f.observation); err == nil {
					successes.Add(1)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.store.RedeemNativePreRegistrationAbort(ctx, f.parent.AdapterPrincipalID, abortRecoveryPGRedeem(f, f.parent, f.parentToken)); err == nil {
				t.Error("old expired authority redeemed during recovery")
			}
		}()
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("duplicate issue did not produce one child")
		}
		abortRecoveryPGParent(t, f, true)
	})
	t.Run("unknown_child_hold_no_third_authority", func(t *testing.T) {
		f := abortRecoveryPGSetup(t, false)
		abortRecoveryPGResume(t, &f)
		child, _ := abortRecoveryPGIssue(t, f)
		if err := f.store.MarkNativeCommandUncertain(ctx, child.CommandID); err != nil {
			t.Fatal(err)
		}
		got, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID)
		if err != nil || !present || got.State != "uncertain" || got.AttemptID != uuid.Nil {
			t.Fatal("unknown child did not remain HOLD")
		}
		if _, _, err = f.store.IssueNativePreRegistrationAbortRecovery(ctx, f.policy, f.intent, f.bindingRecovery, f.observation); err == nil {
			t.Fatal("unknown child minted third authority")
		}
		if f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, child.CommandID) == nil {
			t.Fatal("unknown child archived complete")
		}
	})
}

func TestCapacityNativeAbortUnredeemedRecoveryRefusalsPostgres(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"wrong_human", "wrong_workflow", "wrong_fence", "active_old_lease", "attempt", "result_row", "foreign_recovery_decision", "readback", "private_custody", "hot_token_column", "hot_subject_column", "hot_generation_column", "foreign_uid", "direct_orphan_hot", "expired_new_lease", "canceled", "native_rv", "native_receipt"} {
		t.Run(mode, func(t *testing.T) {
			f := abortRecoveryPGSetup(t, false)
			issue := mode == "expired_new_lease" || mode == "canceled" || mode == "native_rv" || mode == "native_receipt"
			if issue {
				abortRecoveryPGResume(t, &f)
			}
			switch mode {
			case "wrong_human":
				f.store.ExecutorPowerOperator = uuid.NewString()
			case "wrong_workflow":
				f.store.WorkflowID = f.parent.WorkflowID
			case "wrong_fence":
				f.bindingRecovery.ExpectedIntentFencingToken++
			case "active_old_lease":
				future := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
				if _, err := f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, future); err != nil {
					t.Fatal(err)
				}
			case "attempt":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{attempt_id}',to_jsonb($2::text)) WHERE id=$1`, f.parent.CommandID, uuid.NewString()); err != nil {
					t.Fatal(err)
				}
			case "result_row":
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_release_results(command_id,attempt_id,protocol,adapter_source_commit,return_nonce_sha256,original_deadline)VALUES($1,$2,$3,$4,$5,$6)`, f.parent.CommandID, uuid.New(), f.parent.ReleaseProtocol, f.parent.AdapterSourceCommit, strings.Repeat("f", 64), f.parent.ExpiresAt); err != nil {
					t.Fatal(err)
				}
			case "readback":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{native_readback}','{}') WHERE id=$1`, f.parent.CommandID); err != nil {
					t.Fatal(err)
				}
			case "foreign_recovery_decision":
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_release_recovery_decisions(id,parent_command_id,parent_attempt_id,command_id,fence,decision_record)VALUES($1,$2,$3,$2,$4,'{}')`, uuid.New(), f.parent.CommandID, uuid.New(), uuid.New()); err != nil {
					t.Fatal(err)
				}
			case "private_custody":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{authority_token_sha256}',to_jsonb($2::text)) WHERE id=$1`, f.parent.CommandID, strings.Repeat("0", 64)); err != nil {
					t.Fatal(err)
				}
			case "hot_token_column":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET authority_token_sha256=$2 WHERE id=$1`, f.parent.CommandID, strings.Repeat("f", 64)); err != nil {
					t.Fatal(err)
				}
			case "hot_subject_column":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET subject_uid=$2 WHERE id=$1`, f.parent.CommandID, uuid.NewString()); err != nil {
					t.Fatal(err)
				}
			case "hot_generation_column":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET generation=generation+1 WHERE id=$1`, f.parent.CommandID); err != nil {
					t.Fatal(err)
				}
			case "foreign_uid":
				f.bindingRecovery.Native.PodUID = uuid.NewString()
			case "direct_orphan_hot":
				orphan := f.parent
				orphan.CommandID = uuid.New()
				orphan.Sequence = 3
				orphan.AuthorityTokenSHA256 = strings.Repeat("d", 64)
				body, _ := json.Marshal(orphan)
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, orphan.CommandID, orphan.Namespace, orphan.Environment, orphan.Domain, orphan.Dimension, orphan.IntentGeneration, orphan.Operation, f.binding.PodUID, orphan.Phase, orphan.Sequence, orphan.State, orphan.AuthorityTokenSHA256, body); err != nil {
					t.Fatal(err)
				}
			case "expired_new_lease":
				expired := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
				if _, err := f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, expired); err != nil {
					t.Fatal(err)
				}
			case "native_rv":
				f.observation.PodResourceVersion = "changed"
			case "native_receipt":
				f.observation.Receipt = &model.NativePodTerminationReceipt{}
			}
			var err error
			if issue {
				owner := ctx
				if mode == "canceled" {
					var cancel context.CancelFunc
					owner, cancel = context.WithCancel(ctx)
					cancel()
				}
				_, _, err = f.store.IssueNativePreRegistrationAbortRecovery(owner, f.policy, f.intent, f.bindingRecovery, f.observation)
			} else {
				_, err = f.store.ResumeNativePreRegistrationAbortRecovery(ctx, f.policy, f.bindingRecovery)
			}
			if err == nil {
				t.Fatal("ineligible recovery admitted")
			}
			var state string
			if f.db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE id=$1`, f.parent.CommandID).Scan(&state) != nil || state != "uncertain" {
				t.Fatal("refusal discharged parent")
			}
		})
	}
}

func TestCapacityNativeAbortUnredeemedRecoveryRollbackPostgres(t *testing.T) {
	f := abortRecoveryPGSetup(t, false)
	abortRecoveryPGResume(t, &f)
	name := "abort_recovery_fail_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	// A CI-only SQL fault is after parent discharge/archive and before child
	// identity insertion. No production hook or looser acceptance path is added.
	definition := fmt.Sprintf(`CREATE FUNCTION public.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.namespace='%s' AND NEW.sequence=2 THEN RAISE EXCEPTION 'fixed recovery child insertion refused'; END IF; RETURN NEW; END; $$`, name, f.policy.Metadata.Namespace)
	if _, err := f.db.Exec(definition); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON public.capacity_native_command_identities FOR EACH ROW EXECUTE FUNCTION public.%s()`, name, name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(fmt.Sprintf(`DROP FUNCTION public.%s() CASCADE`, name)); err != nil {
			t.Error(err)
		}
	})
	if _, _, err := f.store.IssueNativePreRegistrationAbortRecovery(context.Background(), f.policy, f.intent, f.bindingRecovery, f.observation); err == nil {
		t.Fatal("insertion fault ignored")
	}
	abortRecoveryPGParent(t, f, false)
	var n int
	if f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1`, f.binding.PodUID).Scan(&n) != nil || n != 1 {
		t.Fatal("rollback retained child identity")
	}
}

func TestCapacityNativeAbortUnredeemedRecoveryPairCustodyPostgres(t *testing.T) {
	for _, mode := range []string{"child_body_missing", "child_request_changed", "duplicate_parent_hot", "child_archive_digest", "forged_confirmed_without_result", "foreign_identity"} {
		t.Run(mode, func(t *testing.T) {
			f := abortRecoveryPGSetup(t, false)
			abortRecoveryPGResume(t, &f)
			child, _ := abortRecoveryPGIssue(t, f)
			switch mode {
			case "child_body_missing":
				if _, err := f.db.Exec(`DELETE FROM public.capacity_native_commands WHERE id=$1`, child.CommandID); err != nil {
					t.Fatal(err)
				}
			case "child_request_changed":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{request,proof,lineage,prior_state}','"issued"') WHERE id=$1`, child.CommandID); err != nil {
					t.Fatal(err)
				}
			case "duplicate_parent_hot":
				// Immutable archive corruption must be detected without disabling its
				// UPDATE/DELETE trigger: create a malformed duplicate HOT parent instead.
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record)SELECT i.id,i.namespace,i.environment,i.domain,i.dimension,i.generation,i.operation,i.subject_uid,i.phase,i.sequence,'uncertain',i.authority_token_sha256,a.command_record FROM public.capacity_native_command_identities i JOIN public.capacity_native_command_archive a ON a.id=i.id WHERE i.id=$1`, f.parent.CommandID); err != nil {
					t.Fatal(err)
				}
			case "child_archive_digest":
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)SELECT id,$2,command_record FROM public.capacity_native_commands WHERE id=$1`, child.CommandID, strings.Repeat("0", 64)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.db.Exec(`DELETE FROM public.capacity_native_commands WHERE id=$1`, child.CommandID); err != nil {
					t.Fatal(err)
				}
			case "forged_confirmed_without_result":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET state='confirmed',command_record=jsonb_set(command_record,'{state}','"confirmed"') WHERE id=$1`, child.CommandID); err != nil {
					t.Fatal(err)
				}
			case "foreign_identity":
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,3,$10,$11)`, uuid.New(), child.Namespace, child.Environment, child.Domain, child.Dimension, child.IntentGeneration, child.Operation, f.binding.PodUID, child.Phase, strings.Repeat("d", 64), strings.Repeat("e", 64)); err != nil {
					t.Fatal(err)
				}
			}
			if _, present, err := f.store.LoadNativePreRegistrationAbort(context.Background(), f.policy, f.binding.PodUID); !present || err == nil {
				t.Fatal("broken global pair was reported settled")
			}
		})
	}
}
