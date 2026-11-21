package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type abortPGFixture struct {
	db              *sql.DB
	store, ordinary CapacityStore
	policy          model.Manifest
	p               model.CapacityPolicySpec
	intent          model.CapacityIntent
	binding         model.CapacityNativeAbortBinding
	observation     model.NativePreRegistrationAbortObservation
	boot            model.AdapterCapacityPodAdmissionResponse
}

func abortPGCreate(t *testing.T, db *sql.DB, ns, kind, name string, spec any) model.Manifest {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	m, err := CreateManifestVersion(context.Background(), db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func abortPGWorkflow(b model.CapacityNativeAbortBinding) map[string]any {
	return map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "async", "authorization": map[string]any{"rbac": map[string]any{"namespace": "fixed", "name": "human-only"}}, "steps": []any{map[string]any{"id": "abort-once", "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}, "use": map[string]any{"kind": "yggdrasil", "operation": "capacity.abort_native_birth"}, "with": map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
}
func abortPGSetup(t *testing.T, old8 bool) abortPGFixture {
	t.Helper()
	db, normal, policy, p, intent := nativeLifetimePostgresFixture(t)
	if old8 {
		nativeLifetimeProtect(t, normal, policy, p, intent, nativeLifetimeBoot(p))
	}
	typ := abortPGCreate(t, db, policy.Metadata.Namespace, "integration_type", "abort-type", map[string]any{"provider": "kubernetes"})
	instance := abortPGCreate(t, db, policy.Metadata.Namespace, "integration_instance", "abort-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	boot := nativeLifetimeBoot(p)
	start := *boot.Observation.StartedAt
	finish := time.Now().UTC().Add(-time.Second)
	deleting := finish.Add(-time.Second)
	exit, signal := int32(1), int32(0)
	obs := model.NativePreRegistrationAbortObservation{NativeTerminationObservation: boot.Observation, ReplicaSetUID: uuid.NewString(), PodSpecSHA256: strings.Repeat("e", 64), PodPhase: "Failed", BirthWorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ChallengeState: "absent"}
	obs.StartedAt = &start
	obs.FinishedAt = &finish
	obs.DeletionRequestedAt = &deleting
	obs.ContainerState = "terminated"
	obs.State = "failed_deleting"
	obs.ExitCode = &exit
	obs.Signal = &signal
	obs.AdmissionReady = false
	obs.Receipt = nil
	obs.ReceiptSHA256 = ""
	obs.ObservedAt = time.Now().UTC()
	b := model.CapacityNativeAbortBinding{Schema: capacity.NativePreRegistrationAbortSchema, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, Generation: 1, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), InstanceChecksum: instance.Checksum, TypeChecksum: typ.Checksum}, AdapterPrincipalID: "abort-adapter", AdapterSourceCommit: strings.Repeat("b", 40), OperatorID: uuid.NewString(), BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: obs.Namespace, PodName: obs.PodName, PodUID: obs.PodUID, WorkloadUID: obs.WorkloadUID, ReplicaSetUID: obs.ReplicaSetUID, ContainerName: obs.ContainerName, ImageDigest: obs.ImageDigest, PodSpecSHA256: obs.PodSpecSHA256, Confirmation: "ABORT ONLY EXACT ORIGINAL"}
	wf := abortPGCreate(t, db, policy.Metadata.Namespace, "workflow", "abort-human", abortPGWorkflow(b))
	past := time.Now().UTC().Add(-time.Second)
	if _, err := db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, policy.Metadata.Namespace, past.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	store := normal
	store.AdmissionOnly = false
	store.WorkflowID = wf.ID
	store.ExecutorPowerOperator = b.OperatorID
	resumed, err := store.ResumeNativePreRegistrationAbort(context.Background(), policy, b)
	if err != nil {
		t.Fatal("fresh abort lease", err)
	}
	if resumed.Generation != intent.Generation || resumed.FencingToken != intent.FencingToken+1 || resumed.LeaseOwner == intent.LeaseOwner || resumed.Decision.Action != intent.Decision.Action {
		t.Fatal("abort Resume changed generation/decision or reused expired fence")
	}
	var owners int
	if db.QueryRow(`SELECT count(*) FROM public.capacity_native_scope_owners WHERE native_uid=$1`, b.PodUID).Scan(&owners) != nil || owners != 0 {
		t.Fatal("lease-only Resume claimed native UID before observation")
	}
	return abortPGFixture{db, store, normal, policy, p, resumed, b, obs, boot}
}
func abortPGIssue(t *testing.T, f abortPGFixture) (model.CapacityNativeCommand, string) {
	t.Helper()
	c, token, err := f.store.IssueNativePreRegistrationAbort(context.Background(), f.policy, f.intent, f.binding, f.observation)
	if err != nil {
		t.Fatal(err)
	}
	return c, token
}
func abortPGRedeem(f abortPGFixture, c model.CapacityNativeCommand, token string) model.CapacityNativeAuthorityRedeemRequest {
	return model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: f.binding.Adapter.IntegrationInstanceID, IntegrationTypeID: f.binding.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, ReleaseProtocol: c.ReleaseProtocol, AdapterSourceCommit: c.AdapterSourceCommit}
}
func abortPGResult(f abortPGFixture, c model.CapacityNativeCommand, permit model.CapacityNativeAuthorityPermit) model.CapacityNativeReleaseResult {
	return model.CapacityNativeReleaseResult{Protocol: c.ReleaseProtocol, CommandID: c.CommandID, AttemptID: permit.AttemptID, IntegrationInstanceID: c.Adapter.IntegrationInstanceID, IntegrationTypeID: c.Adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, AdapterSourceCommit: c.AdapterSourceCommit, ReturnNonce: permit.ReturnNonce, OriginalStatus: 200, OriginalResponseSHA256: strings.Repeat("f", 64), Outcome: "applied", OneSend: true, DoReturned: true, ReadReturned: true, CloseReturned: true}
}
func abortPGRemoval(f abortPGFixture) model.AdapterCapacityPodUnregisteredTerminalResponse {
	o := f.observation
	o.Protected = false
	o.PodResourceVersion = "22"
	o.ObservedAt = time.Now().UTC()
	return model.AdapterCapacityPodUnregisteredTerminalResponse{Operation: capacity.ObserveNativeUnregisteredTerminal, Status: "observed", Observation: o}
}
func abortPGNoCheckpoint(t *testing.T, f abortPGFixture) {
	t.Helper()
	var n int
	if f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, f.binding.PodUID).Scan(&n) != nil || n != 0 {
		t.Fatal("abort fabricated a lifetime")
	}
}

func TestCapacityNativePreRegistrationAbortPostgres(t *testing.T) {
	ctx := context.Background()
	t.Run("real_original_nonce_join_archive_and_old8_unchanged", func(t *testing.T) {
		f := abortPGSetup(t, true)
		var old []byte
		if err := f.db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&old); err != nil {
			t.Fatal(err)
		}
		// Exercise the real human step's finite Go deadline with nanoseconds that
		// PostgreSQL timestamptz cannot retain, through both ACKs and compaction.
		deadline := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond).Add(123 * time.Nanosecond)
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		c, token, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation)
		if err != nil || c.ExpiresAt.After(deadline) || c.ExpiresAt.Nanosecond()%1000 != 0 || c.ExpiresAt.Equal(deadline) {
			t.Fatal("original finite deadline was extended or lost PostgreSQL precision", err)
		}
		permit, err := f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token)); err == nil {
			t.Fatal("original token redeemed twice")
		}
		response := abortPGRemoval(f)
		if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, true) == nil {
			t.Fatal("missing authenticated original callback confirmed")
		}
		r := abortPGResult(f, c, permit)
		wrong := r
		wrong.ReturnNonce = strings.Repeat("0", 64)
		if f.store.RecordNativePreRegistrationAbortResult(ctx, f.binding.AdapterPrincipalID, wrong) == nil {
			t.Fatal("foreign nonce accepted")
		}
		if err = f.store.RecordNativePreRegistrationAbortResult(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, false) == nil {
			t.Fatal("caller transport join fabricated")
		}
		if err = f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, response, true); err != nil {
			t.Fatal(err)
		}
		if err = f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID); err != nil {
			t.Fatal(err)
		}
		got, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID)
		if err != nil || !present || got.State != "confirmed" || got.CommandID != c.CommandID {
			t.Fatal("immutable abort history unavailable", err)
		}
		var hot, archive, ids int
		var result []byte
		if f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1),(SELECT count(*) FROM public.capacity_native_command_identities WHERE id=$1)`, c.CommandID).Scan(&hot, &archive, &ids) != nil || hot != 0 || archive != 1 || ids != 1 {
			t.Fatal("abort compaction lost permanent identity")
		}
		if f.db.QueryRow(`SELECT adapter_result FROM public.capacity_native_release_results WHERE command_id=$1`, c.CommandID).Scan(&result) != nil {
			t.Fatal("original callback missing")
		}
		var retained model.CapacityNativeReleaseResult
		if json.Unmarshal(result, &retained) != nil || retained.ReturnNonce != "" {
			t.Fatal("plaintext return nonce persisted")
		}
		var current []byte
		if f.db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&current) != nil || string(old) != string(current) {
			t.Fatal("old admitted lifetime changed")
		}
		if _, err = f.ordinary.RegisterNativeLifetime(ctx, f.policy, f.intent, f.boot); err == nil {
			t.Fatal("archived abort UID registered")
		}
		if _, _, err = f.ordinary.IssueNativeCommand(ctx, f.policy, f.intent, capacity.EnsureNativePodDrain, f.binding.PodUID, json.RawMessage(`{}`)); err == nil {
			t.Fatal("normal Pod command crossed permanent deny")
		}
		if _, _, err = f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation); err == nil {
			t.Fatal("second abort authority issued")
		}
		if _, err = f.db.Exec(`DELETE FROM public.capacity_native_command_identities WHERE id=$1`, c.CommandID); err == nil {
			t.Fatal("identity tombstone deleted")
		}
		if _, err = f.db.Exec(`DELETE FROM public.capacity_native_release_results WHERE command_id=$1`, c.CommandID); err == nil {
			t.Fatal("acknowledged original return row deleted")
		}
		if _, err = f.db.Exec(`UPDATE public.capacity_native_release_results SET caller_ack_at=NULL WHERE command_id=$1`, c.CommandID); err == nil {
			t.Fatal("acknowledged original caller join cleared")
		}
		if got, present, err = f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID); err != nil || !present || got.State != "confirmed" {
			t.Fatal("immutable custody changed after refused SQL mutations", err)
		}
		abortPGNoCheckpoint(t, f)
	})
	t.Run("unknown_original_and_identity_only_never_reissue_or_register", func(t *testing.T) {
		f := abortPGSetup(t, false)
		c, token := abortPGIssue(t, f)
		if err := f.store.MarkNativeCommandUncertain(ctx, c.CommandID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token)); err == nil {
			t.Fatal("uncertain original redeemed again")
		}
		if f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID) == nil {
			t.Fatal("uncertain original archived")
		}
		if _, _, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation); err == nil {
			t.Fatal("uncertain original reissued")
		}
		// Simulate lost HOT custody without deleting the immutable identity.
		if _, err := f.db.Exec(`DELETE FROM public.capacity_native_commands WHERE id=$1`, c.CommandID); err != nil {
			t.Fatal(err)
		}
		if _, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID); !present || err == nil {
			t.Fatal("identity-only uncertainty became absence")
		}
		if _, err := f.ordinary.RegisterNativeLifetime(ctx, f.policy, f.intent, f.boot); err == nil {
			t.Fatal("identity-only abort UID registered")
		}
		abortPGNoCheckpoint(t, f)
	})
	for _, kind := range []string{"lifetime", "lifetime-archive", "legacy", "identity", "hot-orphan", "command-archive", "scope-issued-HPA", "scope-redeemed-HPA", "scope-uncertain-HPA"} {
		t.Run("global-zero-"+kind, func(t *testing.T) {
			f := abortPGSetup(t, false)
			uid := f.binding.PodUID
			id := uuid.New()
			hash := nativeArchiveSHA([]byte(uuid.NewString()))
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := f.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			identity := func() {
				exec(`INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,'foreign','foreign','foreign','foreign',1,'foreign',$2,'protect',1,$3,$3)`, id, uid, hash)
			}
			switch kind {
			case "lifetime":
				exec(`INSERT INTO public.capacity_native_lifetimes VALUES('foreign','foreign','foreign','foreign',$1,1,'{}',clock_timestamp())`, uid)
			case "lifetime-archive":
				exec(`INSERT INTO public.capacity_native_lifetime_archive VALUES('foreign','foreign','foreign','foreign',$1,1,$2,$2,'{}',clock_timestamp())`, uid, hash)
			case "legacy":
				exec(`INSERT INTO public.capacity_native_pod_checkpoints VALUES('foreign','foreign','foreign','foreign',1,$1,'{}',clock_timestamp())`, uid)
			case "identity":
				identity()
			case "hot-orphan":
				exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,phase,sequence,subject_uid,state,authority_token_sha256,command_record)VALUES($1,'foreign','foreign','foreign','foreign',1,'foreign','protect',1,$2,'confirmed',$3,'{}')`, id, uid, hash)
			case "command-archive":
				identity()
				exec(`INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)VALUES($1,$2,'{}')`, id, hash)
			default:
				state := strings.Split(kind, "-")[1]
				exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,phase,sequence,subject_uid,state,authority_token_sha256,command_record)VALUES($1,$2,$3,$4,$5,1,$6,'envelope',1,$7,$8,$9,'{}')`, id, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, capacity.EnsureBoundHPAEnvelope, f.p.AssessmentBinding.Snapshot.HPAUID, state, hash)
			}
			// The lifetime blocker deliberately seeds a foreign existing row.
			// Compare the entire prior target-row set, rather than requiring zero.
			lifetimeSnapshot := func() []byte {
				t.Helper()
				var raw []byte
				if err := f.db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.namespace,x.environment,x.domain,x.dimension),'[]'::jsonb) FROM public.capacity_native_lifetimes x WHERE pod_uid=$1`, uid).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			beforeLifetimes := lifetimeSnapshot()
			if _, _, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation); err == nil {
				t.Fatal("global/other-scope/terminal/orphan evidence ignored")
			}
			var n int
			if f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_command_identities WHERE operation=$1 AND subject_uid=$2`, capacity.DestroyNativeUnregisteredProtection, uid).Scan(&n) != nil || n != 0 {
				t.Fatal("refused transaction left new abort identity")
			}
			if string(beforeLifetimes) != string(lifetimeSnapshot()) {
				t.Fatal("refused abort changed or fabricated a target lifetime")
			}
		})
	}
	for _, kind := range []string{"human", "retry", "condition", "family", "foreign-binding", "template-binding", "inactive-workflow", "stale-fence", "foreign-principal", "foreign-source", "foreign-token-digest", "proof-tamper", "rejected-original", "expired-redemption", "expired-callback"} {
		t.Run("closed-"+kind, func(t *testing.T) {
			f := abortPGSetup(t, false)
			if kind == "human" {
				f.store.ExecutorPowerOperator = uuid.NewString()
			}
			if kind == "stale-fence" {
				f.intent.FencingToken--
			}
			if kind == "retry" || kind == "condition" || kind == "family" || kind == "foreign-binding" || kind == "template-binding" || kind == "inactive-workflow" {
				wf := abortPGWorkflow(f.binding)
				step := wf["steps"].([]any)[0].(map[string]any)
				switch kind {
				case "retry":
					step["retry"] = map[string]any{"max_attempts": 2}
				case "condition":
					step["if"] = true
				case "family":
					step["use"].(map[string]any)["family"] = "capacity"
				case "foreign-binding":
					b := f.binding
					b.PodUID = uuid.NewString()
					step["with"].(map[string]any)["binding"] = b
				case "template-binding":
					step["with"].(map[string]any)["binding"] = "{{ inputs.binding }}"
				}
				m := abortPGCreate(t, f.db, f.policy.Metadata.Namespace, "workflow", "abort-human", wf)
				f.store.WorkflowID = m.ID
				if kind == "inactive-workflow" {
					if _, err := f.db.Exec(`UPDATE public.manifests SET active=false WHERE id=$1`, m.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "human" || kind == "retry" || kind == "condition" || kind == "family" || kind == "foreign-binding" || kind == "template-binding" || kind == "inactive-workflow" || kind == "stale-fence" {
				if _, _, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation); err == nil {
					t.Fatal("unapproved human/WF/binding/fence accepted")
				}
				return
			}
			c, token := abortPGIssue(t, f)
			request := abortPGRedeem(f, c, token)
			principal := f.binding.AdapterPrincipalID
			if kind == "foreign-principal" {
				principal = "foreign"
			}
			if kind == "foreign-source" {
				request.AdapterSourceCommit = strings.Repeat("0", 40)
			}
			if kind == "foreign-token-digest" {
				request.RequestSHA256 = strings.Repeat("0", 64)
			}
			if kind == "proof-tamper" {
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{request,proof,zero_history,lifetimes}','1') WHERE id=$1`, c.CommandID); err != nil {
					t.Fatal(err)
				}
			}
			expire := func() {
				if _, e := f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "expired-redemption" {
				expire()
			}
			permit, err := f.store.RedeemNativePreRegistrationAbort(ctx, principal, request)
			if kind == "expired-callback" {
				if err != nil {
					t.Fatal(err)
				}
				expire()
				if f.store.RecordNativePreRegistrationAbortResult(ctx, principal, abortPGResult(f, c, permit)) == nil {
					t.Fatal("expired lease accepted original callback")
				}
				return
			}
			if kind != "rejected-original" {
				if err == nil {
					t.Fatal("foreign/digest/tampered proof redeemed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r := abortPGResult(f, c, permit)
			r.Outcome = "rejected_no_effect"
			r.OriginalStatus = 409
			if err = f.store.RecordNativePreRegistrationAbortResult(ctx, principal, r); err != nil {
				t.Fatal(err)
			}
			if f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, abortPGRemoval(f), true) == nil {
				t.Fatal("409 relabelled applied")
			}
			if f.store.ArchiveNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID) == nil {
				t.Fatal("409 uncertainty archived as success")
			}
		})
	}
	for _, first := range []string{"registration", "abort"} {
		t.Run("actual-PG-lock-race-"+first+"-wins", func(t *testing.T) {
			f := abortPGSetup(t, false)
			blocker, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if err = lockMutationScope(ctx, blocker, f.policy.Metadata.Namespace, f.p); err != nil {
				t.Fatal(err)
			}
			key, _ := json.Marshal([]string{f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension})
			waiters := func(want int) {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					var n int
					err := f.db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid`, string(key)).Scan(&n)
					if err != nil {
						t.Fatal(err)
					}
					if n == want {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("real PG advisory waiter not reached")
			}
			register := func() error { _, err := f.ordinary.RegisterNativeLifetime(ctx, f.policy, f.intent, f.boot); return err }
			abort := func() error {
				_, _, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation)
				return err
			}
			one, two := register, abort
			if first == "abort" {
				one, two = abort, register
			}
			a, b := make(chan error, 1), make(chan error, 1)
			go func() { a <- one() }()
			waiters(1)
			go func() { b <- two() }()
			waiters(2)
			if err = blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-a:
				if err != nil {
					t.Fatal("first serialized operation failed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("first transaction did not return")
			}
			select {
			case err = <-b:
				if err == nil {
					t.Fatal("losing registration/abort both committed")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("second transaction did not return")
			}
		})
	}
}

func TestCapacityNativePreRegistrationAbortCrossScopePostgres(t *testing.T) {
	ctx := context.Background()
	for _, first := range []string{"registration", "abort"} {
		t.Run(first+"-wins-globalUID", func(t *testing.T) {
			one, two := abortPGSetup(t, false), abortPGSetup(t, false)
			uid := one.binding.PodUID
			two.binding.PodUID = uid
			two.observation.PodUID = uid
			two.boot.Observation.PodUID = uid
			two.boot.Admission.PodUID = uid
			workflow := abortPGCreate(t, two.db, two.policy.Metadata.Namespace, "workflow", "abort-human", abortPGWorkflow(two.binding))
			two.store.WorkflowID = workflow.ID
			blocker, err := one.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if err = nativeAbortUIDLock(ctx, blocker, uid); err != nil {
				t.Fatal(err)
			}
			key, _ := json.Marshal([]string{"capacity-bound-native-uid", uid})
			wait := func(want int) {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					var n int
					if err := one.db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid`, string(key)).Scan(&n); err != nil {
						t.Fatal(err)
					}
					if n == want {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("global UID lock waiter not observed")
			}
			register := func(f abortPGFixture) error {
				_, err := f.ordinary.RegisterNativeLifetime(ctx, f.policy, f.intent, f.boot)
				return err
			}
			abort := func(f abortPGFixture) error {
				_, _, err := f.store.IssueNativePreRegistrationAbort(ctx, f.policy, f.intent, f.binding, f.observation)
				return err
			}
			a, b := make(chan error, 1), make(chan error, 1)
			if first == "registration" {
				go func() { a <- register(one) }()
			} else {
				go func() { a <- abort(one) }()
			}
			wait(1)
			if first == "registration" {
				go func() { b <- abort(two) }()
			} else {
				go func() { b <- register(two) }()
			}
			wait(2)
			if err = blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-a:
				if err != nil {
					t.Fatal("first global UID writer failed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("first global UID writer stuck")
			}
			select {
			case err = <-b:
				if err == nil {
					t.Fatal("foreign scopes both acquired one Pod UID")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("second global UID writer stuck")
			}
		})
	}
}

func TestCapacityNativePreRegistrationAbortConfirmedCustodyPostgres(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"missing-result-row", "missing-caller-join", "wrong-native-readback", "wrong-original-result", "wrong-archive-digest"} {
		t.Run(kind, func(t *testing.T) {
			f := abortPGSetup(t, false)
			c, token := abortPGIssue(t, f)
			permit := model.CapacityNativeAuthorityPermit{AttemptID: uuid.New()}
			if kind != "missing-result-row" {
				var err error
				permit, err = f.store.RedeemNativePreRegistrationAbort(ctx, f.binding.AdapterPrincipalID, abortPGRedeem(f, c, token))
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.RecordNativePreRegistrationAbortResult(ctx, f.binding.AdapterPrincipalID, abortPGResult(f, c, permit)); err != nil {
					t.Fatal(err)
				}
				if kind != "missing-caller-join" {
					if err = f.store.ConfirmNativePreRegistrationAbort(ctx, f.policy, f.intent, c.CommandID, abortPGRemoval(f), true); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch kind {
			case "missing-result-row", "missing-caller-join":
				// A forged mutable HOT flag cannot invent the absent original row
				// or caller join. Never disable the real immutable ACK triggers.
				r := abortPGResult(f, c, permit)
				r.ReturnNonce = ""
				result, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				readback, err := json.Marshal(abortPGRemoval(f))
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				c.State, c.AttemptID, c.RedeemedBy = "confirmed", permit.AttemptID, f.binding.AdapterPrincipalID
				c.NativeReadback, c.OriginalResult, c.OriginalResultSHA256, c.CallerReturnObservedAt = readback, result, nativeCanonicalArchiveSHA(result), &now
				body, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.db.Exec(`UPDATE public.capacity_native_commands SET state='confirmed',command_record=$2 WHERE id=$1`, c.CommandID, body); err != nil {
					t.Fatal(err)
				}
			case "wrong-archive-digest":
				var body []byte
				if f.db.QueryRow(`SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&body) != nil {
					t.Fatal("confirmed fixture body missing")
				}
				if _, err := f.db.Exec(`INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)VALUES($1,$2,$3)`, c.CommandID, strings.Repeat("0", 64), body); err != nil {
					t.Fatal(err)
				}
				if _, err := f.db.Exec(`DELETE FROM public.capacity_native_commands WHERE id=$1`, c.CommandID); err != nil {
					t.Fatal(err)
				}
			case "wrong-native-readback", "wrong-original-result":
				query := `UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{native_readback,observation,protected}','true') WHERE id=$1`
				if kind == "wrong-original-result" {
					query = `UPDATE public.capacity_native_commands SET command_record=jsonb_set(command_record,'{original_result,one_send}','false') WHERE id=$1`
				}
				if _, err := f.db.Exec(query, c.CommandID); err != nil {
					t.Fatal(err)
				}
			}
			if _, present, err := f.store.LoadNativePreRegistrationAbort(ctx, f.policy, f.binding.PodUID); !present || err == nil {
				t.Fatal("unproven confirmed body accepted as settled")
			}
			if _, err := f.ordinary.RegisterNativeLifetime(ctx, f.policy, f.intent, f.boot); err == nil {
				t.Fatal("confirmed custody loss cleared permanent deny")
			}
		})
	}
}
