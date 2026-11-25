package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type migratedOriginPG struct {
	db              *sql.DB
	store           CapacityStore
	origin, current model.Manifest
	op, p           model.CapacityPolicySpec
	intent          model.CapacityIntent
	b               model.CapacityMigratedNativeOriginBinding
	e               model.CapacityMigratedNativeTargetEvidence
	quarantine      *abortQuarantinePGFixture
}

func migratedOriginPGWorkflow(b model.CapacityMigratedNativeOriginBinding) any {
	return map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": map[string]any{"rbac": map[string]string{"namespace": "fixed", "name": "named-human"}}, "steps": []any{map[string]any{"id": "retire-once", "timeout_seconds": 90, "retry": map[string]int{"max_attempts": 1}, "use": map[string]string{"kind": "yggdrasil", "operation": capacity.RetireMigratedNativeOrigin}, "with": map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
}

func migratedOriginPGEvidence(p model.CapacityPolicySpec, namespaceUID string) model.CapacityMigratedNativeTargetEvidence {
	now := time.Now().UTC()
	s := p.AssessmentBinding.Snapshot
	g := model.CurrentBirthGuardObservation{Operation: capacity.ObserveCurrentBirthGuard, Status: "observed", BindingName: p.HPAExecutionBinding.BirthGuardBinding, BindingSHA256: p.HPAExecutionBinding.BirthGuardSHA256, Namespace: s.Namespace, WorkloadUID: s.WorkloadUID, ObservedAt: now}
	for _, kind := range []string{"Namespace", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ConfigMap", "Service", "ServiceAccount", "Endpoints", "Deployment", "Deployment", "ReplicaSet", "Pod", "Pod"} {
		ns := s.Namespace
		if kind == "Namespace" || kind == "MutatingWebhookConfiguration" || kind == "ValidatingWebhookConfiguration" {
			ns = ""
		}
		id, name := uuid.NewString(), kind+uuid.NewString()
		if kind == "Namespace" {
			id, name = namespaceUID, s.Namespace
		}
		if kind == "Deployment" && len(g.Resources) == 7 {
			id, name = s.WorkloadUID, s.WorkloadName
		}
		g.Resources = append(g.Resources, model.BirthGuardNativeIdentity{Kind: kind, Namespace: ns, Name: name, UID: id, ResourceVersion: "1", SHA256: strings.Repeat("c", 64)})
	}
	g.Resources[7].ResourceVersion = "40"
	for _, pod := range g.Resources[10:] {
		g.Processes = append(g.Processes, model.BirthGuardProcess{PodName: pod.Name, PodUID: pod.UID, ResourceVersion: pod.ResourceVersion, ReplicaSetUID: g.Resources[9].UID, NodeName: "target-node", ContainerName: "guard", ContainerID: "containerd://" + uuid.NewString(), ImageDigest: "sha256:" + strings.Repeat("d", 64), StartedAt: now.Add(-time.Minute)})
	}
	h := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: s.Namespace, HPAName: s.HPAName, HPAUID: s.HPAUID, ResourceVersion: "30", WorkloadName: s.WorkloadName, WorkloadUID: s.WorkloadUID, WorkloadResourceVersion: "40", Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "existing-target-envelope", MinReplicas: 4, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: now.Format(time.RFC3339Nano)}}
	c := model.AdapterCapacityPodAdmissionCandidatesResponse{Operation: capacity.ObserveNativePodAdmissionCandidates, Status: "observed", BindingName: p.HPAExecutionBinding.PodTerminationBinding, Namespace: s.Namespace, WorkloadUID: s.WorkloadUID, WorkloadResourceVersion: "40", ListResourceVersion: "50", Complete: true, ObservedAt: now}
	return model.CapacityMigratedNativeTargetEvidence{BirthGuard: g, HPA: h, Candidates: c}
}

// Produce the old checkpoint through the actual register/protect/redeem/project/
// admit APIs. A later valid ACK refresh is intentionally not the command ACK.
func migratedOriginPGSetup(t *testing.T, withQuarantine ...bool) migratedOriginPG {
	t.Helper()
	ctx := context.Background()
	var db *sql.DB
	var store CapacityStore
	var origin model.Manifest
	var op model.CapacityPolicySpec
	var intent model.CapacityIntent
	var q *abortQuarantinePGFixture
	if len(withQuarantine) > 0 && withQuarantine[0] {
		retained := abortQuarantinePGSetup(t, nil)
		abortQuarantinePGClassify(t, retained)
		q = &retained
		db, store, origin, op = retained.db, retained.ordinary, retained.policy, retained.p
		frame := migratedOriginPGEvidence(op, uuid.NewString()).HPA
		snapshot, e := capacity.BoundHPASnapshot(op, frame, time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		var err error
		intent, err = store.AcquireNativeLifetimeExecution(ctx, origin, retained.intent, model.CapacityAssessment{Snapshot: snapshot})
		if err != nil {
			t.Fatal("ordinary admission owner could not retain an already valid quarantine", err)
		}
	} else {
		db, store, origin, op, intent = nativeLifetimePostgresFixture(t)
	}
	boot := nativeLifetimeBoot(op)
	cp, challenge := nativeLifetimeProtect(t, store, origin, op, intent, boot)
	actual := boot
	actual.Observation.PodResourceVersion = "11"
	actual.Admission.State = "roots_open"
	actual.Admission.Challenge = &challenge
	actual.Admission.ChallengeSHA256 = cp.OriginChallengeSHA256
	actual.Admission.ObservedAt = time.Now().UTC()
	actual.Observation.ObservedAt = actual.Admission.ObservedAt
	if err := store.AcknowledgeNativeProjection(ctx, origin, intent, cp.PodUID, actual); err != nil {
		t.Fatal(err)
	}
	no := false
	req := model.AdapterEnsureCapacityPodDrainRequest{BindingName: op.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodResourceVersion: "11", ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "admit", DryRun: &no}
	raw, _ := json.Marshal(req)
	command, token, err := store.IssueNativeCommand(ctx, origin, intent, capacity.EnsureNativePodDrain, cp.PodUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	nativeLifetimeRedeem(t, store, op, command, token)
	actual.Observation.AdmissionReady = true
	actual.Observation.PodResourceVersion = "12"
	actual.Admission.ObservedAt = time.Now().UTC()
	actual.Observation.ObservedAt = actual.Admission.ObservedAt
	if err = store.ConfirmNativeCommand(ctx, origin, intent, command.CommandID, actual); err != nil {
		t.Fatal(err)
	}
	actual.Observation.PodResourceVersion = "13"
	actual.Admission.ObservedAt = time.Now().UTC()
	actual.Observation.ObservedAt = actual.Admission.ObservedAt
	if err = store.AcknowledgeNativeProjection(ctx, origin, intent, cp.PodUID, actual); err != nil {
		t.Fatal(err)
	}
	if err = store.CompleteNativeReservationDecision(ctx, origin, intent); err != nil {
		t.Fatal(err)
	}
	var originalBody []byte
	if err = db.QueryRow(`SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1`, cp.PodUID).Scan(&originalBody); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(originalBody, &cp); err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(origin.Spec, &p) != nil {
		t.Fatal("origin")
	}
	typ := abortPGCreate(t, db, origin.Metadata.Namespace, "integration_type", "native-type", map[string]any{"provider": "kubernetes", "revision": "target"})
	instance := abortPGCreate(t, db, origin.Metadata.Namespace, "integration_instance", "native-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	p.AssessmentBinding.Snapshot.Adapter = adapter
	for i := range p.AssessmentBinding.Signals {
		p.AssessmentBinding.Signals[i].Adapter = adapter
	}
	p.AssessmentBinding.Snapshot.HPAUID = uuid.NewString()
	p.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString()
	p.HPAExecutionBinding.ImageDigest = "sha256:" + strings.Repeat("e", 64)
	current := abortPGCreate(t, db, origin.Metadata.Namespace, "capacity_policy", origin.Metadata.Name, p)
	zero := int32(0)
	operator := "collaborator:" + uuid.NewString()
	b := model.CapacityMigratedNativeOriginBinding{Schema: capacity.MigratedNativeOriginSchema, Confirmation: "RETIRE MIGRATED ORIGIN WITHOUT SDK WITNESS", OperatorID: operator, PolicyID: current.ID.String(), PolicyChecksum: current.Checksum, OriginPolicyID: origin.ID.String(), OriginPolicyChecksum: origin.Checksum, PodUID: cp.PodUID, PodName: cp.PodName, WorkloadUID: cp.WorkloadUID, ContainerName: cp.ContainerName, ImageDigest: cp.ImageDigest, OriginGeneration: cp.IntentGeneration, CheckpointSHA256: nativeCanonicalArchiveSHA(originalBody), ExpectedIntentGeneration: intent.Generation, ExpectedIntentFencingToken: intent.FencingToken, TargetNamespaceUID: uuid.NewString(), Source: model.CapacityMigratedSourceFence{Class: capacity.MigratedSourceFenceClass, MeasuredBy: operator, ObservedAt: time.Now().UTC(), NamespaceUID: uuid.NewString(), WorkloadUID: cp.WorkloadUID, ResourceVersion: "70", Generation: 1, ObservedGeneration: 1, DesiredReplicas: &zero, CurrentReplicas: &zero, ReadyReplicas: &zero, AvailableReplicas: &zero, UnavailableReplicas: &zero, CompletePodCensus: true, OwnedPods: &zero, UnattributedMatchingPods: &zero, OldUIDAbsent: true, OldNameHTTP404: true, ReopeningFenced: true, EvidenceSHA256: strings.Repeat("a", 64), FenceEvidenceSHA256: strings.Repeat("b", 64)}}
	rows, err := db.Query(`SELECT command_record FROM public.capacity_native_commands WHERE subject_uid=$1`, cp.PodUID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var body []byte
		var c model.CapacityNativeCommand
		if rows.Scan(&body) != nil || json.Unmarshal(body, &c) != nil {
			t.Fatal("command")
		}
		switch c.Phase {
		case "protect":
			b.ProtectCommandID, b.ProtectCommandSHA256 = c.CommandID.String(), nativeCanonicalArchiveSHA(body)
		case "admit":
			b.AdmitCommandID, b.AdmitCommandSHA256 = c.CommandID.String(), nativeCanonicalArchiveSHA(body)
			if nativeCanonicalArchiveSHA(c.NativeReadback) == nativeCanonicalArchiveSHA(cp.RootAcknowledgement) {
				t.Fatal("fixture did not retain distinct original and refreshed ACKs")
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	wf := abortPGCreate(t, db, current.Metadata.Namespace, "workflow", "retire-migrated-human", migratedOriginPGWorkflow(b))
	admin := store
	admin.AdmissionOnly = false
	admin.WorkflowID = wf.ID
	admin.ExecutorID = uuid.NewString()
	admin.ExecutorPowerOperator = operator
	f := migratedOriginPG{db: db, store: admin, origin: origin, current: current, op: op, p: p, intent: intent, b: b, e: migratedOriginPGEvidence(p, b.TargetNamespaceUID)}
	f.quarantine = q
	// Teardown alone uses a privileged CI transaction to remove this fixture's
	// immutable receipt before the shared fixture deletes its manifest namespace.
	// All assertions exercise normal enabled triggers; this never runs in product.
	t.Cleanup(func() {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Error(e)
			return
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`SET LOCAL session_replication_role=replica`); e != nil {
			t.Error(e)
			return
		}
		if _, e = tx.Exec(`DELETE FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1`, b.PodUID); e != nil {
			t.Error(e)
			return
		}
		if e = tx.Commit(); e != nil {
			t.Error(e)
		}
	})
	return f
}

func migratedOriginPGSnapshot(t *testing.T, f migratedOriginPG) [][]byte {
	t.Helper()
	out := [][]byte{}
	for _, q := range []string{`SELECT row_to_json(x) FROM public.capacity_native_lifetimes x WHERE pod_uid=$1`, `SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.capacity_native_commands x WHERE subject_uid=$1`, `SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.capacity_native_command_identities x WHERE subject_uid=$1`, `SELECT row_to_json(x) FROM public.capacity_intents x WHERE namespace=$1`} {
		var raw []byte
		arg := f.b.PodUID
		if strings.Contains(q, "capacity_intents") {
			arg = f.current.Metadata.Namespace
		}
		if err := f.db.QueryRow(q, arg).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

func migratedOriginPGUnchanged(t *testing.T, f migratedOriginPG, before [][]byte) {
	t.Helper()
	after := migratedOriginPGSnapshot(t, f)
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("original immutable custody row %d changed", i)
		}
	}
}

func TestCapacityNativeMigratedOriginRetirementPostgres(t *testing.T) {
	f := migratedOriginPGSetup(t)
	ctx := context.Background()
	before := migratedOriginPGSnapshot(t, f)
	if _, _, err := f.store.NativeLedger(ctx, f.current, f.intent); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("foreign admitted checkpoint was ignored without an administrative receipt", err)
	}
	if err := f.store.RetireMigratedNativeOrigin(ctx, f.current, f.b, f.e); err != nil {
		t.Fatal("exact administrative retirement refused", err)
	}
	migratedOriginPGUnchanged(t, f, before)
	if ok, err := f.store.MigratedNativeOriginRetired(ctx, f.current, f.b.PodUID); err != nil || !ok {
		t.Fatal("stored administrative custody did not validate", err)
	}
	commands, cps, err := f.store.NativeLedger(ctx, f.current, f.intent)
	if err != nil || len(commands) != 2 || len(cps) != 0 {
		t.Fatal("ordinary ledger did not separate retired origin from active Target", err)
	}
	for _, c := range commands {
		if c.State != "confirmed" {
			t.Fatal("original command was settled or changed")
		}
	}
	var body []byte
	if err = f.db.QueryRow(`SELECT retirement_record FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1`, f.b.PodUID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var r model.CapacityMigratedNativeOriginRetirement
	if json.Unmarshal(body, &r) != nil {
		t.Fatal("record")
	}
	var cp model.CapacityNativePodCheckpoint
	if json.Unmarshal(r.Checkpoint, &cp) != nil || cp.State != "admitted" || cp.ConfirmedAt != nil || len(cp.NativeTerminationReceipt) != 0 || len(r.Commands) != 2 {
		t.Fatal("administrative receipt invented a native SDK completion")
	}
	for _, q := range []string{`UPDATE public.capacity_native_migrated_origin_retirements SET record_sha256=repeat('0',64) WHERE subject_uid=$1`, `DELETE FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1`} {
		if _, err = f.db.Exec(q, f.b.PodUID); err == nil {
			t.Fatal("immutable administrative history changed")
		}
	}
	if err = f.store.RetireMigratedNativeOrigin(ctx, f.current, f.b, f.e); err == nil {
		t.Fatal("duplicate administration replayed")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = guardMigratedNativeOriginTx(ctx, tx, f.b.PodUID)
	tx.Rollback()
	if !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("old UID lost permanent deny", err)
	}
	// A new Target process still follows ordinary register/protect/project/admit.
	admission := f.store
	admission.AdmissionOnly = true
	wf, err := ResolveManifest(ctx, f.db, "workflow", f.p.HPAExecutionBinding.AdmissionWorkflow.Namespace, f.p.HPAExecutionBinding.AdmissionWorkflow.Name, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	admission.WorkflowID = wf.ID
	next, err := admission.AcquireNativeAdmissionExecution(ctx, f.current, f.e.HPA)
	if err != nil {
		t.Fatal(err)
	}
	boot := nativeLifetimeBoot(f.p)
	registered, err := admission.RegisterNativeLifetime(ctx, f.current, next, boot)
	if err != nil || registered.PodUID == f.b.PodUID {
		t.Fatal("ordinary distinct Target registration remained blocked", err)
	}
}

func TestCapacityNativeMigratedOriginRefusalsPostgres(t *testing.T) {
	for _, name := range []string{"missing_zero", "nonzero_source", "old_uid_present", "incomplete_source", "source_not_fenced", "stale_source", "same_namespace_realm", "stale_target", "target_graph_changed", "target_workload_version_changed", "incomplete_candidates", "wrong_operator", "wrong_fence", "live_lease", "uncertain_subject", "lost_origin", "changed_checkpoint", "current_spec_tamper", "changed_current_scope"} {
		t.Run(name, func(t *testing.T) {
			f := migratedOriginPGSetup(t)
			ctx := context.Background()
			before := migratedOriginPGSnapshot(t, f)
			switch name {
			case "missing_zero":
				f.b.Source.OwnedPods = nil
			case "nonzero_source":
				one := int32(1)
				f.b.Source.DesiredReplicas = &one
			case "old_uid_present":
				f.b.Source.OldUIDAbsent = false
			case "incomplete_source":
				f.b.Source.CompletePodCensus = false
			case "source_not_fenced":
				f.b.Source.ReopeningFenced = false
			case "stale_source":
				f.b.Source.ObservedAt = time.Now().Add(-time.Hour)
			case "same_namespace_realm":
				f.b.Source.NamespaceUID = f.b.TargetNamespaceUID
			case "stale_target":
				f.e.BirthGuard.ObservedAt = time.Now().Add(-time.Hour)
			case "target_graph_changed":
				f.e.BirthGuard.WorkloadUID = uuid.NewString()
			case "target_workload_version_changed":
				f.e.BirthGuard.Resources[7].ResourceVersion = "41"
			case "incomplete_candidates":
				f.e.Candidates.Complete = false
			case "wrong_operator":
				f.store.ExecutorPowerOperator = "another-human"
			case "wrong_fence":
				f.b.ExpectedIntentFencingToken++
			case "live_lease":
				if _, err := f.db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb((clock_timestamp()+interval '1 minute')::text)) WHERE namespace=$1`, f.current.Metadata.Namespace); err != nil {
					t.Fatal(err)
				}
				before = migratedOriginPGSnapshot(t, f)
			case "uncertain_subject":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_commands SET state='uncertain',command_record=jsonb_set(command_record,'{state}','"uncertain"') WHERE id=$1`, f.b.AdmitCommandID); err != nil {
					t.Fatal(err)
				}
				before = migratedOriginPGSnapshot(t, f)
			case "lost_origin":
				if _, err := f.db.Exec(`DELETE FROM public.manifests WHERE id=$1`, f.origin.ID); err != nil {
					t.Fatal(err)
				}
			case "changed_checkpoint":
				if _, err := f.db.Exec(`UPDATE public.capacity_native_lifetimes SET checkpoint_record=jsonb_set(checkpoint_record,'{process_nonce}',to_jsonb($2::text)) WHERE pod_uid=$1`, f.b.PodUID, uuid.NewString()); err != nil {
					t.Fatal(err)
				}
				before = migratedOriginPGSnapshot(t, f)
			case "current_spec_tamper":
				if _, err := f.db.Exec(`UPDATE public.manifests SET spec=jsonb_set(spec,'{assessment_binding,snapshot,workload_uid}',to_jsonb($2::text)) WHERE id=$1`, f.current.ID, uuid.NewString()); err != nil {
					t.Fatal(err)
				}
			case "changed_current_scope":
				f.p.AssessmentBinding.Snapshot.WorkloadName = "different-workload"
				f.current = abortPGCreate(t, f.db, f.current.Metadata.Namespace, "capacity_policy", f.current.Metadata.Name, f.p)
				f.b.PolicyID, f.b.PolicyChecksum = f.current.ID.String(), f.current.Checksum
			}
			// Keep the workflow literal current so failures reach the real guard
			// being exercised rather than a stale manifest-binding mismatch.
			wf := abortPGCreate(t, f.db, f.current.Metadata.Namespace, "workflow", "retire-migrated-human", migratedOriginPGWorkflow(f.b))
			f.store.WorkflowID = wf.ID
			if err := f.store.RetireMigratedNativeOrigin(ctx, f.current, f.b, f.e); err == nil {
				t.Fatal("incomplete/mismatched administrative evidence accepted")
			}
			var count int
			if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_migrated_origin_retirements WHERE subject_uid=$1`, f.b.PodUID).Scan(&count); err != nil || count != 0 {
				t.Fatal("refusal left an administrative receipt", err)
			}
			migratedOriginPGUnchanged(t, f, before)
		})
	}
}

func TestCapacityNativeMigratedOriginConcurrencyPostgres(t *testing.T) {
	f := migratedOriginPGSetup(t)
	before := migratedOriginPGSnapshot(t, f)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.store.RetireMigratedNativeOrigin(context.Background(), f.current, f.b, f.e) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("administrative insert winners=%d", wins.Load())
	}
	migratedOriginPGUnchanged(t, f, before)
}

func TestCapacityNativeMigratedOriginQuarantineCoexistencePostgres(t *testing.T) {
	f := migratedOriginPGSetup(t, true)
	ctx := context.Background()
	if f.quarantine == nil {
		t.Fatal("real retained quarantine missing")
	}
	before := migratedOriginPGSnapshot(t, f)
	qbefore := abortQuarantineRevisionSnapshot(t, *f.quarantine)
	want := model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1}
	if got, err := f.store.NativeUnsettledCounts(ctx, f.current); err != nil || got != want {
		t.Fatal("valid original quarantine did not survive current Target revision", got, err)
	}
	if err := f.store.RetireMigratedNativeOrigin(ctx, f.current, f.b, f.e); err != nil {
		t.Fatal("separate admitted origin could not retain valid raw uncertainty", err)
	}
	if got, err := f.store.NativeUnsettledCounts(ctx, f.current); err != nil || got != want {
		t.Fatal("retirement changed original uncertainty classification", got, err)
	}
	commands, cps, err := f.store.NativeLedger(ctx, f.current, f.intent)
	if err != nil || len(commands) != 3 || len(cps) != 0 {
		t.Fatal("legacy uncertainty and retired lifetime were not kept distinct", err)
	}
	var uncertain int
	for _, c := range commands {
		if c.State == "uncertain" {
			uncertain++
			if ok, e := f.store.NativeAbortCommandQuarantined(ctx, f.current, c.CommandID); e != nil || !ok {
				t.Fatal("original uncertain command lost real quarantine validation", e)
			}
		}
	}
	if uncertain != 1 {
		t.Fatal("retirement settled or hid uncertainty")
	}
	migratedOriginPGUnchanged(t, f, before)
	abortQuarantineRevisionUnchanged(t, *f.quarantine, qbefore)
}

func TestCapacityNativeMigratedOriginCorruptReceiptPostgres(t *testing.T) {
	f := migratedOriginPGSetup(t)
	ctx := context.Background()
	before := migratedOriginPGSnapshot(t, f)
	// A malformed retained row never converts presence into new UID authority.
	if _, err := f.db.Exec(`INSERT INTO public.capacity_native_migrated_origin_retirements(subject_uid,namespace,environment,domain,dimension,origin_policy_id,checkpoint_sha256,record_sha256,retirement_record)VALUES($1,$2,$3,$4,$5,$6,$7,$8,'{}')`, f.b.PodUID, f.current.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.origin.ID, f.b.CheckpointSHA256, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.store.MigratedNativeOriginRetired(ctx, f.current, f.b.PodUID); err == nil || ok {
		t.Fatal("corrupt receipt became a valid exclusion")
	}
	if _, _, err := f.store.NativeLedger(ctx, f.current, f.intent); err == nil {
		t.Fatal("corrupt receipt disappeared from active obligations")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = guardMigratedNativeOriginTx(ctx, tx, f.b.PodUID)
	tx.Rollback()
	if !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("corrupt receipt cleared permanent global UID deny", err)
	}
	migratedOriginPGUnchanged(t, f, before)
}

func TestCapacityNativeMigratedOriginMigration112Postgres(t *testing.T) {
	f := migratedOriginPGSetup(t)
	before := migratedOriginPGSnapshot(t, f)
	raw, err := os.ReadFile("../db/migrations/00112_capacity_native_migrated_origin_retirements.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(raw), "-- +goose Down")
	if len(parts) != 2 {
		t.Fatal("one original migration Down required")
	}
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(parts[1]); err != nil {
		tx.Rollback()
		t.Fatal("unused administrative schema could not roll back", err)
	}
	var absent bool
	if err = tx.QueryRow(`SELECT to_regclass('public.capacity_native_migrated_origin_retirements') IS NULL`).Scan(&absent); err != nil || !absent {
		tx.Rollback()
		t.Fatal("unused table not dropped in original transaction", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RetireMigratedNativeOrigin(context.Background(), f.current, f.b, f.e); err != nil {
		t.Fatal(err)
	}
	tx, err = f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(parts[1])
	tx.Rollback()
	if err == nil {
		t.Fatal("used immutable UID deny allowed rollback")
	}
	if ok, e := f.store.MigratedNativeOriginRetired(context.Background(), f.current, f.b.PodUID); e != nil || !ok {
		t.Fatal("failed Down lost permanent history", e)
	}
	migratedOriginPGUnchanged(t, f, before)
}
