package message

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type capacityNotifySource struct {
	Source         string                              `json:"source_commit"`
	RecordSHA      string                              `json:"record_sha256"`
	BodySHA        string                              `json:"body_sha256"`
	RecipientSHA   string                              `json:"recipient_sha256"`
	RecipientCount int                                 `json:"recipient_count"`
	Reply          model.CapacityBusinessCreationReply `json:"reply"`
	Kind           string                              `json:"fixture_kind"`
}

func capacityOriginalNotifySource(t *testing.T) capacityNotifySource {
	t.Helper()
	var out capacityNotifySource
	binary, sourceDir, pin := os.Getenv("CAPACITY_NOTIFY_FIXTURE_BINARY"), os.Getenv("CAPACITY_NOTIFY_FIXTURE_SOURCE_DIR"), os.Getenv("CAPACITY_NOTIFY_SOURCE_COMMIT")
	if binary == "" || sourceDir == "" || len(pin) != 40 || strings.Trim(pin, "0123456789abcdef") != "" {
		t.Fatal("reviewed committed Notify source and compiled fixture required")
	}
	path := filepath.Join(t.TempDir(), "original-notify-source.json")
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.v", "-test.count=1", "-test.run=^TestNativeCapacityCreationCanaryFixtureProducer$")
	command.Dir = filepath.Join(sourceDir, "controllers", "message")
	command.Env = append(os.Environ(), "DAKASA_NATIVE_REMOTE_QUALIFICATION=true", "CAPACITY_NATIVE_OUTPUT_FILE="+path)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if command.Start() != nil || command.Process == nil || command.Process.Pid < 1 {
		t.Fatal("actual original Notify child did not Start")
	}
	pid := command.Process.Pid
	waitErr := command.Wait()
	if waitErr != nil || command.ProcessState == nil || !command.ProcessState.Success() || nativeAdapterContext(ctx) != nil || output.Len() > 1<<20 || !strings.Contains(output.String(), "--- PASS: TestNativeCapacityCreationCanaryFixtureProducer (") || strings.Contains(output.String(), "--- FAIL:") || strings.Contains(output.String(), "--- SKIP:") {
		t.Fatal("actual original Notify Wait/mandatory root unresolved", waitErr)
	}
	for _, name := range []string{
		"original_handler_same_xid_two_states_and_raw_wire",
		"duplicate_keeps_original_witness_without_publish",
		"capture_mismatch_rolls_back_and_foreign_process_holds",
		"capture_mismatch_rolls_back_and_foreign_process_holds/body",
		"capture_mismatch_rolls_back_and_foreign_process_holds/recipients",
		"capture_mismatch_rolls_back_and_foreign_process_holds/process",
		"unauthorized_route_reads_no_native_private_result",
		"immutable_hashed_witness_keeps_no_user_id_or_message_copy",
		"original_actor_anonymization_erases_hash_without_recipient_deletion",
		"original_recipient_erasure_removes_linkable_hashes",
	} {
		if !strings.Contains(output.String(), "--- PASS: TestNativeCapacityCreationCanaryFixtureProducer/"+name+" (") {
			t.Fatal("original Notify child qualification case did not complete", name)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || capacity.DecodeBusinessJSON(raw, &out) != nil || out.Source != pin || out.Kind != "compiled_original_handler_native_postgres_not_kubernetes_or_main" {
		t.Fatal("original exact source output refused", err)
	}
	t.Logf("original Notify source=%s PID=%d Start/Wait succeeded, stdout_sha256=%s; scope=compiled owning handler+native PostgreSQL, no physical Pod/main/caller-return authority", pin, pid, capacity.BusinessCreationSHA256(output.Bytes()))
	return out
}

// The owning Notify binary produces actual original native SQL/witness bytes.
// Pod replies here are explicit protocol fixtures, not native Kind receipts.
// They exercise the protected dispatcher and its refusal fences in real PG/TLS.
func TestCapacityMutationOriginalBusinessCanaryPostgres(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("strict remote PostgreSQL sector gate required")
		}
		t.Skip("owning remote PostgreSQL sector gate")
	}
	source := capacityOriginalNotifySource(t)
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := newCapacityInvocationContext(t.Context())
	ns := "business-canary-" + uuid.NewString()
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Cleanup(func() {
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "managed_secrets", "manifests"} {
			if _, err := db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	frame := source.Reply.PreparationBefore
	if frame.Challenge == nil {
		t.Fatal("actual SDK fixture origin absent")
	}
	start := frame.Challenge.IssuedAt.Add(-time.Second)
	pod := model.NativeTerminationObservation{BindingName: "notify-original", Namespace: frame.Namespace, PodName: frame.PodName, PodUID: frame.PodUID, PodResourceVersion: "10", PodGeneration: 1, WorkloadUID: frame.Challenge.WorkloadUID, WorkloadResourceVersion: "20", ContainerName: "notify", ContainerID: "containerd://protocol-fixture", ImageID: "fixture@" + frame.ImageDigest, ImageDigest: frame.ImageDigest, RestartCount: 0, ContainerState: "running", StartedAt: &start, Protected: true, AdmissionReady: true, State: "running", Reason: "protocol_fixture_only", ObservedAt: time.Now().UTC()}
	typeSpec := model.IntegrationTypeManifestSpec{Provider: "kubernetes", Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}, TimeoutSeconds: 65}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{}}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}}, ResourceTypes: []model.IntegrationResourceType{{Name: "object", CanonicalPrefix: "thirdparty.kubernetes.object", IdentityTemplate: "object.{id}", DefaultActions: []string{capacity.ObserveNativePodAdmission}}}, ActionCatalog: []model.IntegrationActionDefinition{{Name: capacity.ObserveNativePodAdmission, ResourceTypes: []string{"object"}, Idempotent: true}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.kubernetes.object"}}
	if manifest.ValidateIntegrationTypeSpec(typeSpec) != nil {
		t.Fatal("closed protocol fixture catalog invalid")
	}
	var reads, canaryReads, writes atomic.Int32
	var mode atomic.Value
	mode.Store("complete")
	var policy model.Manifest
	var initialIntent []byte
	canary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != capacity.BusinessCreationPath || r.Header.Get("X-Capacity-Canary-Read-Key") != strings.Repeat("r", 32) {
			writes.Add(1)
			w.WriteHeader(401)
			return
		}
		canaryReads.Add(1)
		if mode.Load().(string) == "epoch" {
			if _, err := db.ExecContext(r.Context(), `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{fencing_token}',to_jsonb((intent->>'fencing_token')::bigint+1)) WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
		reply := source.Reply
		if mode.Load().(string) == "foreign_consumer" {
			reply.PreparationAfter.ProcessNonce = uuid.NewString()
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(canary.Close)
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/describe" {
			raw, _ := json.Marshal(typeSpec)
			var describe model.AdapterDescribeResponse
			_ = json.Unmarshal(raw, &describe)
			_ = json.NewEncoder(w).Encode(describe)
			return
		}
		var request model.AdapterExecuteIntegrationRequest
		if r.Method != "POST" || r.URL.Path != "/execute" || json.NewDecoder(r.Body).Decode(&request) != nil || request.Operation != capacity.ObserveNativePodAdmission || request.Capability != request.Operation || len(request.Auth) != 0 || len(request.Metadata) != 0 {
			writes.Add(1)
			w.WriteHeader(400)
			return
		}
		reads.Add(1)
		current := pod
		current.ObservedAt = time.Now().UTC()
		currentFrame := frame
		currentFrame.ObservedAt = current.ObservedAt
		_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: request.Operation, Capability: request.Capability, Status: "observed", Output: model.AdapterCapacityPodAdmissionResponse{Operation: request.Operation, Status: "observed", Observation: current, Admission: currentFrame, Metadata: map[string]any{}}})
	}))
	t.Cleanup(adapter.Close)
	create := func(id uuid.UUID, kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		checksum := capacity.BusinessCreationSHA256(raw)
		if _, e = db.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES($1,'yggdrasil.io/v1alpha1',$2,$3,$4,1,true,$5::jsonb,$6)`, id, kind, ns, name, raw, checksum); e != nil {
			t.Fatal(e)
		}
		m, e := repository.GetManifestByID(ctx, db, id)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	typ := create(uuid.New(), "integration_type", "native-pod", typeSpec)
	instance := create(uuid.New(), "integration_instance", "native-pod", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: map[string]any{"base_url": adapter.URL}})
	wf := create(uuid.New(), "workflow", "canary", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "capacity-rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "observe", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe_original_creation_canary"}}}})
	ref := manifestReferenceFromRecord(wf)
	binding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	var native struct {
		Database        string `json:"database"`
		DatabaseOID     string `json:"database_oid"`
		SystemID        string `json:"system_identifier"`
		WitnessOID      string `json:"witness_oid"`
		InboxOID        string `json:"inbox_oid"`
		NotificationOID string `json:"notification_oid"`
		StateOID        string `json:"state_oid"`
	}
	if json.Unmarshal(source.Reply.NativeRaw, &native) != nil {
		t.Fatal("original database projection absent")
	}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/native-notify", Owner: "canary-owner", Workflow: model.ManifestSelector{Namespace: ns, Name: "canary"}, Currency: "BRL", Floor: 1, Ceiling: 4, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixed/source", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "fixture", Provider: "protocol-fixture", Region: "fixture", MinUnits: 1, MaxUnits: 4, UnitMonthlyCostMinor: 1, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:no-capacity-claim"}}}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: binding, Namespace: frame.Namespace, HPAName: "fixture", HPAUID: uuid.NewString(), WorkloadName: "fixture", WorkloadUID: pod.WorkloadUID, Owner: p.Owner, Profile: "fixture", ProtectedFloor: 1, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: binding, BindingName: "pressure", BindingSHA256: strings.Repeat("c", 64)}}}
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "fixture", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: pod.BindingName, ContainerName: pod.ContainerName, ImageDigest: pod.ImageDigest, Lanes: []string{"original_sdk", "original_consumer"}, ProjectionDirectory: "/fixture/projection", AdmissionMode: "process_v2", AdmissionPort: 9080, AdmissionWorkflow: model.ManifestSelector{Namespace: ns, Name: "admit"}, BirthGuardBinding: "fixture", BirthGuardSHA256: strings.Repeat("d", 64)}
	p.BusinessCreationBinding = &model.CapacityBusinessCreationBinding{Name: "original", Adapter: binding, ReaderURL: canary.URL + capacity.BusinessCreationPath, ReadTokenRef: "secret://" + ns + "/canary/value", SourceCommit: source.Source, QuerySHA256: source.Reply.Query, RecordSHA256: source.RecordSHA, BodySHA256: source.BodySHA, RecipientSHA256: source.RecipientSHA, RecipientCount: 2, Database: native.Database, DatabaseOID: native.DatabaseOID, SystemID: native.SystemID, TableOIDs: []string{native.WitnessOID, native.InboxOID, native.NotificationOID, native.StateOID}, Pod: model.AdapterObserveCapacityPodAdmissionRequest{BindingName: pod.BindingName, PodName: pod.PodName, ExpectedPodUID: pod.PodUID, ExpectedPodGeneration: pod.PodGeneration, ExpectedContainerID: pod.ContainerID, ExpectedContainerStartedAt: start, ExpectedRestartCount: 0}}
	if capacity.ValidatePolicy(p) != nil || capacity.ValidateBusinessCreationBinding(p) != nil {
		t.Fatal("fixed source policy invalid")
	}
	policy = create(uuid.New(), "capacity_policy", "notify", p)
	if _, err = repository.UpsertManagedSecret(ctx, db, model.UpsertManagedSecretRequest{Namespace: ns, Name: "canary", Status: "active", Data: map[string]string{"value": strings.Repeat("r", 32)}}); err != nil {
		t.Fatal("native fixed secret setup unavailable", err)
	}
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor}
	v := .9
	assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: p.AssessmentBinding.Snapshot.HPAUID, WorkloadUID: pod.WorkloadUID, ResourceVersion: "1", WorkloadResourceVersion: "20", Owner: p.Owner, Profile: "fixture", Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "fixed/source", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	intent, err := store.Assess(ctx, policy, assessment)
	if err != nil {
		t.Fatal("actual original intent unavailable", err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, assessment)
	if err != nil {
		t.Fatal("actual original owning lease unavailable", err)
	}
	_, initialIntent, err = readCapacityBusinessIntent(ctx, db, policy, p)
	if err != nil {
		t.Fatal(err)
	}
	run := func(c context.Context, input map[string]any) model.WorkflowRunStepResult {
		return executeCapacityBusinessWorkflowStepWithClient(c, nil, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.observe_original_creation_canary"}, input, canary.Client())
	}
	input := func() map[string]any {
		return map[string]any{"policy": map[string]any{"namespace": ns, "name": "notify"}, "binding_name": "original"}
	}
	t.Run("original_creation_join_is_scoped_without_authority", func(t *testing.T) {
		result := run(ctx, input())
		if result.Status != "succeeded" || result.Metadata["native_creation_canary_observed"] != true || result.Metadata["original_caller_return_known"] != false || result.Metadata["useful_capacity_known"] != false {
			t.Fatalf("actual original creation join refused: %s", result.Error)
		}
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots"} {
			var n int
			if db.QueryRowContext(ctx, `SELECT count(*) FROM public.`+table+` WHERE namespace=$1`, ns).Scan(&n) != nil || n != 0 {
				t.Fatal("observer wrote native authority")
			}
		}
	})
	t.Run("actorless_caller_expectations_and_old_workflow_refuse", func(t *testing.T) {
		before := reads.Load() + canaryReads.Load()
		if run(context.Background(), input()).Status == "succeeded" {
			t.Fatal("actorless observer accepted")
		}
		for _, key := range []string{"url", "token", "body_sha256", "pod_uid", "healthy", "proof", "generation"} {
			value := input()
			value[key] = true
			if run(ctx, value).Status == "succeeded" {
				t.Fatal("caller authority accepted", key)
			}
		}
		wrong := ref
		wrong.ID = uuid.New()
		if executeCapacityBusinessWorkflowStepWithClient(ctx, nil, db, wrong, model.WorkflowRunStepResult{Operation: "capacity.observe_original_creation_canary"}, input(), canary.Client()).Status == "succeeded" || reads.Load()+canaryReads.Load() != before {
			t.Fatal("refused scope reached private sources")
		}
		legacy := executeCapacityWorkflowStep(ctx, db, ref, model.WorkflowRunStepResult{Operation: "capacity.advance"}, map[string]any{"policy": input()["policy"], "generation": intent.Generation, "fencing_token": intent.FencingToken, "lease_owner": intent.LeaseOwner, "phase": "prepared", "proof": model.CapacityTransitionProof{}})
		if legacy.Status == "succeeded" {
			t.Fatal("fixed business observer reopened legacy caller phase proof")
		}
	})
	t.Run("paused_catalog_precedes_private_hydration", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, instance.ID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, err := db.ExecContext(ctx, `UPDATE public.manifests SET active=true WHERE id=$1`, instance.ID)
			if err != nil {
				t.Error(err)
			}
		}()
		before := reads.Load() + canaryReads.Load()
		if run(ctx, input()).Status == "succeeded" || reads.Load()+canaryReads.Load() != before {
			t.Fatal("paused catalog read private source")
		}
	})
	t.Run("competing_consumer_and_changed_epoch_hold_without_replay", func(t *testing.T) {
		for _, variant := range []string{"foreign_consumer", "epoch"} {
			mode.Store(variant)
			if run(ctx, input()).Status == "succeeded" {
				t.Fatal("competing/original epoch accepted", variant)
			}
			if _, err := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, ns, initialIntent); err != nil {
				t.Fatal(err)
			}
		}
		mode.Store("complete")
		if writes.Load() != 0 {
			t.Fatal("observer republished or actuated")
		}
	})
	t.Run("expired_final_native_context_cannot_accept", func(t *testing.T) {
		expired, done := context.WithDeadline(ctx, time.Now().Add(-time.Second))
		defer done()
		before := reads.Load() + canaryReads.Load()
		if run(expired, input()).Status == "succeeded" || reads.Load()+canaryReads.Load() != before {
			t.Fatal("expired source owner reached private sources")
		}
	})
	t.Run("held_original_close_after_original_lease_expiry_refuses", func(t *testing.T) {
		lease := intent
		deadline := time.Now().Add(3 * time.Second)
		lease.LeaseExpiresAt = &deadline
		shortRaw, _ := json.Marshal(lease)
		if _, err := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, ns, shortRaw); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, ns, initialIntent); err != nil {
				t.Error(err)
			}
		}()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		client := *canary.Client()
		native := client.Transport
		client.Transport = nativeCanaryRoundTrip(func(r *http.Request) (*http.Response, error) {
			reply, err := native.RoundTrip(r)
			if reply != nil && reply.Body != nil {
				body := reply.Body
				reply.Body = &nativeCanaryBody{ReadCloser: body, close: func() error { close(entered); <-release; return body.Close() }}
			}
			return reply, err
		})
		returned := make(chan model.WorkflowRunStepResult, 1)
		joined := false
		t.Cleanup(func() {
			once.Do(func() { close(release) })
			if !joined {
				<-returned
			}
		})
		before := canaryReads.Load()
		go func() {
			returned <- executeCapacityBusinessWorkflowStepWithClient(ctx, nil, db, ref, model.WorkflowRunStepResult{Operation: "capacity.observe_original_creation_canary"}, input(), &client)
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("original native Close did not enter before lease")
		}
		timer := time.NewTimer(time.Until(deadline) + 25*time.Millisecond)
		defer timer.Stop()
		<-timer.C
		select {
		case <-returned:
			joined = true
			t.Fatal("original Close replaced by lease cancellation")
		default:
		}
		once.Do(func() { close(release) })
		result := <-returned
		joined = true
		if result.Status == "succeeded" || result.Metadata != nil || canaryReads.Load() != before+1 {
			t.Fatal("expired original lease accepted or canary replayed")
		}
	})
	t.Run("closed_native_raw_duplicates_and_private_projection_refuse", func(t *testing.T) {
		for _, mutate := range []func(*model.CapacityBusinessCreationReply){func(r *model.CapacityBusinessCreationReply) {
			r.NativeRaw = []byte(`{"schema_version":"notify_capacity_creation_canary_read_v1","schema_version":"foreign"}`)
		}, func(r *model.CapacityBusinessCreationReply) { r.PreparationBefore.ProcessNonce = uuid.NewString() }, func(r *model.CapacityBusinessCreationReply) { r.Query = strings.Repeat("e", 64) }} {
			reply := source.Reply
			mutate(&reply)
			before := model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: frame}
			if _, err := capacity.JoinBusinessCreation(p, reply, before, before, time.Now().UTC()); err == nil {
				t.Fatal("foreign closed native source accepted")
			}
		}
	})
	if writes.Load() != 0 || intent.Generation < 1 || errors.Join(nativeAdapterContext(ctx)) != nil {
		t.Fatal("source observer mutated or lost original owner")
	}
	t.Log(fmt.Sprintf("actual Core PostgreSQL original epoch guarded; actual Notify source %s joined; native Kubernetes/main/original caller return still require integrated remote receipts", source.Source))
}
