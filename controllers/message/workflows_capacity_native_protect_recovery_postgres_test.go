package message

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This is real PostgreSQL and HTTP/TLS protocol integration, not a Kubernetes
// lifetime or physical SDK qualification. The production controller must obtain
// its waiting process frame from the actual adapter RPC before issuing a child.
type protectRecoveryControllerFixture struct {
	db          *sql.DB
	policy      model.Manifest
	spec        model.CapacityPolicySpec
	workflow    model.Manifest
	binding     model.CapacityUnredeemedProtectRecoveryBinding
	boot        model.AdapterCapacityPodAdmissionResponse
	checkpoint  model.CapacityNativePodCheckpoint
	originals   []string
	operator    string
	mode        atomic.Value
	bootReads   atomic.Int32
	ensures     atomic.Int32
	afterReads  atomic.Int32
	redemptions atomic.Int32
}

func protectRecoveryControllerSHA(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var canonical any
	if err = decoder.Decode(&canonical); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newProtectRecoveryControllerFixture(t *testing.T) *protectRecoveryControllerFixture {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("mandatory remote PostgreSQL required")
		}
		t.Skip("PostgreSQL protocol integration runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ns := "protect-recovery-" + uuid.NewString()
	t.Cleanup(func() {
		// Permanent native identities are intentionally not deleted or rewritten.
		// Each fixture uses a new namespace/Pod UID in the disposable CI database.
		for _, table := range []string{"capacity_intent_events", "capacity_intents", "manifests"} {
			if _, e := db.ExecContext(context.Background(), "DELETE FROM public."+table+" WHERE namespace=$1", ns); e != nil {
				t.Error(e)
			}
		}
		if e := db.Close(); e != nil {
			t.Error(e)
		}
	})
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED", "true")
	f := &protectRecoveryControllerFixture{db: db, operator: uuid.NewString()}
	f.mode.Store("complete")
	create := func(kind, name string, value any) model.Manifest {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		m, e := repository.CreateManifestVersion(t.Context(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, hex.EncodeToString(sum[:]))
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	authorization := map[string]any{"rbac": map[string]string{"namespace": ns, "name": "native"}}
	admission := create("workflow", "admit-api", map[string]any{"authorization": authorization})
	create("workflow", "scale-api", map[string]any{"authorization": authorization})

	callback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request model.CapacityNativeAuthorityRedeemRequest
		if r.Method != http.MethodPost || r.URL.Path != "/redeem" || r.TLS == nil || json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "invalid protocol callback", http.StatusBadRequest)
			return
		}
		// The authenticated principal is fixed by this private authority fixture,
		// never taken from the callback payload.
		store := repository.CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true}
		permit, e := store.RedeemNativeCommand(r.Context(), "native-adapter", request)
		if e != nil {
			t.Errorf("actual callback redemption refused: %v", e)
			http.Error(w, "callback refused", http.StatusForbidden)
			return
		}
		f.redemptions.Add(1)
		_ = json.NewEncoder(w).Encode(permit)
	}))
	t.Cleanup(callback.Close)

	operations := []string{capacity.ObserveNativePodAdmission, capacity.EnsureNativePodDrain, capacity.ObserveNativePodTermination}
	typeSpec := model.IntegrationTypeManifestSpec{
		Provider: "kubernetes", Domain: "infrastructure",
		Adapter:          model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Health: "/nativehealth", Describe: "/describe", Execute: "/execute"}, TimeoutSeconds: 35},
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{}},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}},
		ResourceTypes:    []model.IntegrationResourceType{{Name: "object", CanonicalPrefix: "thirdparty.kubernetes.object", IdentityTemplate: "object.{id}", DefaultActions: operations}},
		Discovery:        model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"},
		Normalization:    model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.kubernetes.object"},
	}
	for _, op := range operations {
		typeSpec.ActionCatalog = append(typeSpec.ActionCatalog, model.IntegrationActionDefinition{Name: op, ResourceTypes: []string{"object"}, Idempotent: op != capacity.EnsureNativePodDrain})
	}
	if err := manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal(err)
	}
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/nativehealth" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/describe" {
			var out model.AdapterDescribeResponse
			raw, _ := json.Marshal(typeSpec)
			_ = json.Unmarshal(raw, &out)
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var req model.AdapterExecuteIntegrationRequest
		if r.Method != http.MethodPost || r.URL.Path != "/execute" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != req.Capability {
			http.Error(w, "invalid native request", http.StatusBadRequest)
			return
		}
		switch req.Operation {
		case capacity.ObserveNativePodAdmission:
			f.bootReads.Add(1)
			boot := f.boot
			boot.Observation.PodResourceVersion = "30"
			boot.Observation.ObservedAt = time.Now().UTC()
			boot.Admission.ObservedAt = boot.Observation.ObservedAt
			if f.mode.Load().(string) == "stale" {
				boot.Admission.ObservedAt = time.Now().UTC().Add(-2 * time.Minute)
			}
			if f.mode.Load().(string) == "foreign_nonce" {
				boot.Admission.ProcessNonce = uuid.NewString()
			}
			outer := "observed"
			if f.mode.Load().(string) == "outer_failed" {
				outer = "failed"
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: outer, Output: boot})
		case capacity.EnsureNativePodDrain:
			f.ensures.Add(1)
			fields := make(map[string]any, len(req.Input))
			for k, v := range req.Input {
				fields[k] = v
			}
			token, ok := fields["authority_token"].(string)
			delete(fields, "authority_token")
			var actual model.AdapterEnsureCapacityPodDrainRequest
			if !ok || token == "" || capacity.DecodeNativeCapacity(fields, &actual) != nil || actual.Phase != "protect" || actual.ExpectedPodUID != f.checkpoint.PodUID || actual.ExpectedPodResourceVersion != "30" || actual.ExpectedContainerID != f.checkpoint.ContainerID || actual.ExpectedRestartCount != f.checkpoint.RestartCount {
				t.Error("ensure escaped the observed immutable lifetime")
				http.Error(w, "unexpected ensure", http.StatusBadRequest)
				return
			}
			var challenge model.NativePodTerminationChallenge
			_ = json.Unmarshal(f.checkpoint.OriginChallengeBytes, &challenge)
			if !reflect.DeepEqual(actual.Challenge, challenge) {
				t.Error("recovery replaced the original SDK challenge")
				http.Error(w, "foreign origin", http.StatusBadRequest)
				return
			}
			b := f.spec.AssessmentBinding.Snapshot.Adapter
			redeem := model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: token, IntegrationInstanceID: b.IntegrationInstanceID, IntegrationTypeID: b.IntegrationTypeID, Capability: req.Operation, RequestSHA256: protectRecoveryControllerSHA(t, fields)}
			body, _ := json.Marshal(redeem)
			call, e := http.NewRequestWithContext(r.Context(), http.MethodPost, callback.URL+"/redeem", bytes.NewReader(body))
			if e != nil {
				t.Error(e)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			resp, e := callback.Client().Do(call)
			if e != nil {
				t.Error(e)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			raw, e := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			var permit model.CapacityNativeAuthorityPermit
			if resp.StatusCode != http.StatusOK || e != nil || closeErr != nil || json.Unmarshal(raw, &permit) != nil || permit.CommandID == uuid.Nil || permit.RequestSHA256 != redeem.RequestSHA256 {
				t.Error("the actual TLS callback was not received", resp.StatusCode, e, closeErr)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: "protected", Output: map[string]any{"status": "protected"}})
		case capacity.ObserveNativePodTermination:
			f.afterReads.Add(1)
			pod := f.boot.Observation
			pod.PodResourceVersion, pod.ObservedAt = "31", time.Now().UTC()
			outer := "observed"
			if f.mode.Load().(string) == "after_failed" {
				outer = "failed"
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: outer, Output: model.AdapterCapacityPodTerminationResponse{Operation: req.Operation, Status: "observed", Observation: pod}})
		default:
			t.Error("unexpected native operation", req.Operation)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(adapter.Close)
	typ := create("integration_type", "native", typeSpec)
	instance := create("integration_instance", "native", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: map[string]any{"base_url": adapter.URL}})
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/native-api", Owner: "native-api", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale-api"}, Currency: "USD", Floor: 1, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 60, CooldownSeconds: 30, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MinUnits: 1, MaxUnits: 4, UnitMonthlyCostMinor: 1, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "protocol-only"}}}
	binding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: binding, Namespace: ns, HPAName: "api-hpa", HPAUID: uuid.NewString(), WorkloadName: "api", WorkloadUID: uuid.NewString(), Owner: p.Owner, Profile: "base", ProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: binding, BindingName: "pressure", BindingSHA256: strings.Repeat("a", 64)}}}
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("b", 64), Lanes: []string{"listener", "worker"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: ns, Name: "admit-api"}, BirthGuardBinding: "api-birth", BirthGuardSHA256: strings.Repeat("c", 64)}
	f.policy, f.spec = create("capacity_policy", "api", p), p
	if err := manifest.ValidateCapacityPolicySpec(p); err != nil {
		t.Fatal(err)
	}
	ctx := newCapacityInvocationContext(t.Context())
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: admission.ID, ExecutorID: executor}
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: ns, HPAName: "api-hpa", HPAUID: p.AssessmentBinding.Snapshot.HPAUID, ResourceVersion: "1", WorkloadName: "api", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", Owner: p.Owner, EnvelopeGeneration: 7, IdempotencyKey: "previous", MinReplicas: 1, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	intent, err := store.AcquireNativeAdmissionExecution(ctx, f.policy, hpa)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	pod := model.NativeTerminationObservation{BindingName: "api-native", Namespace: ns, PodName: "api-protocol", PodUID: uuid.NewString(), PodResourceVersion: "10", WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: "api", ContainerID: "containerd://" + strings.Repeat("d", 64), ImageID: "fixture@" + p.HPAExecutionBinding.ImageDigest, ImageDigest: p.HPAExecutionBinding.ImageDigest, StartedAt: &start, Protected: true, ContainerState: "running", State: "running", Reason: "protocol_fixture_only", ObservedAt: time.Now().UTC()}
	f.boot = model.AdapterCapacityPodAdmissionResponse{Operation: capacity.ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: model.NativeProcessAdmissionObservation{SchemaVersion: 2, Namespace: ns, PodName: pod.PodName, PodUID: pod.PodUID, ImageDigest: pod.ImageDigest, LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes), ProcessNonce: uuid.NewString(), ObservedAt: time.Now().UTC(), State: "waiting_projection"}}
	f.checkpoint, err = store.RegisterNativeLifetime(ctx, f.policy, intent, f.boot)
	if err != nil {
		t.Fatal(err)
	}
	var challenge model.NativePodTerminationChallenge
	if err = json.Unmarshal(f.checkpoint.Challenge, &challenge); err != nil {
		t.Fatal(err)
	}
	no := false
	request := model.AdapterEnsureCapacityPodDrainRequest{BindingName: "api-native", PodName: pod.PodName, ExpectedPodUID: pod.PodUID, ExpectedPodResourceVersion: "10", ExpectedContainerID: pod.ContainerID, ExpectedContainerStartedAt: start, ExpectedRestartCount: 0, Challenge: challenge, Phase: "protect", DryRun: &no}
	encoded, _ := json.Marshal(request)
	f.binding = model.CapacityUnredeemedProtectRecoveryBinding{Schema: capacity.UnredeemedProtectRecoverySchema, PolicyID: f.policy.ID.String(), PolicyChecksum: f.policy.Checksum, OperatorID: f.operator, PodUID: pod.PodUID, ExpectedIntentGeneration: intent.Generation, ExpectedIntentFencingToken: intent.FencingToken, Confirmation: "CONFIRM ONE PROTOCOL FIXTURE PROTECT CHILD"}
	for i := 0; i < 4; i++ {
		command, _, e := store.IssueNativeCommand(ctx, f.policy, intent, capacity.EnsureNativePodDrain, pod.PodUID, encoded)
		if e != nil {
			t.Fatal("ordinary original permission", e)
		}
		refused, e := store.RevokeUnredeemedNativeCommand(ctx, f.policy, intent, command.CommandID)
		if e != nil || !refused {
			t.Fatal("actual atomic unredeemed disposition", e, refused)
		}
		var raw json.RawMessage
		if e = db.QueryRowContext(ctx, "SELECT command_record FROM public.capacity_native_commands WHERE id=$1", command.CommandID).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		f.binding.Commands = append(f.binding.Commands, model.CapacityUnredeemedProtectReference{CommandID: command.CommandID.String(), RecordSHA256: protectRecoveryControllerSHA(t, raw)})
	}
	f.originals = f.originalRows(t)
	var cp json.RawMessage
	if err = db.QueryRowContext(ctx, "SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1", pod.PodUID).Scan(&cp); err != nil {
		t.Fatal(err)
	}
	f.binding.CheckpointSHA256 = protectRecoveryControllerSHA(t, cp)
	spec := map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": authorization, "steps": []any{map[string]any{"id": "recover", "use": map[string]any{"kind": "yggdrasil", "operation": capacity.RecoverUnredeemedNativeProtect}, "with": map[string]any{"binding": f.binding, "confirmation": "{{ inputs.confirmation }}"}, "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}}}}
	f.workflow = create("workflow", "recover-one-protect", spec)
	// Only the mutable lease expires. The four original records/identities,
	// deadlines, checkpoint and challenge are never edited by setup.
	if _, err = db.ExecContext(ctx, "UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1", ns, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *protectRecoveryControllerFixture) originalRows(t *testing.T) []string {
	t.Helper()
	rows, err := f.db.Query("SELECT command_record::text FROM public.capacity_native_commands WHERE subject_uid=$1 AND generation=$2 ORDER BY sequence", f.binding.PodUID, f.binding.ExpectedIntentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result = append(result, raw)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *protectRecoveryControllerFixture) run(t *testing.T, human bool, input map[string]any) model.WorkflowRunStepResult {
	t.Helper()
	ctx := newCapacityInvocationContext(t.Context())
	if human {
		ctx = context.WithValue(ctx, executorPowerOperatorKey{}, f.operator)
	}
	ctx = WithCapacityReleaseRecoveryAuthorization(ctx, func(context.Context) error { return nil })
	if input == nil {
		raw, _ := json.Marshal(map[string]any{"binding": f.binding, "confirmation": f.binding.Confirmation})
		_ = json.Unmarshal(raw, &input)
	}
	return executeCapacityUnredeemedProtectRecoveryStep(ctx, nil, f.db, manifestReferenceFromRecord(f.workflow), model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: capacity.RecoverUnredeemedNativeProtect}, input)
}

func (f *protectRecoveryControllerFixture) assertOriginals(t *testing.T) {
	t.Helper()
	if got := f.originalRows(t); !reflect.DeepEqual(got, f.originals) || len(got) != 4 {
		t.Fatal("four original refused records changed")
	}
	var count int
	if err := f.db.QueryRow("SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1", f.binding.PodUID).Scan(&count); err != nil || count < 4 || count > 5 {
		t.Fatal("permanent identity accounting changed", count, err)
	}
}

func TestCapacityUnredeemedProtectRecoveryHandlerPostgres(t *testing.T) {
	t.Run("actual_boot_one_ensure_TLS_redemption_and_readback", func(t *testing.T) {
		f := newProtectRecoveryControllerFixture(t)
		result := f.run(t, true, nil)
		if result.Status != "succeeded" || result.Error != "" || f.bootReads.Load() != 1 || f.ensures.Load() != 1 || f.redemptions.Load() != 1 || f.afterReads.Load() != 1 {
			t.Fatalf("real protected handler did not receive its sole original: %+v boot=%d ensure=%d redeem=%d after=%d", result, f.bootReads.Load(), f.ensures.Load(), f.redemptions.Load(), f.afterReads.Load())
		}
		f.assertOriginals(t)
		var checkpoint model.CapacityNativePodCheckpoint
		var raw []byte
		if err := f.db.QueryRow("SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE pod_uid=$1", f.binding.PodUID).Scan(&raw); err != nil || json.Unmarshal(raw, &checkpoint) != nil {
			t.Fatal(err)
		}
		if checkpoint.State != "protected" || checkpoint.PodResourceVersion != "31" || checkpoint.ConfirmedAt != nil || string(checkpoint.OriginChallengeBytes) != string(f.checkpoint.OriginChallengeBytes) || checkpoint.ProcessNonce != f.checkpoint.ProcessNonce || checkpoint.ContainerID != f.checkpoint.ContainerID {
			t.Fatal("protect confirmation changed immutable origin or invented completion", checkpoint.State)
		}
		if replay := f.run(t, true, nil); replay.Status != "failed" || f.ensures.Load() != 1 || f.redemptions.Load() != 1 {
			t.Fatal("same manual input issued a second ensure", replay)
		}
		f.assertOriginals(t)
	})
	for _, mode := range []string{"machine", "stale", "foreign_nonce", "caller_boot", "outer_failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newProtectRecoveryControllerFixture(t)
			f.mode.Store(mode)
			var input map[string]any
			if mode == "caller_boot" {
				raw, _ := json.Marshal(map[string]any{"binding": f.binding, "confirmation": f.binding.Confirmation, "boot": f.boot})
				_ = json.Unmarshal(raw, &input)
			}
			result := f.run(t, mode != "machine", input)
			if result.Status != "failed" || result.Error != "protected one-use native protect recovery refused" || result.Metadata != nil || f.ensures.Load() != 0 || f.redemptions.Load() != 0 || f.afterReads.Load() != 0 {
				t.Fatal("invalid authority or SDK frame reached mutation", mode, result)
			}
			if (mode == "machine" || mode == "caller_boot") && f.bootReads.Load() != 0 {
				t.Fatal("unauthorized input reached private SDK RPC", mode)
			}
			if mode != "machine" && mode != "caller_boot" && f.bootReads.Load() != 1 {
				t.Fatal("SDK negative did not reach its actual private RPC", mode)
			}
			f.assertOriginals(t)
			var count int
			if err := f.db.QueryRow("SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1", f.binding.PodUID).Scan(&count); err != nil || count != 4 {
				t.Fatalf("refusal minted a child: %d %v", count, err)
			}
		})
	}
	t.Run("after_failed_retains_uncertain_child", func(t *testing.T) {
		f := newProtectRecoveryControllerFixture(t)
		f.mode.Store("after_failed")
		result := f.run(t, true, nil)
		if result.Status != "failed" || f.ensures.Load() != 1 || f.redemptions.Load() != 1 || f.afterReads.Load() != 1 {
			t.Fatal("failed outer read credited or resent", result)
		}
		var state string
		if err := f.db.QueryRow(`SELECT state FROM public.capacity_native_commands WHERE subject_uid=$1 AND generation>$2`, f.binding.PodUID, f.binding.ExpectedIntentGeneration).Scan(&state); err != nil || state != "uncertain" {
			t.Fatal("unknown result not retained", state, err)
		}
		f.assertOriginals(t)
	})
}
