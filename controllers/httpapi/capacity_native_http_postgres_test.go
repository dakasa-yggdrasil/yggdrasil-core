package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCapacityMutationNativeHTTPPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("native authority requires actual PostgreSQL")
		}
		t.Skip("remote PostgreSQL native authority")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := "native-http-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"capacity_native_commands", "capacity_native_pod_checkpoints", "capacity_native_scope_owners", "capacity_intent_events", "capacity_intents", "manifests"} {
			if _, err := db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	create := func(kind, name string, value any) model.Manifest {
		raw, _ := json.Marshal(value)
		m, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wf := create("workflow", "native-scale", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": ns, "name": "native-rbac"}}})
	typ := create("integration_type", "native-type", map[string]any{"provider": "kubernetes"})
	instance := create("integration_instance", "native-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
	now := time.Now().UTC()
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	hpaUID, workloadUID := uuid.NewString(), uuid.NewString()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "native-http", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/native-http", Owner: "native-owner", Workflow: model.ManifestSelector{Namespace: ns, Name: "native-scale"}, Currency: "USD", Floor: 2, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 180, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Profiles: []model.CapacityProfile{{Name: "reserved", Provider: "kubernetes", Region: "fixture-only", MinUnits: 2, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:native-source-only"}}, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixture/pressure", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: "platform", HPAName: "api", HPAUID: hpaUID, WorkloadName: "api", WorkloadUID: workloadUID, Owner: "native-owner", Profile: "reserved", ProtectedFloor: 2, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: adapter, BindingName: "pressure", BindingSHA256: strings.Repeat("a", 64)}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-http-adapter", Mode: capacity.HPAExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener"}, ProjectionDirectory: "/native"}}
	policy := create("capacity_policy", "native-policy", p)
	value := .9
	assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: hpaUID, ResourceVersion: "1", WorkloadUID: workloadUID, WorkloadResourceVersion: "2", Owner: p.Owner, Profile: "reserved", Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "fixture/pressure", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 5, CoverageComplete: true, MaxGapSeconds: 15}}}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	intent, err := store.Assess(ctx, policy, assessment)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, assessment)
	if err != nil {
		t.Fatal(err)
	}
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: "platform", HPAName: "api", HPAUID: hpaUID, ResourceVersion: "1", APIGeneration: 1, WorkloadName: "api", WorkloadUID: workloadUID, WorkloadResourceVersion: "2", Owner: p.Owner, EnvelopeGeneration: 1, IdempotencyKey: "previous", MinReplicas: 2, MaxReplicas: 4, ProtectedFloor: 2, TrackedProtectedFloor: 2, MaximumReplicas: 4, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: now.Format(time.RFC3339Nano)}}
	inventory := model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: "api-native", Namespace: "platform", WorkloadUID: workloadUID, WorkloadResourceVersion: "2", ListResourceVersion: "3", Complete: true, ObservedAt: now, Pods: []model.NativeTerminationObservation{}}
	if err := store.SaveNativePodPlan(ctx, policy, intent, inventory, hpa, nil); err != nil {
		t.Fatal(err)
	}
	intent.NativeHPAGeneration = 2
	no := false
	request := model.CapacityNativeHPARequest{Namespace: "platform", HPAName: "api", ExpectedUID: hpaUID, ExpectedResourceVersion: "1", ExpectedWorkloadUID: workloadUID, ExpectedWorkloadResourceVersion: "2", Owner: p.Owner, Generation: 2, IdempotencyKey: "native-one-use", MinReplicas: intent.Decision.Units, MaxReplicas: 4, DryRun: &no, Mode: "upshift"}
	raw, _ := json.Marshal(request)
	command, permission, err := store.IssueNativeCommand(ctx, policy, intent, capacity.EnsureBoundHPAEnvelope, hpaUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	machineToken := "native-ci-machine"
	principalRaw, _ := json.Marshal([]capacityMutationPrincipalConfig{{PrincipalID: "native-http-adapter", Status: "active", ExpiresAt: now.Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))), IntegrationInstanceID: instance.ID.String(), Capabilities: []string{capacity.EnsureBoundHPAEnvelope}}})
	t.Setenv(capacityMutationPrincipalsEnv, string(principalRaw))
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, capacityMutationPrincipals: principals}
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("native permission escaped machine surface") }))
	payload := model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: permission, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: capacity.EnsureBoundHPAEnvelope, RequestSHA256: command.RequestSHA256}
	body, _ := json.Marshal(payload)
	call := func(token string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, capacityMutationBasePath+"/native/redeem", strings.NewReader(string(body)))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if strings.Contains(out.Body.String(), permission) || strings.Contains(out.Body.String(), machineToken) {
			t.Fatal("private authority leaked")
		}
		return out
	}
	t.Run("default_deny", func(t *testing.T) {
		if call("", body).Code != 401 {
			t.Fatal("anonymous authority")
		}
		if call("human", body).Code != 401 {
			t.Fatal("human fallback authority")
		}
	})
	t.Run("canonical_members", func(t *testing.T) {
		for _, key := range []string{"AUTHORITY_TOKEN", "authority_token_alias"} {
			bad := []byte(strings.Replace(string(body), "authority_token", key, 1))
			if call(machineToken, bad).Code != 400 {
				t.Fatal("noncanonical authority member")
			}
		}
	})
	t.Run("instance_capability_and_hash_fences", func(t *testing.T) {
		for _, mode := range []string{"instance", "capability", "hash"} {
			bad := payload
			switch mode {
			case "instance":
				bad.IntegrationInstanceID = uuid.NewString()
			case "capability":
				bad.Capability = capacity.EnsureNativePodDrain
			case "hash":
				bad.RequestSHA256 = strings.Repeat("b", 64)
			}
			raw, _ := json.Marshal(bad)
			if call(machineToken, raw).Code == 200 {
				t.Fatal("native scope widened", mode)
			}
		}
	})
	t.Run("single_use_redemption", func(t *testing.T) {
		if call(machineToken, body).Code != 200 {
			t.Fatal("private native command refused")
		}
		if call(machineToken, body).Code == 200 {
			t.Fatal("private command replay")
		}
	})
}
