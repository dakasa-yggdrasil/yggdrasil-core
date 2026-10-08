package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This CI-only gate uses the actual Kubernetes adapter main, actual Core HTTP
// actor/RBAC and command APIs, production migrations, PostgreSQL, RabbitMQ and
// current native KinD Pods carrying the exact independently qualified producer.
func TestCapacityNativeKinDHTTP(t *testing.T) {
	if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") != "true" {
		t.Skip("remote native Core/Kubernetes/PG qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn, image, digest, adapterBinary := os.Getenv("DB_URL"), os.Getenv("NATIVE_FIXTURE_IMAGE"), os.Getenv("NATIVE_FIXTURE_DIGEST"), os.Getenv("CAPACITY_KUBERNETES_MAIN_BINARY")
	if dsn == "" || image == "" || digest == "" || adapterBinary == "" || os.Getenv("CAPACITY_METRIC_FIXTURE_BINARY") == "" {
		t.Fatal("exact native binaries, image and PostgreSQL required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := amqp.Dial(os.Getenv("BROKER_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Cleanup(func() { _ = db.Close() })
	realm := "native-core-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	create := func(kind, name string, value any) model.Manifest {
		raw, _ := json.Marshal(value)
		m, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Cleanup(func() {
		for _, table := range []string{"capacity_native_commands", "capacity_native_pod_checkpoints", "capacity_native_scope_owners", "capacity_intent_events", "capacity_intents", "manifests"} {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, realm)
		}
	})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": realm}})
	defer func() { _ = exec.Command("kubectl", "delete", "namespace", realm, "--wait=false").Run() }()
	projection := []map[string]any{{"path": "uid", "fieldRef": map[string]any{"fieldPath": "metadata.uid"}}, {"path": "namespace", "fieldRef": map[string]any{"fieldPath": "metadata.namespace"}}, {"path": "name", "fieldRef": map[string]any{"fieldPath": "metadata.name"}}, {"path": "challenge", "fieldRef": map[string]any{"fieldPath": "metadata.annotations['yggdrasil.io/capacity-drain-challenge']"}}}
	deployment := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"namespace": realm, "name": "api"}, "spec": map[string]any{"replicas": 3, "selector": map[string]any{"matchLabels": map[string]string{"app": "native-core"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "native-core"}}, "spec": map[string]any{"terminationGracePeriodSeconds": 30, "containers": []map[string]any{{"name": "api", "image": image, "imagePullPolicy": "Never", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "env": []map[string]string{{"name": "NATIVE_TERMINATION_PROJECTION_DIR", "value": "/native"}, {"name": "NATIVE_TERMINATION_IMAGE_DIGEST", "value": digest}, {"name": "NATIVE_FIXTURE_MODE", "value": "blocked_callback"}}, "volumeMounts": []map[string]any{{"name": "native", "mountPath": "/native", "readOnly": true}}}}, "volumes": []map[string]any{{"name": "native", "downwardAPI": map[string]any{"items": projection}}}}}}}
	nativeKindApply(t, ctx, deployment)
	nativeKindCommand(t, ctx, "-n", realm, "rollout", "status", "deployment/api", "--timeout=60s")
	dep := nativeKindGet(t, ctx, "-n", realm, "get", "deployment", "api", "-o", "json")
	workloadUID := dep["metadata"].(map[string]any)["uid"].(string)
	owner := "native-core-owner"
	annotations := map[string]string{"yggdrasil.io/capacity-envelope-owner": owner, "yggdrasil.io/capacity-envelope-generation": "1", "yggdrasil.io/capacity-envelope-idempotency": "previous-native", "yggdrasil.io/capacity-envelope-protected-floor": "2", "yggdrasil.io/capacity-envelope-min": "3", "yggdrasil.io/capacity-envelope-max": "4"}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": map[string]any{"namespace": realm, "name": "api", "annotations": annotations}, "spec": map[string]any{"scaleTargetRef": map[string]string{"apiVersion": "apps/v1", "kind": "Deployment", "name": "api"}, "minReplicas": 3, "maxReplicas": 4, "metrics": []map[string]any{{"type": "Resource", "resource": map[string]any{"name": "cpu", "target": map[string]any{"type": "Utilization", "averageUtilization": 80}}}}}})
	hpaObj := nativeKindGet(t, ctx, "-n", realm, "get", "hpa", "api", "-o", "json")
	hpaUID := hpaObj["metadata"].(map[string]any)["uid"].(string)
	nativeInstanceID := uuid.New()
	machineToken, eventToken, workflowToken := "native-ci-callback", "native-ci-events", "native-ci-workflow"
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_ENV", "development")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, workflowToken, "native-ci-runner", machineWorkflowRef{Namespace: realm, Name: "execute"}))
	nativeCaps := []string{capacity.EnsureBoundHPAEnvelope, capacity.EnsureNativePodDrain, capacity.DestroyNativePodProtection}
	principal, _ := json.Marshal([]capacityMutationPrincipalConfig{{PrincipalID: "native-adapter", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))), IntegrationInstanceID: nativeInstanceID.String(), Capabilities: nativeCaps}})
	t.Setenv(capacityMutationPrincipalsEnv, string(principal))
	eventPrincipal, _ := json.Marshal([]eventPublisherPrincipalConfig{{PrincipalID: "native-events", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(eventToken))), AllowedEvents: []eventPublisherEventRef{{Provider: "kubernetes", InstanceID: nativeInstanceID.String(), EventType: "kubernetes.object.ensured"}, {Provider: "kubernetes", InstanceID: nativeInstanceID.String(), EventType: "kubernetes.object.destroyed"}}}})
	t.Setenv(eventPublisherPrincipalsEnv, string(eventPrincipal))
	coreHandler, err := New("native-source-ci", db, conn, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	core := httptest.NewServer(coreHandler)
	defer core.Close()
	port, healthPort := nativeKindFreePort(t), nativeKindFreePort(t)
	adapterLog := filepath.Join(t.TempDir(), "adapter.log")
	logFile, err := os.Create(adapterLog)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	t.Cleanup(func() {
		if t.Failed() {
			raw, _ := os.ReadFile(adapterLog)
			if len(raw) > 12000 {
				raw = raw[len(raw)-12000:]
			}
			t.Logf("actual native adapter diagnostics: %s", raw)
		}
	})
	adapterCmd := exec.CommandContext(ctx, adapterBinary)
	adapterCmd.Env = append(os.Environ(), "YGGDRASIL_TRANSPORT=http", "ADAPTER_PORT="+strconv.Itoa(port), "HEALTHCHECK_PORT="+strconv.Itoa(healthPort), "YGGDRASIL_CORE_URL="+core.URL, "YGGDRASIL_RUN_TOKEN="+eventToken)
	adapterCmd.Stdout, adapterCmd.Stderr = logFile, logFile
	if err := adapterCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adapterCmd.Process.Kill(); _ = adapterCmd.Wait() }()
	adapterURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	var describe model.AdapterDescribeResponse
	nativeKindAwait(t, ctx, func() bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, adapterURL+"/rpc/describe", strings.NewReader("{}"))
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		var envelope struct {
			Body []byte `json:"body"`
		}
		var payload struct {
			OK   bool                          `json:"ok"`
			Data model.AdapterDescribeResponse `json:"data"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&envelope) != nil || json.Unmarshal(envelope.Body, &payload) != nil || !payload.OK {
			return false
		}
		describe = payload.Data
		return true
	})
	var nativeType model.IntegrationTypeManifestSpec
	raw, _ := json.Marshal(describe)
	if json.Unmarshal(raw, &nativeType) != nil || manifest.ValidateIntegrationTypeSpec(nativeType) != nil {
		t.Fatal("actual native main describe invalid")
	}
	typ := create("integration_type", "native-kubernetes", nativeType)
	nativeConfig := map[string]any{"base_url": adapterURL, "kubeconfig_path": os.Getenv("KUBECONFIG"), "capacity_authority_url": core.URL, "capacity_envelope_targets": []map[string]any{{"namespace": realm, "hpa_name": "api", "hpa_uid": hpaUID, "workload_name": "api", "workload_uid": workloadUID, "owner": owner, "protected_floor": 2, "maximum_replicas": 4, "adoption_allowed": false, "surplus_max_age_seconds": 180}}, "capacity_pod_targets": []map[string]any{{"binding_name": "api-native", "namespace": realm, "workload_name": "api", "workload_uid": workloadUID, "owner": owner, "container_name": "api", "image_digest": digest, "lanes": []string{"listener", "workers"}, "projection_directory": "/native"}}}
	// The registered instance uses the actual predetermined machine scope UUID.
	specRaw, _ := json.Marshal(model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: nativeConfig, Credentials: map[string]any{"capacity_mutation_token": machineToken}})
	instance := create("integration_instance", "native-kubernetes", json.RawMessage(specRaw))
	if instance.ID != nativeInstanceID {
		if _, err := db.ExecContext(ctx, `UPDATE public.manifests SET id=$2 WHERE id=$1`, instance.ID, nativeInstanceID); err != nil {
			t.Fatal(err)
		}
		instance.ID = nativeInstanceID
	}
	metricData := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		start, _ := strconv.ParseInt(r.Form.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(r.Form.Get("end"), 10, 64)
		values := [][]any{}
		for at := start; at <= end; at += 15 {
			v := "0.1"
			if r.Form.Get("query") == "min(timestamp(fixed-source))" {
				v = strconv.FormatInt(at, 10)
			}
			values = append(values, []any{at, v})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{"unit": "api"}, "values": values}}}})
	}))
	defer metricData.Close()
	metricConfig := map[string]any{"prometheus_url": metricData.URL, "evidence_bindings": map[string]any{"admission": map[string]any{"name": "admission_pressure", "source_identity": "fixture/prom/native", "unit": "ratio", "value_query": "fixed-pressure", "source_timestamp_query": "min(timestamp(fixed-source))", "expected_labels": map[string]string{"unit": "api"}, "window_seconds": 60, "step_seconds": 15, "max_source_age_seconds": 180, "max_gap_seconds": 30, "min_samples": 3}}}
	seedReq := model.AdapterExecuteIntegrationRequest{Operation: capacity.ObserveMetricRange, Capability: capacity.ObserveMetricRange, Input: map[string]any{"binding": "admission"}, Integration: model.AdapterExecuteIntegrationContext{InstanceSpec: model.IntegrationInstanceManifestSpec{Config: metricConfig}}}
	seed := nativeKindMetricProducer(t, ctx, "seed", seedReq)
	var metricDescribe model.AdapterDescribeResponse
	raw, _ = json.Marshal(seed["describe"])
	if json.Unmarshal(raw, &metricDescribe) != nil {
		t.Fatal("actual metric describe")
	}
	metricDescribe.Adapter.Transport = "http_json"
	metricDescribe.Adapter.Queues = model.IntegrationAdapterQueue{}
	metricDescribe.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}
	metricDescribe.InstanceSchema.Properties["base_url"] = model.IntegrationSchemaProperty{Type: "string"}
	metricServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/describe" {
			json.NewEncoder(w).Encode(metricDescribe)
			return
		}
		var request model.AdapterExecuteIntegrationRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		result := nativeKindMetricProducer(t, ctx, "observe", request)
		json.NewEncoder(w).Encode(result)
	}))
	defer metricServer.Close()
	var metricType model.IntegrationTypeManifestSpec
	raw, _ = json.Marshal(metricDescribe)
	if json.Unmarshal(raw, &metricType) != nil {
		t.Fatal("metric type")
	}
	metricTM := create("integration_type", "native-prometheus", metricType)
	metricConfig["base_url"] = metricServer.URL
	metricIM := create("integration_instance", "native-prometheus", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: metricTM.ID.String()}, Status: "active", Config: metricConfig})
	var metric model.CapacityMetricRangeObservation
	raw, _ = json.Marshal(seed["output"])
	if json.Unmarshal(raw, &metric) != nil {
		t.Fatal("metric source output")
	}
	nativeBinding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	metricBinding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: metricIM.ID.String(), InstanceChecksum: metricIM.Checksum, IntegrationTypeID: metricTM.ID.String(), TypeChecksum: metricTM.Checksum}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "native-core", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/native-core", Owner: owner, Workflow: model.ManifestSelector{Namespace: realm, Name: "execute"}, Currency: "USD", Floor: 2, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 180, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Profiles: []model.CapacityProfile{{Name: "reserved", Provider: "kubernetes", Region: "fixture-only", MinUnits: 2, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:source-qualification-only"}}, Signals: []model.CapacitySignalRule{{Name: "admission_pressure", SourceIdentity: "fixture/prom/native", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: nativeBinding, Namespace: realm, HPAName: "api", HPAUID: hpaUID, WorkloadName: "api", WorkloadUID: workloadUID, Owner: owner, Profile: "reserved", ProtectedFloor: 2, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "admission_pressure", Adapter: metricBinding, BindingName: "admission", BindingSHA256: metric.BindingSHA256}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPAExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: digest, Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native"}}
	create("rbac", "native-rbac", map[string]any{"roles": []any{map[string]any{"name": "native", "rules": []any{map[string]any{"effect": "allow", "resources": []string{"workflow:" + realm + ":execute"}, "actions": []string{"run"}}}}}, "bindings": []any{map[string]any{"name": "ci-only", "subjects": []any{map[string]string{"type": "service", "id": "native-ci-runner"}}, "roles": []string{"native"}}}})
	noNativeInputs := false
	create("workflow", "execute", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: "native-rbac"}}, InputSchema: model.WorkflowInputSchemaSpec{Properties: map[string]model.IntegrationSchemaProperty{}, AdditionalProperties: &noNativeInputs}, Steps: []model.WorkflowStepSpec{{ID: "native", TimeoutSeconds: 180, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, With: map[string]any{"policy": map[string]string{"namespace": realm, "name": "native-policy"}}}}})
	policy := create("capacity_policy", "native-policy", p)
	if err := manifest.ValidateCapacityPolicySpec(p); err != nil {
		t.Fatalf("actual native operator binding: %v", err)
	}
	// Read through the same real Core resolution and SDK transport before the
	// protected workflow. Failures stay private to CI diagnostics, not API output.
	for _, check := range []struct {
		instance  model.Manifest
		operation string
		input     map[string]any
	}{
		{metricIM, capacity.ObserveMetricRange, map[string]any{"binding": "admission"}},
		{instance, capacity.ObserveHPAEnvelope, map[string]any{"namespace": realm, "hpa_name": "api"}},
		{instance, capacity.ObserveNativePodInventory, map[string]any{"binding_name": "api-native"}},
	} {
		result, err := message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{Integration: model.ManifestSelector{ManifestID: check.instance.ID.String()}, Operation: check.operation, Capability: check.operation, Input: check.input})
		if err != nil {
			t.Fatalf("actual native read preflight %s: %v", check.operation, err)
		}
		t.Logf("actual native read preflight %s status=%s", check.operation, result.Status)
		switch check.operation {
		case capacity.ObserveMetricRange:
			var source model.CapacityMetricRangeObservation
			if err := capacity.DecodeNativeCapacity(result.Output, &source); err != nil {
				t.Fatalf("actual metric closed source: %v", err)
			}
			if _, err := capacity.BoundMetricEvidence(p, p.AssessmentBinding.Signals[0], source, time.Now().UTC()); err != nil {
				t.Fatalf("actual metric binding: %v", err)
			}
		case capacity.ObserveHPAEnvelope:
			var source model.CapacityHPAEnvelopeResponse
			if err := capacity.DecodeNativeCapacity(result.Output, &source); err != nil {
				t.Fatalf("actual HPA closed source: %v", err)
			}
			if _, err := capacity.BoundHPASnapshot(p, source, time.Now().UTC()); err != nil {
				t.Fatalf("actual HPA binding: %v %#v", err, source.Observation)
			}
		case capacity.ObserveNativePodInventory:
			var source model.AdapterCapacityPodInventoryResponse
			if err := capacity.DecodeNativeCapacity(result.Output, &source); err != nil {
				t.Fatalf("actual native inventory closed source: %v", err)
			}
			if err := capacity.NativePodInventory(p, source, time.Now().UTC()); err != nil {
				t.Fatalf("actual native inventory binding: %v", err)
			}
		}
	}
	post := func(token string, input any) (int, map[string]any) {
		raw, _ := json.Marshal(input)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, core.URL+"/api/v1/workflow-runs", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		if json.NewDecoder(res.Body).Decode(&out) != nil {
			t.Fatal("native Core response invalid")
		}
		return res.StatusCode, out
	}
	request := map[string]any{"workflow": map[string]string{"namespace": realm, "name": "execute"}, "inputs": map[string]any{}}
	if code, _ := post("", request); code != 401 {
		t.Fatal("native executor bypassed actor")
	}
	heldNativeWork := false
	run := func() {
		code, out := post(workflowToken, request)
		if code != 202 {
			t.Fatalf("native protected dispatch %d %#v", code, out)
		}
		runID, _ := out["run_id"].(string)
		nativeKindAwait(t, ctx, func() bool {
			var status string
			var result []byte
			err := db.QueryRowContext(ctx, `SELECT status,COALESCE(result,'{}'::jsonb) FROM public.workflow_runs WHERE id=$1`, runID).Scan(&status, &result)
			if err != nil {
				return false
			}
			if status == "failed" {
				t.Fatalf("actual native workflow failed: %s", string(result))
			}
			if status == "running" {
				var checkpointRaw []byte
				if db.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND checkpoint_record->>'state'='terminating' LIMIT 1`, realm).Scan(&checkpointRaw) == nil {
					var checkpoint model.CapacityNativePodCheckpoint
					if json.Unmarshal(checkpointRaw, &checkpoint) == nil && checkpoint.ConfirmedAt == nil && len(checkpoint.NativeTerminationReceipt) == 0 {
						object := nativeKindGet(t, ctx, "-n", realm, "get", "pod", checkpoint.PodName, "-o", "json")
						podStatus, ok := object["status"].(map[string]any)
						if ok {
							containers, _ := podStatus["containerStatuses"].([]any)
							for _, item := range containers {
								container, _ := item.(map[string]any)
								state, _ := container["state"].(map[string]any)
								if state["running"] != nil {
									meta, _ := object["metadata"].(map[string]any)
									finalizers, _ := meta["finalizers"].([]any)
									for _, f := range finalizers {
										if f == "yggdrasil.io/capacity-native-termination" {
											heldNativeWork = true
										}
									}
								}
							}
						}
					}
				}
			}
			return status == "succeeded"
		})
	}
	run()
	time.Sleep(1200 * time.Millisecond)
	run()
	if !heldNativeWork {
		t.Fatal("native held callback was acknowledged before actual worker return")
	}
	store := repository.CapacityStore{DB: db}
	intent, err := store.Observe(ctx, policy)
	if err != nil || intent.Phase != "native_completed" || intent.Dimension != capacity.ReservedPodEnvelopeUnit {
		t.Fatal("actual native bounded completion missing", intent.Phase, err)
	}
	var confirmed, released, grants int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND state='confirmed'`, realm).Scan(&confirmed) != nil || confirmed != 4 {
		t.Fatal("missing native phase confirmations", confirmed)
	}
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND checkpoint_record->>'state'='released' AND checkpoint_record->>'confirmed_at' IS NOT NULL`, realm).Scan(&released) != nil || released != 1 {
		t.Fatal("missing durable exact lifetime receipt")
	}
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, realm).Scan(&grants) != nil || grants != 0 {
		t.Fatal("reserved envelope created VM authority")
	}
}
func nativeKindFreePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
func nativeKindAwait(t *testing.T, ctx context.Context, predicate func() bool) {
	t.Helper()
	for !predicate() {
		select {
		case <-ctx.Done():
			t.Fatal("native Core qualification timeout")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func nativeKindCommand(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	raw, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("native kubectl %v: %v %s", args, err, raw)
	}
	return raw
}
func nativeKindGet(t *testing.T, ctx context.Context, args ...string) map[string]any {
	var value map[string]any
	if json.Unmarshal(nativeKindCommand(t, ctx, args...), &value) != nil {
		t.Fatal("native API JSON missing")
	}
	return value
}
func nativeKindApply(t *testing.T, ctx context.Context, value any) {
	t.Helper()
	raw, _ := json.Marshal(value)
	command := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	command.Stdin = bytes.NewReader(raw)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native fixture apply: %v %s", err, out)
	}
}
func nativeKindMetricProducer(t *testing.T, ctx context.Context, mode string, request any) map[string]any {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	raw, _ := json.Marshal(map[string]any{"mode": mode, "request": request})
	if os.WriteFile(input, raw, 0600) != nil {
		t.Fatal("native source input")
	}
	command := exec.CommandContext(ctx, os.Getenv("CAPACITY_METRIC_FIXTURE_BINARY"), "-test.run=^TestCapacityCoreMetricSourceFixtureProducer$")
	command.Env = append(os.Environ(), "CAPACITY_NATIVE_INPUT_FILE="+input, "CAPACITY_NATIVE_OUTPUT_FILE="+output)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual metric producer: %v %s", err, out)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("actual metric JSON")
	}
	return value
}
