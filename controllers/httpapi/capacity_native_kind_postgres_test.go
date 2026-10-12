package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Package-owned read seam for the PRIVATE Notify original joint template.
// Public Core KinD keeps its complete old gate/census. This function neither
// creates a row nor supplies a success flag: its caller must join the actual
// original RunOne/HTTP/SQL/SDK and selected native participants independently.
// Observe intentionally redacts the private marker/owner; this fixed original
// SQL read is confined to the CI fixture instead of weakening public readback.
func nativeKindOriginalNotifyIntent(t *testing.T, parent context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec) model.CapacityIntent {
	t.Helper()
	owner, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var raw []byte
	err := db.QueryRowContext(owner, `SELECT substring(convert_to(intent::text,'UTF8') FROM 1 FOR 2097153) FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw)
	var out model.CapacityIntent
	if err != nil || len(raw) > 2<<20 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &out) != nil || errors.Join(dispatchContext(owner), dispatchContext(parent)) != nil || out.PolicyID != policy.ID || out.PolicyChecksum != policy.Checksum {
		t.Fatal("original joint native intent read unavailable")
	}
	return out
}

// This CI-only gate uses the actual Kubernetes adapter main, actual Core HTTP
// actor/RBAC and command APIs, production migrations, PostgreSQL, RabbitMQ and
// current native KinD Pods carrying the exact independently qualified producer.
func TestCapacityNativeKinDHTTP(t *testing.T) {
	if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") != "true" {
		t.Skip("remote native Core/Kubernetes/PG qualification")
	}
	for _, scenario := range []struct {
		name  string
		mixed bool
		drift string
	}{{"complete_baseline_controller_retirement", false, ""}, {"mixed_schema_one_frozen_bootstrap", true, ""}, {"installed_guard_refusal_before_authority", false, "before"}, {"installed_guard_refusal_during_redemption", false, "during"}, {"durable_scheduled_dispatch_original_native_executor", false, ""}} {
		t.Run(scenario.name, func(t *testing.T) {
			qualifyCapacityNativeKinDHTTP(t, scenario.mixed, scenario.drift, scenario.name == "durable_scheduled_dispatch_original_native_executor", scenario.name)
		})
	}
}

func qualifyCapacityNativeKinDHTTP(t *testing.T, mixed bool, drift string, scheduled bool, recoveryMode ...string) {
	protocolEnabled := len(recoveryMode) == 1
	mode := ""
	if protocolEnabled {
		mode = recoveryMode[0]
	}
	forceConflict := strings.HasPrefix(mode, "forced_conflict")
	compiledSource := os.Getenv("CAPACITY_KUBERNETES_SOURCE_COMMIT")
	if protocolEnabled && (len(compiledSource) != 40 || strings.ContainsAny(compiledSource, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")) {
		t.Fatal("exact compiled native release source required before effects")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
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
	workloadName := nativeBirthRoster(t)[0]
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
	const admissionKey = "native-core-ci-scoped-admission-key-32bytes"
	const nativeFinalizer = "yggdrasil.io/capacity-native-termination"
	const admissionGate = "yggdrasil.io/capacity-native-admitted"
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"namespace": realm, "name": "native-admission-key"}, "stringData": map[string]string{"key": admissionKey}})
	container := map[string]any{"name": "api", "image": image, "imagePullPolicy": "Never", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File",
		"env":          []map[string]any{{"name": "NATIVE_TERMINATION_PROJECTION_DIR", "value": "/native"}, {"name": "NATIVE_TERMINATION_IMAGE_DIGEST", "value": digest}, {"name": "NATIVE_FIXTURE_MODE", "value": "blocked_callback"}, {"name": "NATIVE_ADMISSION_ENABLED", "value": "true"}, {"name": "NATIVE_ADMISSION_KEY", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "native-admission-key", "key": "key"}}}},
		"volumeMounts": []map[string]any{{"name": "native", "mountPath": "/native", "readOnly": true}}}
	nativeTemplate := map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "native-core"}, "finalizers": []string{nativeFinalizer}}, "spec": map[string]any{"terminationGracePeriodSeconds": 30, "readinessGates": []map[string]string{{"conditionType": admissionGate}}, "containers": []map[string]any{container}, "volumes": []map[string]any{{"name": "native", "downwardAPI": map[string]any{"items": projection}}}}}
	template := nativeTemplate
	if mixed {
		oldImage, oldDigest := os.Getenv("NATIVE_OLD_FIXTURE_IMAGE"), os.Getenv("NATIVE_OLD_FIXTURE_DIGEST")
		if oldImage == "" || oldDigest == "" {
			t.Fatal("actual immutable qualified schema one fixture required")
		}
		template = map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "native-core"}, "finalizers": []string{nativeFinalizer}}, "spec": map[string]any{"containers": []map[string]any{{"name": "api", "image": oldImage, "imagePullPolicy": "Never", "env": []map[string]string{{"name": "NATIVE_TERMINATION_PROJECTION_DIR", "value": "/native"}, {"name": "NATIVE_TERMINATION_IMAGE_DIGEST", "value": oldDigest}}, "volumeMounts": []map[string]any{{"name": "native", "mountPath": "/native", "readOnly": true}}}}, "volumes": []map[string]any{{"name": "native", "downwardAPI": map[string]any{"items": projection}}}}}
	}
	deployment := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"namespace": realm, "name": workloadName}, "spec": map[string]any{"replicas": 3, "selector": map[string]any{"matchLabels": map[string]string{"app": "native-core"}}, "template": template}}
	nativeKindApply(t, ctx, deployment)
	// Custom readiness is not fabricated. Containers must actually enter the
	// running state while the native admission gate keeps SDK2 Pods unready.
	nativeKindAwait(t, ctx, func() bool {
		objects := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "app=native-core", "-o", "json")["items"].([]any)
		if len(objects) != 3 {
			return false
		}
		for _, item := range objects {
			pod := item.(map[string]any)
			status, _ := pod["status"].(map[string]any)
			cs, _ := status["containerStatuses"].([]any)
			if len(cs) != 1 {
				return false
			}
			state, _ := cs[0].(map[string]any)["state"].(map[string]any)
			if state["running"] == nil {
				return false
			}
		}
		return true
	})
	dep := nativeKindGet(t, ctx, "-n", realm, "get", "deployment", workloadName, "-o", "json")
	workloadUID := dep["metadata"].(map[string]any)["uid"].(string)
	var originalBaseline map[string]any
	if mixed {
		originalBaseline = nativeBirthBaseline(t, ctx, realm, os.Getenv("NATIVE_OLD_FIXTURE_IMAGE"))
	}
	birthBinding, adapterKubeconfig := nativeInstallBirthGuard(t, ctx, realm, workloadName, workloadUID, image)
	adapterKubeconfig, conflictCount := nativeReleaseConflictProxy(t, ctx, adapterKubeconfig, realm, forceConflict)
	if mixed {
		// Pause the real Deployment then update its existing native ReplicaSet
		// template. Its actual controller adds one current SDK2 candidate while
		// all three already booted SDK1 Pods retain their original spec/lifetime.
		nativeKindCommand(t, ctx, "-n", realm, "rollout", "pause", "deployment/"+workloadName)
		// The paused Deployment and its existing RS both declare the source-two
		// template before a new Pod is born. Existing schema-one lifetimes remain
		// unchanged; pausing prevents a rollout from replacing that baseline.
		deploymentPatch, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": nativeTemplate}})
		nativeKindCommand(t, ctx, "-n", realm, "patch", "deployment", workloadName, "--type=merge", "-p", string(deploymentPatch))
		sets := nativeKindGet(t, ctx, "-n", realm, "get", "replicasets", "-l", "app=native-core", "-o", "json")["items"].([]any)
		if len(sets) != 1 {
			t.Fatal("exact real baseline ReplicaSet unavailable")
		}
		rs := sets[0].(map[string]any)
		rsName := rs["metadata"].(map[string]any)["name"].(string)
		labels := rs["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["labels"].(map[string]any)
		labels["candidate"] = "sdk2"
		patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": labels, "finalizers": []string{nativeFinalizer}}, "spec": nativeTemplate["spec"]}}})
		nativeKindCommand(t, ctx, "-n", realm, "patch", "replicaset", rsName, "--type=merge", "-p", string(patch))
		nativeKindCommand(t, ctx, "-n", realm, "scale", "deployment/"+workloadName, "--replicas=4")
		nativeKindAwait(t, ctx, func() bool {
			objects := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "candidate=sdk2", "-o", "json")["items"].([]any)
			if len(objects) != 1 {
				return false
			}
			status, _ := objects[0].(map[string]any)["status"].(map[string]any)
			cs, _ := status["containerStatuses"].([]any)
			if len(cs) != 1 {
				return false
			}
			state, _ := cs[0].(map[string]any)["state"].(map[string]any)
			return state["running"] != nil
		})
	}
	owner := "native-core-owner"
	annotations := map[string]string{"yggdrasil.io/capacity-envelope-owner": owner, "yggdrasil.io/capacity-envelope-generation": "1", "yggdrasil.io/capacity-envelope-idempotency": "previous-native", "yggdrasil.io/capacity-envelope-protected-floor": "2", "yggdrasil.io/capacity-envelope-min": "3", "yggdrasil.io/capacity-envelope-max": "4"}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": map[string]any{"namespace": realm, "name": "api", "annotations": annotations}, "spec": map[string]any{"scaleTargetRef": map[string]string{"apiVersion": "apps/v1", "kind": "Deployment", "name": workloadName}, "minReplicas": 3, "maxReplicas": 4, "metrics": []map[string]any{{"type": "Resource", "resource": map[string]any{"name": "cpu", "target": map[string]any{"type": "Utilization", "averageUtilization": 80}}}}}})
	hpaObj := nativeKindGet(t, ctx, "-n", realm, "get", "hpa", "api", "-o", "json")
	hpaUID := hpaObj["metadata"].(map[string]any)["uid"].(string)
	nativeInstanceID := uuid.New()
	machineToken, eventToken, workflowToken := "native-ci-callback", "native-ci-events", "native-ci-workflow"
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED", "true")
	t.Setenv("YGGDRASIL_ENV", "development")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, workflowToken, "native-ci-runner", machineWorkflowRef{Namespace: realm, Name: "execute"}, machineWorkflowRef{Namespace: realm, Name: "admit"}))
	nativeCaps := []string{capacity.EnsureBoundHPAEnvelope, capacity.EnsureNativePodDrain, capacity.DestroyNativePodProtection}
	principal, _ := json.Marshal([]capacityMutationPrincipalConfig{{PrincipalID: "native-adapter", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))), IntegrationInstanceID: nativeInstanceID.String(), Capabilities: nativeCaps}})
	t.Setenv(capacityMutationPrincipalsEnv, string(principal))
	eventPrincipal, _ := json.Marshal([]eventPublisherPrincipalConfig{{PrincipalID: "native-events", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(eventToken))), AllowedEvents: []eventPublisherEventRef{{Provider: "kubernetes", InstanceID: nativeInstanceID.String(), EventType: "kubernetes.object.ensured"}, {Provider: "kubernetes", InstanceID: nativeInstanceID.String(), EventType: "kubernetes.object.destroyed"}}}})
	t.Setenv(eventPublisherPrincipalsEnv, string(eventPrincipal))
	var dispatchService *CapacityDispatchService
	coreHandler, err := New("native-source-ci", db, conn, zap.NewNop(), WithCapacityDispatchServiceReceiver(func(service *CapacityDispatchService) { dispatchService = service }))
	if err != nil {
		t.Fatal(err)
	}
	var redeemedAfterDrift atomic.Bool
	var heldAdapterAck, heldCallerAck atomic.Bool
	var staleWitness atomic.Int32
	var recoveryInventoryRace atomic.Int32
	var recoveryVictim atomic.Value
	coreServe := func(w http.ResponseWriter, r *http.Request) {
		if drift == "during" && r.URL.Path == capacityMutationBasePath+"/native/redeem" {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
			if err != nil || len(raw) > 8192 {
				t.Error("closed native redemption body unavailable")
				w.WriteHeader(400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var request model.CapacityNativeAuthorityRedeemRequest
			if json.Unmarshal(raw, &request) != nil {
				t.Error("closed native redemption decode failed")
				w.WriteHeader(400)
				return
			}
			if request.Capability == capacity.EnsureBoundHPAEnvelope && redeemedAfterDrift.CompareAndSwap(false, true) {
				if _, err := exec.CommandContext(ctx, "kubectl", "patch", "validatingwebhookconfiguration", "capacity-native-validate", "--type=json", "-p", `[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]`).CombinedOutput(); err != nil {
					t.Error("actual guarded authority corruption hook failed")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
		}
		if r.URL.Path == capacityMutationBasePath+"/native/result" && (mode == "forced_conflict_adapter_ack_held" || mode == "forced_conflict_source_changed_hold" || mode == "forced_conflict_rbac_revoked_hold") && heldAdapterAck.CompareAndSwap(false, true) {
			recorder := httptest.NewRecorder()
			coreHandler.ServeHTTP(recorder, r)
			assertNativeReleaseNoRecoveryBeforeCaller(t, r.Context(), db, realm)
			if mode == "forced_conflict_source_changed_hold" {
				if _, e := db.ExecContext(r.Context(), `UPDATE public.manifests SET checksum=$2 WHERE namespace=$1 AND kind='integration_instance' AND name='native-kubernetes'`, realm, strings.Repeat("f", 64)); e != nil {
					t.Error("native source drift fixture failed")
				}
			}
			if mode == "forced_conflict_rbac_revoked_hold" {
				if _, e := db.ExecContext(r.Context(), `UPDATE public.manifests SET active=false WHERE namespace=$1 AND kind='rbac'`, realm); e != nil {
					t.Error("current native RBAC refusal fixture failed")
				}
			}
			for key, values := range recorder.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		coreHandler.ServeHTTP(w, r)
	}
	var core *httptest.Server
	if protocolEnabled {
		core = httptest.NewTLSServer(http.HandlerFunc(coreServe))
	} else {
		core = httptest.NewServer(http.HandlerFunc(coreServe))
	}
	defer core.Close()
	trustPath := ""
	if protocolEnabled {
		trustPath = nativeCoreResultTrust(t, core)
	}
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
	if trustPath != "" {
		adapterCmd.Env = append(adapterCmd.Env, "SSL_CERT_FILE="+trustPath)
	}
	adapterCmd.Stdout, adapterCmd.Stderr = logFile, logFile
	if err := adapterCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adapterCmd.Process.Kill(); _ = adapterCmd.Wait() }()
	adapterURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	if mode == "forced_conflict_caller_ack_held" || mode == "forced_conflict_late_owner_hold" || mode == "stale_witness_unredeemed_original_retry" || mode == "forced_conflict_recovery_inventory_race" {
		upstream := adapterURL
		caller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, e := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
			closeErr := r.Body.Close()
			if e != nil || closeErr != nil || len(raw) > 2<<20 {
				w.WriteHeader(503)
				return
			}
			if mode == "forced_conflict_recovery_inventory_race" {
				operation, e := nativeRecoveryFrameExecuteRequest(r, raw)
				if e != nil {
					w.WriteHeader(503)
					return
				}
				if operation.Operation == capacity.DestroyNativePodProtection && operation.Input.PodName != "" {
					recoveryVictim.Store(operation.Input.PodName)
				}
				if operation.Operation == capacity.ObserveNativePodInventory && recoveryInventoryRace.Load() == 0 {
					var parents int
					if db.QueryRowContext(r.Context(), `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND state='rejected_no_effect' AND operation=$2`, realm, capacity.DestroyNativePodProtection).Scan(&parents) != nil {
						w.WriteHeader(503)
						return
					}
					if parents == 1 && recoveryInventoryRace.CompareAndSwap(0, 1) {
						name, known := recoveryVictim.Load().(string)
						// The original recovery witness has returned. Advance the REAL
						// same Pod RV before the original inventory read, once only.
						if !known || name == "" || exec.CommandContext(r.Context(), "kubectl", "-n", realm, "annotate", "pod", name, "fixture.yggdrasil.io/native-recovery-frame=original", "--overwrite").Run() != nil {
							t.Error("actual recovery witness/inventory race fixture failed")
							w.WriteHeader(503)
							return
						}
					}
				}
			}
			if mode == "stale_witness_unredeemed_original_retry" && staleWitness.Load() == 0 {
				var stale struct {
					Operation string `json:"operation"`
					Input     struct {
						PodName string `json:"pod_name"`
					} `json:"input"`
				}
				// Advance the REAL Pod RV after Core's current witness and before
				// the original adapter read, exactly once. Nothing is fabricated:
				// the adapter itself must refuse before any redemption.
				if json.Unmarshal(raw, &stale) == nil && stale.Operation == capacity.DestroyNativePodProtection && stale.Input.PodName != "" && staleWitness.CompareAndSwap(0, 1) {
					if exec.CommandContext(ctx, "kubectl", "-n", realm, "annotate", "pod", stale.Input.PodName, "fixture.yggdrasil.io/native-stale-witness=original", "--overwrite").Run() != nil {
						t.Error("actual stale native witness fixture failed")
						w.WriteHeader(503)
						return
					}
				}
			}
			request, e := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.Path, bytes.NewReader(raw))
			if e != nil {
				w.WriteHeader(503)
				return
			}
			request.GetBody = nil
			request.Header = r.Header.Clone()
			reply, e := http.DefaultClient.Do(request)
			if e != nil || reply == nil || reply.Body == nil {
				if reply != nil && reply.Body != nil {
					_ = reply.Body.Close()
				}
				w.WriteHeader(503)
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(reply.Body, 2<<20+1))
			closeErr = reply.Body.Close()
			if readErr != nil || closeErr != nil || len(body) > 2<<20 {
				w.WriteHeader(503)
				return
			}
			var operation struct {
				Operation string `json:"operation"`
			}
			if json.Unmarshal(raw, &operation) == nil && operation.Operation == capacity.DestroyNativePodProtection && conflictCount.Load() == 1 && heldCallerAck.CompareAndSwap(false, true) {
				assertNativeReleaseNoRecoveryBeforeCaller(t, r.Context(), db, realm)
				if mode == "forced_conflict_late_owner_hold" {
					<-r.Context().Done()
					return
				}
			}
			for key, values := range reply.Header {
				w.Header()[key] = values
			}
			w.WriteHeader(reply.StatusCode)
			_, _ = w.Write(body)
		}))
		defer caller.Close()
		adapterURL = caller.URL
	}
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
	nativeConfig := map[string]any{"base_url": adapterURL, "kubeconfig_path": adapterKubeconfig, "current_birth_guard_bindings": []map[string]any{birthBinding}, "capacity_authority_url": core.URL, "capacity_envelope_targets": []map[string]any{{"namespace": realm, "hpa_name": "api", "hpa_uid": hpaUID, "workload_name": workloadName, "workload_uid": workloadUID, "owner": owner, "protected_floor": 2, "maximum_replicas": 4, "adoption_allowed": false, "surplus_max_age_seconds": 180}}, "capacity_pod_targets": []map[string]any{{"binding_name": "api-native", "namespace": realm, "workload_name": workloadName, "workload_uid": workloadUID, "owner": owner, "container_name": "api", "image_digest": digest, "lanes": []string{"listener", "requests", "signal", "workers"}, "projection_directory": "/native", "admission_mode": "process_v2", "admission_port": 8080}}}
	if protocolEnabled {
		nativeConfig["native_release_result_protocol"] = capacity.NativeReleaseResultProtocol
		nativeConfig["native_release_source_commit"] = compiledSource
	}
	// The registered instance uses the actual predetermined machine scope UUID.
	specRaw, _ := json.Marshal(model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: nativeConfig, Credentials: map[string]any{"capacity_mutation_token": machineToken, "capacity_admission_key": admissionKey}})
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
	birthResult, birthErr := message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{Integration: model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: capacity.ObserveCurrentBirthGuard, Capability: capacity.ObserveCurrentBirthGuard, Input: map[string]any{"binding_name": "api-birth"}})
	var birth model.CurrentBirthGuardObservation
	if birthErr != nil || capacity.DecodeNativeCapacity(birthResult.Output, &birth) != nil || birth.BindingSHA256 == "" {
		t.Fatal("actual installed birth guard readback refused", birthErr)
	}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "native-core", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/native-core", Owner: owner, Workflow: model.ManifestSelector{Namespace: realm, Name: "execute"}, Currency: "USD", Floor: 2, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 180, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Profiles: []model.CapacityProfile{{Name: "reserved", Provider: "kubernetes", Region: "fixture-only", MinUnits: 2, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:source-qualification-only"}}, Signals: []model.CapacitySignalRule{{Name: "admission_pressure", SourceIdentity: "fixture/prom/native", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: nativeBinding, Namespace: realm, HPAName: "api", HPAUID: hpaUID, WorkloadName: workloadName, WorkloadUID: workloadUID, Owner: owner, Profile: "reserved", ProtectedFloor: 2, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "admission_pressure", Adapter: metricBinding, BindingName: "admission", BindingSHA256: metric.BindingSHA256}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", BirthGuardBinding: "api-birth", BirthGuardSHA256: birth.BindingSHA256, ContainerName: "api", ImageDigest: digest, Lanes: []string{"listener", "requests", "signal", "workers"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: realm, Name: "admit"}}}
	create("rbac", "native-rbac", map[string]any{"roles": []any{map[string]any{"name": "native", "rules": []any{map[string]any{"effect": "allow", "resources": []string{"workflow:" + realm + ":execute", "workflow:" + realm + ":admit"}, "actions": []string{"run"}}}}}, "bindings": []any{map[string]any{"name": "ci-only", "subjects": []any{map[string]string{"type": "service", "id": "native-ci-runner"}}, "roles": []string{"native"}}}})
	noNativeInputs := false
	pressureSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: "native-rbac"}}, InputSchema: model.WorkflowInputSchemaSpec{Properties: map[string]model.IntegrationSchemaProperty{}, AdditionalProperties: &noNativeInputs}, Steps: []model.WorkflowStepSpec{{ID: "native", TimeoutSeconds: 180, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, With: map[string]any{"policy": map[string]string{"namespace": realm, "name": "native-policy"}}}}}
	if scheduled {
		t.Setenv(CapacityDispatchEnabledEnv, "true")
		p.ControllerBinding = &model.CapacityControllerBinding{Mode: repository.CapacityDispatchProtocol, MachinePrincipalID: "native-ci-runner", DispatchLeaseSeconds: 90}
		enabled := true
		pressureSpec.Trigger = model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", Timezone: "UTC"}}
		pressureSpec.InputSchema.Properties = map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}
	}
	pressureWorkflow := create("workflow", "execute", pressureSpec)
	create("workflow", "admit", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: "native-rbac"}}, InputSchema: model.WorkflowInputSchemaSpec{Properties: map[string]model.IntegrationSchemaProperty{}, AdditionalProperties: &noNativeInputs}, Steps: []model.WorkflowStepSpec{{ID: "admission", TimeoutSeconds: 180, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.admit_bound"}, With: map[string]any{"policy": map[string]string{"namespace": realm, "name": "native-policy"}}}}})
	if protocolEnabled {
		p.HPAExecutionBinding.ReleaseRecovery = &model.CapacityNativeReleaseRecoveryBinding{Protocol: capacity.NativeReleaseResultProtocol, AdapterSourceCommit: compiledSource}
	}
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
		{instance, capacity.ObserveNativePodAdmissionCandidates, map[string]any{"binding_name": "api-native"}},
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
		case capacity.ObserveNativePodAdmissionCandidates:
			var source model.AdapterCapacityPodAdmissionCandidatesResponse
			if err := capacity.DecodeNativeCapacity(result.Output, &source); err != nil {
				t.Fatalf("actual native inventory closed source: %v", err)
			}
			if err := capacity.NativeAdmissionCandidates(p, source, time.Now().UTC()); err != nil {
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
		res, err := core.Client().Do(req)
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
	var scheduledTick int
	run := func(workflow string, succeed bool) {
		if scheduled && workflow == "execute" {
			if dispatchService == nil {
				t.Fatal("same owning dispatch service absent")
			}
			scheduledTick++
			tick := now.Truncate(time.Minute).Add(time.Duration(scheduledTick-20) * time.Minute)
			prepared, err := dispatchService.PrepareScheduledTick(ctx, pressureWorkflow.ID, tick)
			if err != nil || prepared == nil {
				t.Fatal("current principal/native scheduled preparation refused", err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			won, err := repository.UpsertWorkflowScheduleState(ctx, tx, pressureWorkflow.ID.String(), tick, tick.Add(time.Minute))
			if err != nil || !won {
				t.Fatal("original scheduled tick not admitted", err)
			}
			job, _, err := prepared.Enqueue(ctx, tx)
			if err != nil || tx.Commit() != nil {
				t.Fatal("same native tick/run/job transaction failed", err)
			}
			ran, err := dispatchService.RunOne(ctx, realm, p.Environment)
			if err != nil || !ran {
				t.Fatal("actual original scheduled native invocation unresolved", err)
			}
			record, err := repository.GetWorkflowRun(ctx, db, job.RunID)
			var acknowledged bool
			if err != nil || db.QueryRowContext(ctx, `SELECT state='returned' AND finalization_ack_at IS NOT NULL FROM public.capacity_dispatch_jobs WHERE id=$1`, job.JobID).Scan(&acknowledged) != nil || !acknowledged || (record.Status == "succeeded") != succeed {
				t.Fatal("actual source return/ack/native workflow outcome missing", err)
			}
			if record.Result == nil || record.Result.Workflow.ID != pressureWorkflow.ID || record.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != "native-ci-runner" {
				t.Fatal("scheduled native result lost original authorization/source")
			}
			t.Log("same private admission/worker reached original native HPA/SDK executor; scheduler cron covered separately in native PG, not whole Core main startup")
			return
		}
		request["workflow"] = map[string]string{"namespace": realm, "name": workflow}
		code, out := post(workflowToken, request)
		if code != 202 {
			t.Fatalf("native protected dispatch %d %#v", code, out)
		}
		runID, _ := out["run_id"].(string)
		nativeKindAwait(t, ctx, func() bool {
			var status string
			var result []byte
			if db.QueryRowContext(ctx, `SELECT status,COALESCE(result,'{}'::jsonb) FROM public.workflow_runs WHERE id=$1`, runID).Scan(&status, &result) != nil {
				return false
			}
			if status == "pending" || status == "running" || status == "queued" {
				return false
			}
			if (status == "succeeded") != succeed {
				// Keep exact native diagnostics in this isolated CI fixture. The
				// production protected endpoint retains its detail-free refusal.
				store := repository.CapacityStore{DB: db}
				intent, observeErr := store.Observe(ctx, policy)
				t.Logf("native intent phase=%s decision=%s generation=%d observe=%v", intent.Phase, intent.Decision.Action, intent.Generation, observeErr)
				_, checkpoints, ledgerErr := store.NativeLedger(ctx, policy, intent)
				t.Logf("native retained origins=%d ledger=%v", len(checkpoints), ledgerErr)
				var inventory model.AdapterCapacityPodInventoryResponse
				native, nativeErr := message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{Integration: model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: capacity.ObserveNativePodInventory, Capability: capacity.ObserveNativePodInventory, Input: map[string]any{"binding_name": "api-native"}})
				decodeErr := capacity.DecodeNativeCapacity(native.Output, &inventory)
				t.Logf("native complete inventory status=%s transport=%v decode=%v binding=%v", native.Status, nativeErr, decodeErr, capacity.NativePodInventory(p, inventory, time.Now().UTC()))
				for _, cp := range checkpoints {
					request := model.AdapterObserveCapacityPodAdmissionRequest{BindingName: "api-native", PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount}
					raw, _ := json.Marshal(request)
					var input map[string]any
					_ = json.Unmarshal(raw, &input)
					native, readErr := message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{Integration: model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: capacity.ObserveNativePodAdmission, Capability: capacity.ObserveNativePodAdmission, Input: input})
					var ack model.AdapterCapacityPodAdmissionResponse
					decodeErr := capacity.DecodeNativeCapacity(native.Output, &ack)
					t.Logf("native origin pod=%s state=%s read=%v decode=%v checkpoint=%v roots=%s readiness=%t", cp.PodName, cp.State, readErr, decodeErr, capacity.NativeProcessAdmissionCheckpoint(p, cp, ack, time.Now().UTC()), ack.Admission.State, ack.Observation.AdmissionReady)
				}
				t.Fatalf("actual native workflow %s status=%s: %s", workflow, status, result)
			}
			return true
		})
	}
	run("admit", true)
	store := repository.CapacityStore{DB: db}
	var admitted int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=$1 AND checkpoint_record->>'state'='admitted' AND checkpoint_record->>'process_nonce'<>'' AND checkpoint_record->'root_acknowledgement'->'admission'->>'state'='roots_open'`, realm).Scan(&admitted) != nil {
		t.Fatal("actual admitted lifetime read failed")
	}
	if mixed {
		if admitted != 1 {
			t.Fatalf("mixed bootstrap invented old SDK1 process origins: %d", admitted)
		}
		nativeBirthCheckBaseline(t, ctx, realm, originalBaseline)
		run("execute", false)
		nativeBirthCheckBaseline(t, ctx, realm, originalBaseline)
		var writes int
		if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND operation=$2`, realm, capacity.EnsureBoundHPAEnvelope).Scan(&writes) != nil || writes != 0 {
			t.Fatal("mixed bootstrap gained pressure/HPA permission", writes)
		}
		t.Log("actual SDK2 candidate admitted while old schema one baseline remains native-running, unqualified and pressure-frozen")
		return
	}
	if admitted != 3 {
		t.Fatal("full baseline was not actually admitted", admitted)
	}
	nativeKindCommand(t, ctx, "-n", realm, "rollout", "status", "deployment/"+workloadName, "--timeout=60s")
	if drift != "" {
		// Prime the actual protected planner's sustained-surplus window. A
		// first HOLD is a successful read, not a reached mutation boundary.
		run("execute", true)
		primed, primeErr := store.Observe(ctx, policy)
		var initialCommands int
		if primeErr != nil || primed.Decision.Action != "hold" || primed.Decision.Reason != "down_window_pending" || db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND operation=$2`, realm, capacity.EnsureBoundHPAEnvelope).Scan(&initialCommands) != nil || initialCommands != 0 {
			t.Fatal("guard adversary did not prime the real read-only hold window", primeErr, initialCommands)
		}
		time.Sleep(1200 * time.Millisecond)
		if drift == "before" {
			nativeKindCommand(t, ctx, "patch", "validatingwebhookconfiguration", "capacity-native-validate", "--type=json", "-p", `[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]`)
		}
		run("execute", false)
		current := nativeKindGet(t, ctx, "-n", realm, "get", "hpa", "api", "-o", "json")
		if current["spec"].(map[string]any)["minReplicas"] != float64(3) {
			t.Fatal("drifted current birth authority changed reserved HPA minimum")
		}
		var commands, uncertainRedeemed int
		if db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='uncertain' AND command_record->>'redeemed_by'='native-adapter' AND command_record->>'attempt_id' IS NOT NULL AND command_record->>'attempt_id'<>'00000000-0000-0000-0000-000000000000') FROM public.capacity_native_commands WHERE namespace=$1 AND operation=$2`, realm, capacity.EnsureBoundHPAEnvelope).Scan(&commands, &uncertainRedeemed) != nil {
			t.Fatal("actual native authority ledger read failed")
		}
		if drift == "before" && commands != 0 {
			t.Fatal("invalid current guard reached native command authority")
		}
		if drift == "during" && (!redeemedAfterDrift.Load() || commands != 1 || uncertainRedeemed != 1) {
			t.Fatal("actual native redemption hook was not exercised", commands, uncertainRedeemed)
		}
		t.Log("actual installed guard refused before authority or after consumed redemption; HPA minimum unchanged")
		return
	}
	run("execute", true)
	time.Sleep(1200 * time.Millisecond)
	run("execute", true)
	intent, err := store.Observe(ctx, policy)
	if err != nil || intent.Phase != "envelope_applied" || len(intent.NativePodBaseline) != 3 {
		t.Fatal("reservation/lifetime separation missing", intent.Phase, len(intent.NativePodBaseline), err)
	}
	objects := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "app=native-core", "-o", "json")["items"].([]any)
	names := []string{}
	podsByName := map[string]map[string]any{}
	for _, item := range objects {
		pod := item.(map[string]any)
		meta := pod["metadata"].(map[string]any)
		name := meta["name"].(string)
		names = append(names, name)
		podsByName[name] = pod
		finalizers := meta["finalizers"].([]any)
		found := false
		for _, value := range finalizers {
			found = found || value == nativeFinalizer
		}
		if !found || meta["annotations"].(map[string]any)["yggdrasil.io/capacity-drain-challenge"] == nil {
			t.Fatal("HPA CAS preceded baseline protection")
		}
	}
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatal("actual full baseline membership changed")
	}
	victimName, victimUID := names[0], podsByName[names[0]]["metadata"].(map[string]any)["uid"].(string)
	oldSelectedUID := victimUID
	for _, name := range names[1:] {
		uid := podsByName[name]["metadata"].(map[string]any)["uid"].(string)
		if uid > victimUID {
			victimName, victimUID = name, uid
		}
		if uid < oldSelectedUID {
			oldSelectedUID = uid
		}
	}
	if victimUID == oldSelectedUID {
		t.Fatal("controller adversary did not differ from old selected subset")
	}
	for _, name := range names {
		cost := "10000"
		if name == victimName {
			cost = "-10000"
		}
		nativeKindCommand(t, ctx, "-n", realm, "annotate", "pod", name, "controller.kubernetes.io/pod-deletion-cost="+cost, "--overwrite")
	}
	// Retain the actual terminal native object with an independently owned
	// finalizer. Core must remove only its own protection and keep HOLD readable.
	const fixtureFinalizer = "qualification.dakasa.io/held-native-deletion"
	victim := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
	victimMeta := victim["metadata"].(map[string]any)
	retainedFinalizers := append(victimMeta["finalizers"].([]any), fixtureFinalizer)
	patchFinalizers, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": victimUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": victimMeta["resourceVersion"]}, {"op": "replace", "path": "/metadata/finalizers", "value": retainedFinalizers}})
	nativeKindCommand(t, ctx, "-n", realm, "patch", "pod", victimName, "--type=json", "-p", string(patchFinalizers))
	// The envelope min is a reservation, not a scale command. This native CI
	// action asks the real Deployment/ReplicaSet controller to reduce replicas.
	// The cost is only an adversary input; actual victim UID proves selection.
	nativeKindCommand(t, ctx, "-n", realm, "scale", "deployment/"+workloadName, "--replicas=2")
	nativeKindAwait(t, ctx, func() bool {
		pod := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
		meta := pod["metadata"].(map[string]any)
		return meta["uid"] == victimUID && meta["deletionTimestamp"] != nil
	})
	// Read-only diagnostics, never an oracle: every later version of the victim
	// Pod with its arrival time and the managedFields entry it adds, and on
	// failure the durable release ledger of that Pod. They name the window and
	// the writer of an advanced resourceVersion; they decide nothing.
	victimVersions := nativeKindWatchPod(t, ctx, realm, victimName)
	defer func() {
		for _, line := range nativeKindPodTimelineLines(victimVersions()) {
			t.Logf("native victim pod version %s", line)
		}
		if t.Failed() {
			nativeKindLogReleaseLedger(t, db, realm, victimUID)
		}
	}()
	var cpRaw []byte
	if db.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND pod_uid=$2`, realm, victimUID).Scan(&cpRaw) != nil {
		t.Fatal("controller selected an unretained baseline")
	}
	var checkpoint model.CapacityNativePodCheckpoint
	if json.Unmarshal(cpRaw, &checkpoint) != nil || checkpoint.State != "admitted" || checkpoint.ConfirmedAt != nil {
		t.Fatal("controller victim had no immutable actual admitted origin")
	}
	held := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
	cs := held["status"].(map[string]any)["containerStatuses"].([]any)
	if cs[0].(map[string]any)["state"].(map[string]any)["running"] == nil {
		t.Fatal("actual native held callback was not observed")
	}
	var releases int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND operation=$2`, realm, capacity.DestroyNativePodProtection).Scan(&releases) != nil || releases != 0 {
		t.Fatal("held native lifetime released before actual return")
	}
	nativeKindAwait(t, ctx, func() bool {
		pod := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
		statuses := pod["status"].(map[string]any)["containerStatuses"].([]any)
		return statuses[0].(map[string]any)["state"].(map[string]any)["terminated"] != nil
	})
	terminated := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
	status := terminated["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["state"].(map[string]any)["terminated"].(map[string]any)
	var receipt model.NativePodTerminationReceipt
	if status["exitCode"] != float64(0) || json.Unmarshal([]byte(status["message"].(string)), &receipt) != nil || receipt.SchemaVersion != 2 || receipt.ProcessNonce != checkpoint.ProcessNonce || receipt.RootAdmission != "previously_opened" || len(receipt.Lanes) != 4 {
		t.Fatal("actual current SDK2 termination receipt unavailable", status)
	}
	if mode == "forced_conflict_source_changed_hold" || mode == "forced_conflict_rbac_revoked_hold" || mode == "forced_conflict_late_owner_hold" {
		beforeIDs := nativeReleaseIdentityCount(t, ctx, db, realm)
		run("execute", false)
		// Only original refusals proven unredeemed before the single redeemed
		// parent may precede it; any further identity is replacement authority.
		predecessors := nativeReleaseUnredeemedPredecessors(t, ctx, db, realm, victimUID)
		if conflictCount.Load() != 1 || nativeReleaseIdentityCount(t, ctx, db, realm) != beforeIDs+1+predecessors {
			t.Fatal("failed current source/RBAC/owner created replacement authority", predecessors)
		}
		var decisions int
		if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions d JOIN public.capacity_native_command_identities i ON i.id=d.command_id WHERE i.namespace=$1`, realm).Scan(&decisions) != nil || decisions != 0 {
			t.Fatal("HOLD condition admitted a recovery subdecision")
		}
		return
	}
	run("execute", true)
	if forceConflict {
		assertNativeReleaseRecoveryIdentities(t, ctx, db, realm, compiledSource, conflictCount.Load())
	}
	if mode == "forced_conflict_recovery_inventory_race" && recoveryInventoryRace.Load() != 1 {
		t.Fatal("native witness/inventory race was not injected exactly once")
	}
	if mode == "stale_witness_unredeemed_original_retry" {
		assertNativeReleaseStaleWitnessRetry(t, ctx, db, realm, victimUID, staleWitness.Load(), adapterLog)
	}
	retained := nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
	retainedMeta := retained["metadata"].(map[string]any)
	remainingFinalizers := retainedMeta["finalizers"].([]any)
	if retainedMeta["uid"] != victimUID || len(remainingFinalizers) != 1 || remainingFinalizers[0] != fixtureFinalizer {
		t.Fatal("Core removed foreign protection or retained its own finalizer")
	}
	beforeHold, archived := nativeKindReleaseSnapshot(t, ctx, db, realm, victimUID, policy, p)
	if archived {
		t.Fatal("first original release was not retained before terminal compaction")
	}
	run("execute", true)
	afterHold, archived := nativeKindReleaseSnapshot(t, ctx, db, realm, victimUID, policy, p)
	if !archived || !bytes.Equal(beforeHold, afterHold) {
		t.Fatal("terminal HOLD changed an original native command, identity or bundle")
	}
	run("execute", true)
	afterRepeatedHold, archived := nativeKindReleaseSnapshot(t, ctx, db, realm, victimUID, policy, p)
	if !archived || !bytes.Equal(beforeHold, afterRepeatedHold) {
		t.Fatal("repeated archived HOLD introduced an identity, attempt or bundle")
	}
	// The fixture removes only its own native finalizer after the actual
	// read-only HOLD. This is cleanup, never a Core Pod DELETE/capacity witness.
	retained = nativeKindGet(t, ctx, "-n", realm, "get", "pod", victimName, "-o", "json")
	retainedMeta = retained["metadata"].(map[string]any)
	patchFinalizers, _ = json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": victimUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": retainedMeta["resourceVersion"]}, {"op": "test", "path": "/metadata/finalizers", "value": []string{fixtureFinalizer}}, {"op": "replace", "path": "/metadata/finalizers", "value": []string{}}})
	nativeKindCommand(t, ctx, "-n", realm, "patch", "pod", victimName, "--type=json", "-p", string(patchFinalizers))
	var released, grants int
	if db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=$1 AND checkpoint_record->>'state'='released' AND checkpoint_record->>'confirmed_at' IS NOT NULL)+(SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE namespace=$1 AND bundle_record->'checkpoint'->>'state'='released' AND bundle_record->'checkpoint'->>'confirmed_at' IS NOT NULL)`, realm).Scan(&released) != nil || released != 1 {
		t.Fatal("missing durable exact controller-selected lifetime ACK", released)
	}
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND phase='terminate'`, realm).Scan(&releases) != nil || releases != 0 {
		t.Fatal("lifetime executor issued a selected Pod DELETE")
	}
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, realm).Scan(&grants) != nil || grants != 0 {
		t.Fatal("reserved envelope created VM authority")
	}
	for _, name := range names {
		if name == victimName {
			continue
		}
		pod := nativeKindGet(t, ctx, "-n", realm, "get", "pod", name, "-o", "json")
		if pod["metadata"].(map[string]any)["deletionTimestamp"] != nil {
			t.Fatal("additional baseline retired outside observed controller selection")
		}
	}
	t.Log("complete baseline protected before HPA CAS; actual adversarial controller victim currentTerm/SDK2 join then durable ACK and one-use finalizer release; alive origins retained")

}

// A refused, never-redeemed permission remains a permanent identity. The
// invariant is one original confirmed release, not one issued sequence. A HOLD
// may move the exact hot records into the immutable archive, so compare the
// complete logical bundle and identity rows, independently of storage location.
// Confirmed here means native readback; the schema has no caller-return or
// writer-quiescence field, and this fixture does not invent either proof.
func nativeKindReleaseSnapshot(t *testing.T, ctx context.Context, db *sql.DB, realm, subject string, policy model.Manifest, p model.CapacityPolicySpec) ([]byte, bool) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal("original native snapshot transaction unavailable", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT checkpoint_record,origin_generation,''::text,NULL::jsonb,''::text
		FROM public.capacity_native_lifetimes WHERE namespace=$1 AND pod_uid=$2
		UNION ALL SELECT bundle_record->'checkpoint',origin_generation,origin_sha256,bundle_record,bundle_sha256
		FROM public.capacity_native_lifetime_archive WHERE namespace=$1 AND pod_uid=$2`, realm, subject)
	if err != nil {
		t.Fatal("original native checkpoint/archive query unavailable", err)
	}
	var checkpointRaw, archiveRaw []byte
	var generation int64
	var originSHA, bundleSHA string
	checkpoints := 0
	for rows.Next() {
		if err = rows.Scan(&checkpointRaw, &generation, &originSHA, &archiveRaw, &bundleSHA); err != nil {
			rows.Close()
			t.Fatal("original native checkpoint/archive row unavailable", err)
		}
		checkpoints++
	}
	err = rows.Err()
	rows.Close()
	var checkpoint model.CapacityNativePodCheckpoint
	decodeRan := err == nil && checkpoints == 1
	var decodeErr error
	if decodeRan {
		decodeErr = capacity.DecodeNativeCapacity(json.RawMessage(checkpointRaw), &checkpoint)
	}
	if err != nil || checkpoints != 1 || decodeErr != nil || checkpoint.PodUID != subject || checkpoint.Namespace != realm || checkpoint.PolicyID != policy.ID || checkpoint.PolicyChecksum != policy.Checksum || checkpoint.IntentGeneration != generation || checkpoint.State != "released" || checkpoint.ConfirmedAt == nil || len(checkpoint.NativeTerminationReceipt) == 0 {
		// Only facts from the SAME original SQL reply and the ORIGINAL decode.
		// No opaque cause/body/identity is reflected; unknown decoded fields
		// remain omitted instead of becoming successful zero-value predicates.
		facts := map[string]any{"rows_ok": err == nil, "row_count": checkpoints, "decode_ran": decodeRan, "decode_ok": decodeRan && decodeErr == nil, "bytes": len(checkpointRaw), "sha256": fmt.Sprintf("%x", sha256.Sum256(checkpointRaw))}
		if decodeRan && decodeErr == nil {
			facts["uid_equal"] = checkpoint.PodUID == subject
			facts["namespace_equal"] = checkpoint.Namespace == realm
			facts["policy_equal"] = checkpoint.PolicyID == policy.ID
			facts["checksum_equal"] = checkpoint.PolicyChecksum == policy.Checksum
			facts["origin_generation_equal"] = checkpoint.IntentGeneration == generation
			facts["released"] = checkpoint.State == "released"
			facts["confirmed_at_present"] = checkpoint.ConfirmedAt != nil
			facts["termination_bytes_present"] = len(checkpoint.NativeTerminationReceipt) != 0
		}
		diagnostic, _ := json.Marshal(facts)
		t.Logf("original release checkpoint safe predicates: %s", diagnostic)
		t.Fatal("exact original released checkpoint missing, duplicated or changed", checkpoints, err)
	}
	var originalWitness model.AdapterCapacityPodTerminationResponse
	if capacity.DecodeNativeCapacity(checkpoint.NativeTerminationReceipt, &originalWitness) != nil || originalWitness.Operation != capacity.ObserveNativePodTermination || originalWitness.Status != "observed" || capacity.NativePodWitness(p, checkpoint, originalWitness.Observation, *checkpoint.ConfirmedAt) != nil {
		t.Fatal("released original checkpoint lost its exact SDK/process termination witness")
	}
	archived := len(archiveRaw) != 0
	if archived && originSHA != checkpoint.OriginChallengeSHA256 {
		t.Fatal("original archived native challenge hash changed")
	}
	rows, err = tx.QueryContext(ctx, `SELECT row_to_json(i),h.command_record,a.command_record,a.record_sha256
		FROM public.capacity_native_command_identities i
		LEFT JOIN public.capacity_native_commands h ON h.id=i.id
		LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id
		WHERE i.namespace=$1 AND i.subject_uid=$2
		ORDER BY COALESCE(h.updated_at,(a.command_record->>'updated_at')::timestamptz),i.id`, realm, subject)
	if err != nil {
		t.Fatal("complete original native identity query unavailable", err)
	}
	identities, commands := []json.RawMessage{}, []json.RawMessage{}
	confirmed, refused, rejected := 0, 0, 0
	for rows.Next() {
		var identityRaw, hotRaw, coldRaw []byte
		var archiveSHA sql.NullString
		if err = rows.Scan(&identityRaw, &hotRaw, &coldRaw, &archiveSHA); err != nil {
			rows.Close()
			t.Fatal("complete original native identity/command row unavailable", err)
		}
		if (len(hotRaw) == 0) == (len(coldRaw) == 0) || archived != (len(coldRaw) != 0) {
			rows.Close()
			t.Fatal("original command is missing, duplicated or outside its checkpoint storage")
		}
		commandRaw := hotRaw
		if archived {
			commandRaw = coldRaw
		}
		canonical := nativeKindCanonicalJSON(t, commandRaw)
		if archived && (!archiveSHA.Valid || archiveSHA.String != fmt.Sprintf("%x", sha256.Sum256(canonical))) {
			rows.Close()
			t.Fatal("immutable original archived command hash changed")
		}
		var command model.CapacityNativeCommand
		// UpdatedAt is the durable confirmation/refusal timestamp. Recovery
		// under a new lease may record it after the original permission expires;
		// it cannot certify the original redemption or caller-return time.
		if capacity.DecodeNativeCapacity(json.RawMessage(commandRaw), &command) != nil || command.CommandID == uuid.Nil || command.PolicyID != policy.ID || command.PolicyChecksum != policy.Checksum || command.Namespace != realm || command.Environment != p.Environment || command.Domain != p.Domain || command.Dimension != p.Dimension || command.Adapter != p.AssessmentBinding.Snapshot.Adapter || command.AdapterPrincipalID != p.HPAExecutionBinding.AdapterPrincipalID || command.CreatedAt.IsZero() || command.UpdatedAt.Before(command.CreatedAt) || !command.ExpiresAt.After(command.CreatedAt) {
			rows.Close()
			t.Fatal("original native command identity, deadline or completed readback refused")
		}
		expectedIdentity, err := json.Marshal(map[string]any{"id": command.CommandID, "namespace": command.Namespace, "environment": command.Environment, "domain": command.Domain, "dimension": command.Dimension, "generation": command.IntentGeneration, "operation": command.Operation, "subject_uid": subject, "phase": command.Phase, "sequence": command.Sequence, "authority_token_sha256": command.AuthorityTokenSHA256, "request_sha256": command.RequestSHA256})
		if err != nil || !bytes.Equal(nativeKindCanonicalJSON(t, identityRaw), nativeKindCanonicalJSON(t, expectedIdentity)) || command.RequestSHA256 != fmt.Sprintf("%x", sha256.Sum256(nativeKindCanonicalJSON(t, command.Request))) {
			rows.Close()
			t.Fatal("permanent native identity or request hash differs from the original command")
		}
		switch command.State {
		case "confirmed":
			if command.AttemptID == uuid.Nil || command.RedeemedBy != p.HPAExecutionBinding.AdapterPrincipalID || len(command.NativeReadback) == 0 || bytes.Equal(bytes.TrimSpace(command.NativeReadback), []byte("null")) {
				rows.Close()
				t.Fatal("confirmed original command lacks its actual redemption/readback")
			}
		case "rejected_no_effect":
			var original model.CapacityNativeReleaseResult
			if p.HPAExecutionBinding.ReleaseRecovery == nil || command.ReleaseProtocol != capacity.NativeReleaseResultProtocol || command.AdapterSourceCommit != p.HPAExecutionBinding.ReleaseRecovery.AdapterSourceCommit || command.CallerReturnObservedAt == nil || !command.CallerReturnObservedAt.Before(command.ExpiresAt) || capacity.DecodeNativeCapacity(command.OriginalResult, &original) != nil || command.OriginalResultSHA256 != fmt.Sprintf("%x", sha256.Sum256(nativeKindCanonicalJSON(t, command.OriginalResult))) || original.CommandID != command.CommandID || original.AttemptID != command.AttemptID || original.RequestSHA256 != command.RequestSHA256 || original.ReturnNonce != "" || original.OriginalStatus != 409 || original.Outcome != "rejected_no_effect" || !original.OneSend || !original.DoReturned || !original.ReadReturned || !original.CloseReturned {
				rows.Close()
				t.Fatal("rejected original lost dual ACKs or native result identity")
			}
		case "refused_no_redemption":
			if command.AttemptID != uuid.Nil || command.RedeemedBy != "" || (len(command.NativeReadback) != 0 && !bytes.Equal(bytes.TrimSpace(command.NativeReadback), []byte("null"))) {
				rows.Close()
				t.Fatal("refused original command gained a redemption, attempt or readback")
			}
		default:
			rows.Close()
			t.Fatal("unknown, issued, redeemed or late command cannot certify terminal HOLD", command.State)
		}
		if command.Phase == "release" {
			var request model.AdapterDestroyCapacityPodDrainProtectionRequest
			if command.Operation != capacity.DestroyNativePodProtection || capacity.DecodeNativeCapacity(command.Request, &request) != nil || request.ExpectedPodUID != subject || request.ExpectedContainerID != checkpoint.ContainerID || !request.ExpectedContainerStartedAt.Equal(checkpoint.ContainerStartedAt) || request.ExpectedRestartCount != checkpoint.RestartCount {
				rows.Close()
				t.Fatal("original release operation or current process identity changed")
			}
			switch command.State {
			case "confirmed":
				var readback model.AdapterCapacityPodTerminationResponse
				if capacity.DecodeNativeCapacity(command.NativeReadback, &readback) != nil || readback.Operation != capacity.ObserveNativePodTermination || readback.Status != "observed" || readback.Observation.State != "unprotected" || readback.Observation.PodUID != subject || capacity.NativePodReleaseTarget(p, checkpoint, readback.Observation, command.UpdatedAt) != nil {
					rows.Close()
					t.Fatal("original confirmed release lacks the exact completed native removal readback")
				}
				confirmed++
			case "refused_no_redemption":
				refused++
			case "rejected_no_effect":
				rejected++
			}
		}
		identities = append(identities, nativeKindCanonicalJSON(t, identityRaw))
		commands = append(commands, canonical)
	}
	err = rows.Err()
	rows.Close()
	var durableRejected int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_results r JOIN public.capacity_native_command_identities i ON i.id=r.command_id WHERE i.namespace=$1 AND i.subject_uid=$2 AND r.adapter_ack_at IS NOT NULL AND r.caller_ack_at IS NOT NULL AND r.adapter_result->>'outcome'='rejected_no_effect'`, realm, subject).Scan(&durableRejected) != nil || durableRejected != rejected {
		t.Fatal("original rejected result lost durable dual acknowledgements")
	}
	if err != nil || confirmed != 1 || len(commands) != len(identities) {
		t.Fatal("original native release lacks exactly one confirmed attempt", confirmed, refused, err)
	}
	bundle, err := json.Marshal(map[string]any{"checkpoint": json.RawMessage(checkpointRaw), "commands": commands})
	if err != nil {
		t.Fatal("original native bundle encoding unavailable", err)
	}
	bundle = nativeKindCanonicalJSON(t, bundle)
	if archived && (!bytes.Equal(bundle, nativeKindCanonicalJSON(t, archiveRaw)) || bundleSHA != fmt.Sprintf("%x", sha256.Sum256(bundle))) {
		t.Fatal("immutable terminal bundle differs from its complete original SQL rows")
	}
	snapshot, err := json.Marshal(map[string]any{"identities": identities, "bundle": json.RawMessage(bundle)})
	if err != nil || tx.Commit() != nil {
		t.Fatal("original native snapshot did not complete", err)
	}
	snapshot = nativeKindCanonicalJSON(t, snapshot)
	t.Logf("actual native SQL release confirmed=%d refused_no_redemption=%d rejected_no_effect=%d archived=%t snapshot_sha256=%x snapshot=%s", confirmed, refused, rejected, archived, sha256.Sum256(snapshot), snapshot)
	return snapshot, archived
}

func nativeKindCanonicalJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || value == nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("complete original native JSON unavailable")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal("complete original native JSON cannot be encoded", err)
	}
	return canonical
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
