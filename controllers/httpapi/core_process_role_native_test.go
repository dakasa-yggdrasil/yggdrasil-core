package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Invoked by the existing strict KinD root. This is the committed production
// Dockerfile/main in a real Pod, not the schema-two SDK fixture main. The
// challenge is CI-declared scope over actual Pod/Deployment/process identities;
// it is no production grant, HPA envelope or useful-capacity assertion.
func qualifyCoreAPIWorkerNative(t *testing.T) {
	t.Helper()
	image, digest, gateway := os.Getenv("CORE_API_WORKER_IMAGE"), os.Getenv("CORE_API_WORKER_DIGEST"), os.Getenv("CORE_API_WORKER_HOST_GATEWAY")
	if image == "" || !strings.HasSuffix(image, "@"+digest) || net.ParseIP(gateway) == nil {
		t.Fatal("actual current Core image and KinD host route required")
	}
	f := dispatchHTTPPostgresFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if _, err := oidc.EnsureSigningKey(ctx, f.db); err != nil {
		t.Fatal("existing authority signing-key producer failed", err)
	}
	realm := f.workflow.Metadata.Namespace
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": realm}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"namespace": realm, "name": "yggdrasil-api"}, "automountServiceAccountToken": false})
	t.Cleanup(func() { _ = exec.Command("kubectl", "delete", "namespace", realm, "--wait=false").Run() })
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	var calls atomic.Int32
	var canceled atomic.Bool
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	typeSpec := model.IntegrationTypeManifestSpec{Provider: "core-api-native-ci", Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute", Health: "/health"}, TimeoutSeconds: 30}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}}, ResourceTypes: []model.IntegrationResourceType{{Name: "source", CanonicalPrefix: "thirdparty.core-api-native-ci.source", IdentityTemplate: "source.{id}", DefaultActions: []string{"observe_state"}}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.core-api-native-ci.source"}, ActionCatalog: []model.IntegrationActionDefinition{{Name: "observe_state", ResourceTypes: []string{"source"}, Idempotent: true}}}
	adapter := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/describe":
			_ = json.NewEncoder(w).Encode(typeSpec)
		case "/execute":
			var req model.AdapterExecuteIntegrationRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != "observe_state" {
				http.Error(w, "fixture refused", 400)
				return
			}
			calls.Add(1)
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-release:
				_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: "succeeded", Output: map[string]any{"actual_return": true}})
			case <-r.Context().Done():
				canceled.Store(true)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	adapter.Listener = listener
	adapter.Start()
	defer func() { releaseOnce.Do(func() { close(release) }); adapter.Close() }()
	typ := f.create("integration_type", "api-source", typeSpec)
	instance := f.create("integration_instance", "api-source", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: map[string]any{"base_url": "http://" + net.JoinHostPort(gateway, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))}})
	allow := f.allow
	allow.Roles[0].Rules = append(allow.Roles[0].Rules, model.RBACRule{Effect: "allow", Resources: []string{"workflow:" + realm + ":api-original"}, Actions: []string{"run"}})
	f.create("rbac", f.rbac.Metadata.Name, allow)
	wf := f.create("workflow", "api-original", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: f.rbac.Metadata.Name}}, Steps: []model.WorkflowStepSpec{{ID: "original", TimeoutSeconds: 30, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "integration", InstanceRef: &model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: "observe_state"}}}})
	const machine, admissionKey = "native-api-worker-ci-machine-only", "native-api-admission-ci-key-only-32bytes"
	// Match the actual production PostgreSQL loader, which consumes DB_* rather
	// than the test driver's DB_URL. Only the CI host route changes.
	shared := map[string]string{"DB_HOST": gateway, "BROKER_URL": coreWorkerHostURL(t, os.Getenv("BROKER_URL"), gateway), "YGGDRASIL_ENV": "development", "AUTH_THIRD_PARTY_STATE_SECRET": strings.Repeat("s", 32), "YGGDRASIL_CSRF_HMAC_SECRET": strings.Repeat("c", 32), "YGGDRASIL_AUTH_KEK_BASE64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "NATIVE_ADMISSION_KEY": admissionKey, workflowMachinePrincipalsEnv: testWorkflowMachinePrincipalsJSON(t, machine, "dispatch-ci", machineWorkflowRef{Namespace: realm, Name: wf.Metadata.Name})}
	for _, key := range []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "DB_PORT", "DB_SSLMODE"} {
		if value := os.Getenv(key); value != "" {
			shared[key] = value
		} else {
			t.Fatal("exact existing CI PostgreSQL startup configuration required", key)
		}
	}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"namespace": realm, "name": "core-api-ci-config"}, "stringData": shared})
	const label, foreign = "core-api-producer", "ci.yggdrasil.io/core-api-evidence"
	env := []map[string]any{{"name": coreprocess.RoleEnv, "value": string(coreprocess.APIWorker)}, {"name": "NATIVE_ADMISSION_ENABLED", "value": "true"}, {"name": "NATIVE_TERMINATION_PROJECTION_DIR", "value": "/native"}, {"name": "NATIVE_TERMINATION_IMAGE_DIGEST", "value": digest}, {"name": "HTTP_ADDR", "value": ":9080"}}
	projection := []map[string]any{{"path": "uid", "fieldRef": map[string]any{"fieldPath": "metadata.uid"}}, {"path": "name", "fieldRef": map[string]any{"fieldPath": "metadata.name"}}, {"path": "namespace", "fieldRef": map[string]any{"fieldPath": "metadata.namespace"}}, {"path": "challenge", "fieldRef": map[string]any{"fieldPath": "metadata.annotations['yggdrasil.io/capacity-drain-challenge']"}}}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"namespace": realm, "name": label}, "spec": map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": map[string]string{"app": label}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": label}, "finalizers": []string{foreign}}, "spec": map[string]any{"serviceAccountName": "yggdrasil-api", "automountServiceAccountToken": false, "terminationGracePeriodSeconds": int64(coreprocess.ShutdownBudget(coreprocess.APIWorker) / time.Second), "containers": []map[string]any{{"name": "core", "image": image, "command": []string{coreprocess.APIWorkerExecutable}, "imagePullPolicy": "Never", "resources": map[string]any{"requests": map[string]string{"cpu": "100m", "memory": "256Mi"}, "limits": map[string]string{"memory": "512Mi"}}, "env": env, "envFrom": []any{map[string]any{"secretRef": map[string]string{"name": "core-api-ci-config"}}}, "ports": []any{map[string]any{"containerPort": 9080}}, "readinessProbe": map[string]any{"httpGet": map[string]any{"path": "/readyz", "port": 9080}, "periodSeconds": 1}, "volumeMounts": []any{map[string]any{"name": "native", "mountPath": "/native", "readOnly": true}}}}, "volumes": []any{map[string]any{"name": "native", "downwardAPI": map[string]any{"items": projection}}}}}}})
	var pod map[string]any
	nativeKindAwait(t, ctx, func() bool {
		items := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "app="+label, "-o", "json")["items"].([]any)
		if len(items) != 1 {
			return false
		}
		pod = items[0].(map[string]any)
		return pod["status"].(map[string]any)["phase"] == "Running"
	})
	meta := pod["metadata"].(map[string]any)
	podName, podUID := meta["name"].(string), meta["uid"].(string)
	base, stopForward := coreWorkerPortForward(t, ctx, realm, podName)
	defer stopForward()
	client := &http.Client{Timeout: 5 * time.Second}
	call := func(method, path string, body []byte, token string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if path == "/internal-runtime/native-admission" {
			req.Header.Set("X-Native-Admission-Key", admissionKey)
		}
		response, err := client.Do(req)
		if err != nil {
			if method == http.MethodGet {
				return 0, nil
			}
			t.Fatal("actual Core worker HTTP unavailable", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("actual Core response did not return")
		}
		return response.StatusCode, raw
	}
	var observed model.NativeProcessAdmissionObservation
	var code int
	var raw []byte
	nativeKindAwait(t, ctx, func() bool {
		code, raw = call(http.MethodGet, "/internal-runtime/native-admission", nil, "")
		if code != http.StatusOK {
			return false
		}
		if json.Unmarshal(raw, &observed) != nil || observed.PodUID != podUID || observed.State != "waiting_projection" || !capacity.NativeProcessNonce(observed.ProcessNonce) {
			t.Fatal("actual process nonce unavailable", code)
		}
		return true
	})
	deployment := nativeKindGet(t, ctx, "-n", realm, "get", "deployment", label, "-o", "json")
	challenge := model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: realm, PodName: podName, PodUID: podUID, WorkloadUID: deployment["metadata"].(map[string]any)["uid"].(string), ContainerName: "core", ImageDigest: digest, IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: time.Now().UTC(), LaneRosterSHA256: capacity.NativeRosterDigest(coreprocess.WorkerLanes()), ProcessNonce: observed.ProcessNonce}
	challengeRaw, _ := json.Marshal(challenge)
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]string{"yggdrasil.io/capacity-drain-challenge": string(challengeRaw)}}})
	nativeKindCommand(t, ctx, "-n", realm, "patch", "pod", podName, "--type=merge", "-p", string(patch))
	nativeKindAwait(t, ctx, func() bool { code, _ := call(http.MethodGet, "/readyz", nil, ""); return code == 200 })
	for _, route := range []string{"/capacity/native/canary-authority", "/api/v1/capacity/mutations/native/redeem", "/api/v1/auth/login", "/api/v1/secrets", "/api/v1/github/webhook", "/api/v1/manifests?kind=control_plane"} {
		code, _ := call(http.MethodPost, route, []byte(`{}`), machine)
		if code != 503 {
			t.Fatal("worker accepted authority-only path", route, code)
		}
	}
	// The HTTP root itself is allowed, but the actually resolved workflow
	// execution must still refuse authority steps before their private guards.
	// Fake role metadata cannot alter the immutable process role.
	for _, use := range []model.WorkflowStepUseSpec{{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, {Kind: "yggdrasil", Operation: "apply_manifest"}, {Kind: "product", Operation: "installation.observe"}, {Kind: "integration", InstanceRef: &model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: model.WorkflowDispatchOperation}} {
		refusedSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: f.rbac.Metadata.Name}}, Steps: []model.WorkflowStepSpec{{ID: "authority", TimeoutSeconds: 30, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: use, With: map[string]any{"manifest": map[string]any{"kind": "control_plane"}, "product_ref": map[string]any{"namespace": realm, "name": "not-applied"}, "policy": map[string]any{"namespace": realm, "name": f.policy.Metadata.Name}}}}}
		if err := manifest.ValidateWorkflowSpec(refusedSpec); err != nil {
			t.Fatal("declared authority-refusal workflow invalid", err)
		}
		f.create("workflow", wf.Metadata.Name, refusedSpec)
		attempt, _ := json.Marshal(model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: realm, Name: wf.Metadata.Name}, Metadata: map[string]any{"idempotency_key": uuid.NewString(), coreprocess.RoleEnv: "authority", "claimed_native_success": true}})
		status, body := call(http.MethodPost, "/api/v1/workflow-runs", attempt, machine)
		var accepted struct {
			RunID string `json:"run_id"`
		}
		if status != 202 || json.Unmarshal(body, &accepted) != nil {
			t.Fatal("authority-step refusal did not exercise actual async worker", status)
		}
		id, err := uuid.Parse(accepted.RunID)
		if err != nil {
			t.Fatal(err)
		}
		nativeKindAwait(t, ctx, func() bool {
			run, err := repository.GetWorkflowRun(ctx, f.db, id)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status == "pending" || run.Status == "running" {
				return false
			}
			if run.Status != "failed" || !strings.Contains(run.Error, "workflow requires configured control authority origin") {
				t.Fatal("role refusal fell through to another authority/guard", run.Status, run.Error)
			}
			return true
		})
		if calls.Load() != 0 {
			t.Fatal("authority workflow reached adapter execution")
		}
	}
	f.create("workflow", wf.Metadata.Name, model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: f.rbac.Metadata.Name}}, Steps: []model.WorkflowStepSpec{{ID: "original", TimeoutSeconds: 30, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "integration", InstanceRef: &model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: "observe_state"}}}})
	request := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: realm, Name: wf.Metadata.Name}, Metadata: map[string]any{"idempotency_key": uuid.NewString()}}
	body, _ := json.Marshal(request)
	code, raw = call(http.MethodPost, "/api/v1/workflow-runs", body, machine)
	var accepted struct {
		RunID string `json:"run_id"`
	}
	if code != 202 || json.Unmarshal(raw, &accepted) != nil {
		t.Fatal("real worker did not accept ordinary workflow", code)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original callback did not start")
	}
	nativeKindCommand(t, ctx, "-n", realm, "delete", "pod", podName, "--wait=false")
	nativeKindAwait(t, ctx, func() bool {
		code, raw := call(http.MethodGet, "/internal-runtime/native-admission", nil, "")
		var current model.NativeProcessAdmissionObservation
		return code == 200 && json.Unmarshal(raw, &current) == nil && current.PodUID == podUID && current.State == "draining"
	})
	code, _ = call(http.MethodPost, "/api/v1/workflow-runs", body, machine)
	if code != 503 || canceled.Load() || calls.Load() != 1 {
		t.Fatal("drain admitted/replayed or canceled original callback", code, calls.Load())
	}
	releaseOnce.Do(func() { close(release) })
	var terminal map[string]any
	nativeKindAwait(t, ctx, func() bool {
		current := nativeKindGet(t, ctx, "-n", realm, "get", "pod", podName, "-o", "json")
		status := current["status"].(map[string]any)
		states, ok := status["containerStatuses"].([]any)
		if !ok || len(states) != 1 {
			return false
		}
		terminal, _ = states[0].(map[string]any)["state"].(map[string]any)["terminated"].(map[string]any)
		pod = current
		return terminal != nil
	})
	var receipt model.NativePodTerminationReceipt
	message, _ := terminal["message"].(string)
	if terminal["exitCode"] != float64(0) || json.Unmarshal([]byte(message), &receipt) != nil || receipt.PodUID != podUID || receipt.ProcessNonce != observed.ProcessNonce || receipt.RootAdmission != "previously_opened" || len(receipt.Lanes) != len(coreprocess.WorkerLanes()) {
		t.Fatal("actual current successful seven-lane receipt unavailable")
	}
	actualScope, _ := json.Marshal(receipt.NativePodTerminationChallenge)
	container := pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)
	if !bytes.Equal(actualScope, challengeRaw) || receipt.SchemaVersion != 2 || receipt.JoinedAt.Before(challenge.IssuedAt) || container["restartCount"] != float64(0) || !strings.HasSuffix(container["imageID"].(string), digest) {
		t.Fatal("current native receipt or actual container identity changed")
	}
	for _, lane := range coreprocess.WorkerLanes() {
		if receipt.Lanes[lane] != "done" {
			t.Fatal("enabled worker lane did not actually return", lane)
		}
	}
	id, err := uuid.Parse(accepted.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := repository.GetWorkflowRun(ctx, f.db, id)
	if err != nil || run.Status != "succeeded" || run.FinishedAt == nil || calls.Load() != 1 || canceled.Load() {
		t.Fatal("native exit preceded original durable completion", err)
	}
	root := os.Getenv("CORE_API_WORKER_NATIVE_LOG_DIR")
	if root == "" {
		t.Fatal("retained native producer evidence directory required")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	podRaw, _ := json.Marshal(pod)
	for name, data := range map[string][]byte{"CURRENT-CORE-API-POD-TERMINAL.PUBLIC.json": podRaw, "CURRENT-CORE-API-PROCESS-RECEIPT.original.json": []byte(message), "CURRENT-CORE-API-CHALLENGE.original.json": challengeRaw} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("actual Core api_worker producer uid=%s process=%s container_exit=0 lanes=7 original_calls=1 receipt_sha256=%x; no HPA/production/useful-capacity credit", podUID, observed.ProcessNonce, sha256.Sum256([]byte(message)))
	finalizers, ok := pod["metadata"].(map[string]any)["finalizers"].([]any)
	if !ok || len(finalizers) != 1 || finalizers[0] != foreign {
		t.Fatal("foreign CI evidence finalizer ownership changed")
	}
	// This is the CI-owned evidence finalizer, not the capacity finalizer API.
	nativeKindCommand(t, ctx, "-n", realm, "patch", "pod", podName, "--type=merge", "-p", `{"metadata":{"finalizers":[]}}`)
}

func coreWorkerHostURL(t *testing.T, raw, gateway string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() != "127.0.0.1" {
		t.Fatal("exact existing CI loopback dependency URL required")
	}
	u.Host = net.JoinHostPort(gateway, u.Port())
	return u.String()
}

func coreWorkerPortForward(t *testing.T, ctx context.Context, namespace, pod string) (string, func()) {
	t.Helper()
	owner, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(owner, "kubectl", "-n", namespace, "port-forward", "pod/"+pod, "0:9080")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	address := make(chan string, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stdout)
		pattern := regexp.MustCompile(`Forwarding from 127\.0\.0\.1:([0-9]+) ->`)
		for scanner.Scan() {
			if m := pattern.FindStringSubmatch(scanner.Text()); len(m) == 2 {
				select {
				case address <- "http://127.0.0.1:" + m[1]:
				default:
				}
			}
		}
	}()
	stop := func() { cancel(); _ = cmd.Wait(); <-scanDone }
	select {
	case base := <-address:
		return base, stop
	case <-ctx.Done():
		stop()
		t.Fatal("actual fixed-Pod port-forward did not start")
		return "", func() {}
	}
}
