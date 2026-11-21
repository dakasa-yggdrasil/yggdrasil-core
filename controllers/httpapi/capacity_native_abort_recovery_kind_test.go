package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const abortRecoveryKindFinalizer = "yggdrasil.io/capacity-native-termination"

// This root runs only in the existing remote PG/Rabbit/Kind job. It uses the
// real compiled adapter main, real authenticated Core callbacks, managed-secret
// resolution, and an original Kubernetes finalizer CAS. No return is fabricated.
func TestCapacityNativeAbortUnredeemedRecoveryKinDHTTP(t *testing.T) {
	runCapacityNativeAbortKindHTTP(t, false, false)
}
func TestCapacityNativeAbortReencryptedFrontendKinDHTTP(t *testing.T) {
	runCapacityNativeAbortKindHTTP(t, true, false)
}
func TestCapacityNativeAbortQuarantineKinDHTTP(t *testing.T) {
	runCapacityNativeAbortKindHTTP(t, true, true)
}
func runCapacityNativeAbortKindHTTP(t *testing.T, frontend, quarantine bool) {
	if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") != "true" {
		t.Skip("remote original abort recovery qualification")
	}
	source, binary := os.Getenv("CAPACITY_ABORT_RECOVERY_ADAPTER_SOURCE_COMMIT"), os.Getenv("CAPACITY_ABORT_RECOVERY_ADAPTER_BINARY")
	if len(source) != 40 || strings.Trim(source, "0123456789abcdef") != "" || binary == "" || os.Getenv("NATIVE_FIXTURE_IMAGE") == "" || os.Getenv("NATIVE_FIXTURE_DIGEST") == "" {
		t.Fatal("qualified paired adapter source, main and native image required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal("actual PostgreSQL unavailable")
	}
	defer db.Close()
	conn, err := amqp.Dial(os.Getenv("BROKER_URL"))
	if err != nil {
		t.Fatal("actual broker unavailable")
	}
	defer conn.Close()
	realm := "abort-core-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": realm}})
	defer func() { _ = exec.Command("kubectl", "delete", "namespace", realm, "--wait=false").Run() }()
	create := func(kind, name string, value any) model.Manifest {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal("fixed manifest unavailable")
		}
		m, e := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if e != nil {
			t.Fatal("actual manifest refused", e)
		}
		return m
	}
	// Immutable ledger rows remain retained until the remote job database ends.
	// Cleanup never deletes identities/archive/result rows or relabels outcomes.
	defer func() {
		for _, table := range []string{"capacity_native_commands", "capacity_native_scope_owners", "capacity_intent_events", "capacity_intents", "managed_secrets", "manifests"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM public."+table+" WHERE namespace=$1", realm)
		}
	}()
	pod, rs, dp := abortRecoveryKindBirthWithForeignFinalizer(t, ctx, realm, !quarantine)
	meta := pod["metadata"].(map[string]any)
	podName, podUID := meta["name"].(string), meta["uid"].(string)
	workloadUID := dp["metadata"].(map[string]any)["uid"].(string)
	actorConfig, puts, successfulPUTs := abortRecoveryKindActor(t, ctx, realm, podName, rs["metadata"].(map[string]any)["name"].(string))
	abortRecoveryKindFinalizerPolicy(t, ctx, realm, pod, actorConfig)
	var route atomic.Pointer[http.Handler]
	var successfulRedeems, successfulResults, successfulEvents atomic.Int32
	var plaintextResultRequests, plaintextResult400 atomic.Int32
	coreBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := route.Load()
		if handler == nil {
			http.Error(w, "initializing", http.StatusServiceUnavailable)
			return
		}
		out := httptest.NewRecorder()
		(*handler).ServeHTTP(out, r)
		if out.Code >= 200 && out.Code < 300 {
			switch r.URL.Path {
			case capacityMutationBasePath + "/native/redeem":
				successfulRedeems.Add(1)
			case capacityMutationBasePath + "/native/result":
				successfulResults.Add(1)
			case "/api/v1/events":
				successfulEvents.Add(1)
			}
		}
		for key, values := range out.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(out.Code)
		_, _ = w.Write(out.Body.Bytes())
	}))
	defer coreBackend.Close()
	core := coreBackend
	if frontend {
		target, _ := url.Parse(coreBackend.URL)
		verified := httputil.NewSingleHostReverseProxy(target)
		// This is a real terminating frontend followed by separately verified TLS
		// to Core. No forwarded header is treated as a TLS backend connection.
		backendTransport, ok := coreBackend.Client().Transport.(*http.Transport)
		if !ok || backendTransport.TLSClientConfig == nil || backendTransport.TLSClientConfig.InsecureSkipVerify || backendTransport.TLSClientConfig.RootCAs == nil {
			t.Fatal("frontend requires verified backend TLS")
		}
		verified.Transport = backendTransport.Clone()
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler := route.Load()
			if handler == nil {
				http.Error(w, "initializing", http.StatusServiceUnavailable)
				return
			}
			out := httptest.NewRecorder()
			(*handler).ServeHTTP(out, r)
			if r.URL.Path == capacityMutationBasePath+"/native/result" {
				plaintextResultRequests.Add(1)
				if out.Code == http.StatusBadRequest && strings.Contains(out.Body.String(), "capacity.mutation_invalid") && strings.Contains(out.Body.String(), "over TLS") {
					plaintextResult400.Add(1)
				}
			}
			for key, values := range out.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(out.Code)
			_, _ = w.Write(out.Body.Bytes())
		}))
		defer plain.Close()
		plainTarget, _ := url.Parse(plain.URL)
		misroutedResult := httputil.NewSingleHostReverseProxy(plainTarget)
		core = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if quarantine && r.URL.Path == capacityMutationBasePath+"/native/result" {
				// Fault injection is only backend transport: the real result handler
				// returns its actual plaintext 400. Redemption and native PUT stay real.
				misroutedResult.ServeHTTP(w, r)
				return
			}
			verified.ServeHTTP(w, r)
		}))
		defer core.Close()
	}
	machineToken, eventToken, foreignToken := uuid.NewString()+uuid.NewString(), uuid.NewString()+uuid.NewString(), uuid.NewString()+uuid.NewString()
	port, health := nativeKindFreePort(t), nativeKindFreePort(t)
	logFile, e := os.Create(filepath.Join(t.TempDir(), "paired-adapter-private.log"))
	if e != nil {
		t.Fatal("private main log unavailable")
	}
	defer logFile.Close()
	process := exec.CommandContext(ctx, binary)
	process.Env = append(os.Environ(), "YGGDRASIL_TRANSPORT=http", "ADAPTER_PORT="+strconv.Itoa(port), "HEALTHCHECK_PORT="+strconv.Itoa(health), "YGGDRASIL_CORE_URL="+core.URL, "YGGDRASIL_RUN_TOKEN="+eventToken, "SSL_CERT_FILE="+nativeCoreResultTrust(t, core))
	process.Stdout, process.Stderr = logFile, logFile
	if process.Start() != nil {
		t.Fatal("actual paired adapter main unavailable")
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	adapterURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	var describe model.AdapterDescribeResponse
	nativeKindAwait(t, ctx, func() bool {
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, adapterURL+"/rpc/describe", strings.NewReader("{}"))
		response, e := http.DefaultClient.Do(request)
		if e != nil {
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
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&envelope) != nil || json.Unmarshal(envelope.Body, &payload) != nil || !payload.OK {
			return false
		}
		describe = payload.Data
		return true
	})
	var typeSpec model.IntegrationTypeManifestSpec
	raw, _ := json.Marshal(describe)
	if json.Unmarshal(raw, &typeSpec) != nil {
		t.Fatal("actual paired Describe cannot become current type")
	}
	typeSpec.ResourceTypes = append([]model.IntegrationResourceType{}, describe.ResourceTypes...)
	if manifest.ValidateIntegrationTypeSpec(typeSpec) != nil {
		t.Fatal("actual paired Describe type invalid")
	}
	typ := create("integration_type", "paired-kubernetes", typeSpec)
	scope := model.CapacityPodTerminationTarget{BindingName: "abort-native", Namespace: realm, WorkloadName: "api", WorkloadUID: workloadUID, Owner: "abort-owner", ContainerName: "api", ImageDigest: os.Getenv("NATIVE_FIXTURE_DIGEST"), Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080}
	annotations := map[string]string{"yggdrasil.io/capacity-envelope-owner": scope.Owner, "yggdrasil.io/capacity-envelope-generation": "1", "yggdrasil.io/capacity-envelope-idempotency": "original-abort-fixture", "yggdrasil.io/capacity-envelope-protected-floor": "1", "yggdrasil.io/capacity-envelope-min": "1", "yggdrasil.io/capacity-envelope-max": "2"}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": map[string]any{"namespace": realm, "name": "api", "annotations": annotations}, "spec": map[string]any{"scaleTargetRef": map[string]string{"apiVersion": "apps/v1", "kind": "Deployment", "name": "api"}, "minReplicas": 1, "maxReplicas": 2, "metrics": []map[string]any{{"type": "Resource", "resource": map[string]any{"name": "cpu", "target": map[string]any{"type": "Utilization", "averageUtilization": 80}}}}}})
	hpaObject := nativeKindGet(t, ctx, "-n", realm, "get", "hpa", "api", "-o", "json")
	hpaUID := hpaObject["metadata"].(map[string]any)["uid"].(string)
	if _, e = repository.UpsertManagedSecret(ctx, db, model.UpsertManagedSecretRequest{Namespace: realm, Name: "native-auth", Status: "active", Data: map[string]string{"capacity_mutation_token": machineToken}}); e != nil {
		t.Fatal("private managed credential unavailable")
	}
	config := map[string]any{"base_url": adapterURL, "kubeconfig_path": actorConfig, "capacity_authority_url": core.URL, "native_pre_registration_abort_protocol": capacity.NativePreRegistrationAbortProtocol, "native_pre_registration_abort_source_commit": source, "capacity_pod_targets": []model.CapacityPodTerminationTarget{scope}, "capacity_envelope_targets": []map[string]any{{"namespace": realm, "hpa_name": "api", "hpa_uid": hpaUID, "workload_name": "api", "workload_uid": workloadUID, "owner": scope.Owner, "protected_floor": 1, "maximum_replicas": 2, "adoption_allowed": false, "surplus_max_age_seconds": 180}}}
	instance := create("integration_instance", "paired-kubernetes", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", CredentialsRef: "secret://" + realm + "/native-auth", Config: config})
	principalID := "abort-recovery-kind"
	principals, _ := json.Marshal([]capacityMutationPrincipalConfig{{PrincipalID: principalID, Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))), IntegrationInstanceID: instance.ID.String(), Capabilities: []string{capacity.DestroyNativeUnregisteredProtection}}, {PrincipalID: "foreign-instance", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(foreignToken))), IntegrationInstanceID: uuid.NewString(), Capabilities: []string{capacity.DestroyNativeUnregisteredProtection}}})
	events, _ := json.Marshal([]eventPublisherPrincipalConfig{{PrincipalID: "abort-recovery-events", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "ci-only", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(eventToken))), AllowedEvents: []eventPublisherEventRef{{Provider: "kubernetes", InstanceID: instance.ID.String(), EventType: "kubernetes.object.destroyed"}}}})
	t.Setenv(capacityMutationPrincipalsEnv, string(principals))
	t.Setenv(eventPublisherPrincipalsEnv, string(events))
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED", "true")
	t.Setenv("YGGDRASIL_ENV", "development")
	handler, e := New("abort-recovery-native-ci", db, conn, zap.NewNop())
	if e != nil {
		t.Fatal("actual authenticated Core unavailable")
	}
	route.Store(&handler)
	call := func(operation string, input map[string]any) (model.ExecuteIntegrationResponse, error) {
		return message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{Integration: model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: operation, Capability: operation, Input: input})
	}
	var observed model.AdapterCapacityPodUnregisteredTerminalResponse
	read := func() model.AdapterCapacityPodUnregisteredTerminalResponse {
		returned, e := call(capacity.ObserveNativeUnregisteredTerminal, map[string]any{"binding_name": scope.BindingName, "pod_name": podName, "expected_pod_uid": podUID})
		var out model.AdapterCapacityPodUnregisteredTerminalResponse
		if e != nil || capacity.DecodeNativeCapacity(returned.Output, &out) != nil || out.Status != "observed" || out.Observation.Receipt != nil {
			t.Fatal("actual original unregistered native witness unavailable")
		}
		return out
	}
	observed = read()
	binding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), InstanceChecksum: instance.Checksum, TypeChecksum: typ.Checksum}
	basicWF := create("workflow", "admit", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": realm, "name": "human-only"}}})
	create("workflow", "scale", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": realm, "name": "human-only"}}})
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "abort-recovery", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/original-abort", Owner: scope.Owner, Workflow: model.ManifestSelector{Namespace: realm, Name: "scale"}, Currency: "USD", Floor: 1, Ceiling: 2, Step: 1, MaxEvidenceAgeSeconds: 180, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 1, LeaseSeconds: 15, ExecutionEnabled: true, Profiles: []model.CapacityProfile{{Name: "reserved", Provider: "kubernetes", Region: "fixture-only", MinUnits: 1, MaxUnits: 2, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:original-native-only"}}, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixture/native", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: binding, Namespace: realm, HPAName: "api", HPAUID: hpaUID, WorkloadName: "api", WorkloadUID: workloadUID, Owner: scope.Owner, Profile: "reserved", ProtectedFloor: 1, MaximumReplicas: 2}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: binding, BindingName: "unused-pressure", BindingSHA256: strings.Repeat("a", 64)}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: principalID, Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: scope.BindingName, BirthGuardBinding: "source-only-unused", BirthGuardSHA256: strings.Repeat("d", 64), ContainerName: "api", ImageDigest: scope.ImageDigest, Lanes: scope.Lanes, ProjectionDirectory: scope.ProjectionDirectory, AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: realm, Name: "admit"}}}
	if manifest.ValidateCapacityPolicySpec(p) != nil {
		t.Fatal("fixed original recovery policy invalid")
	}
	policy := create("capacity_policy", "original-abort", p)
	hpaReturned, e := call(capacity.ObserveHPAEnvelope, map[string]any{"namespace": realm, "hpa_name": "api"})
	var hpa model.CapacityHPAEnvelopeResponse
	if e != nil || capacity.DecodeNativeCapacity(hpaReturned.Output, &hpa) != nil {
		t.Fatal("actual native HPA read unavailable")
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: basicWF.ID, ExecutorID: uuid.NewString()}
	intent, e := store.AcquireNativeAdmissionExecution(ctx, policy, hpa)
	if e != nil {
		t.Fatal("actual initial intent unavailable", e)
	}
	// Both leases really expire in GHA. No command, proof, policy checksum or SQL
	// timestamp is rewritten to manufacture an expired predecessor.
	abortRecoveryKindExpire(t, ctx, db, realm)
	observed = read()
	human := uuid.NewString()
	create("rbac", "named-human", map[string]any{"roles": []any{map[string]any{"name": "operator", "rules": []any{map[string]any{"effect": "allow", "resources": []string{"workflow:" + realm + ":original-human", "workflow:" + realm + ":recovery-human", "workflow:" + realm + ":quarantine-human"}, "actions": []string{"run"}}}}}, "bindings": []any{map[string]any{"name": "ci-named-human", "subjects": []any{map[string]string{"type": "collaborator", "id": human}}, "roles": []string{"operator"}}}})
	b := model.CapacityNativeAbortBinding{Schema: capacity.NativePreRegistrationAbortSchema, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, Generation: intent.Generation, Adapter: binding, AdapterPrincipalID: principalID, AdapterSourceCommit: source, OperatorID: human, BindingName: scope.BindingName, Namespace: realm, PodName: podName, PodUID: podUID, WorkloadUID: workloadUID, ReplicaSetUID: observed.Observation.ReplicaSetUID, ContainerName: scope.ContainerName, ImageDigest: scope.ImageDigest, PodSpecSHA256: observed.Observation.PodSpecSHA256, Confirmation: "ABORT ONLY EXACT CI ORIGINAL"}
	oldWF := create("workflow", "original-human", abortRecoveryKindWorkflow(realm, "capacity.abort_native_birth", b, b.Confirmation))
	store.AdmissionOnly, store.WorkflowID, store.ExecutorID, store.ExecutorPowerOperator = false, oldWF.ID, uuid.NewString(), human
	intent, e = store.ResumeNativePreRegistrationAbort(ctx, policy, b)
	if e != nil {
		t.Fatal("actual original abort lease unavailable", e)
	}
	observed = read()
	parent, parentToken, e := store.IssueNativePreRegistrationAbort(ctx, policy, intent, b, observed.Observation)
	if e != nil {
		t.Fatal("actual original command unavailable", e)
	}
	t.Run("authenticated_http_refusals", func(t *testing.T) {
		payload := model.CapacityNativeAuthorityRedeemRequest{AuthorityToken: parentToken, IntegrationInstanceID: instance.ID.String(), IntegrationTypeID: typ.ID.String(), Capability: parent.Operation, RequestSHA256: parent.RequestSHA256, ReleaseProtocol: parent.ReleaseProtocol, AdapterSourceCommit: source}
		for _, test := range []struct {
			name, token string
			status      int
			change      func(map[string]any)
		}{
			{"anonymous", "", 401, nil}, {"foreign_grant", foreignToken, 403, nil}, {"wrong_digest", machineToken, 403, func(v map[string]any) { v["request_sha256"] = strings.Repeat("0", 64) }}, {"closed_callback_schema", machineToken, 400, func(v map[string]any) { v["caller_ready"] = true }},
		} {
			t.Run(test.name, func(t *testing.T) {
				body, _ := json.Marshal(payload)
				var value map[string]any
				_ = json.Unmarshal(body, &value)
				if test.change != nil {
					test.change(value)
				}
				body, _ = json.Marshal(value)
				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, core.URL+capacityMutationBasePath+"/native/redeem", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				if test.token != "" {
					request.Header.Set("Authorization", "Bearer "+test.token)
				}
				response, e := core.Client().Do(request)
				if e != nil {
					t.Fatal("actual negative HTTP return unavailable")
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != test.status {
					t.Fatal("actual callback default-deny boundary changed")
				}
				abortRecoveryKindUnredeemed(t, ctx, db, parent.CommandID)
			})
		}
	})
	parentRequest := abortRecoveryKindInput(t, parent.Request, parentToken)
	parentRequest["proof"].(map[string]any)["observation"].(map[string]any)["receipt"] = map[string]any{"caller_ready": true}
	t.Run("original_closed_refusal_before_redemption", func(t *testing.T) {
		if _, e := call(capacity.DestroyNativeUnregisteredProtection, parentRequest); e == nil || !strings.Contains(e.Error(), "noncanonical or duplicate native field") {
			t.Fatal("actual closed receiver refusal missing")
		}
		abortRecoveryKindUnredeemed(t, ctx, db, parent.CommandID)
		if puts.Load() != 0 || successfulRedeems.Load() != 0 || successfulResults.Load() != 0 {
			t.Fatal("closed original request reached native or redemption")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	if e = store.MarkNativeCommandUncertain(ctx, parent.CommandID); e != nil {
		t.Fatal("original uncertainty not retained")
	}
	var originalIdentity []byte
	if db.QueryRowContext(ctx, `SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, parent.CommandID).Scan(&originalIdentity) != nil {
		t.Fatal("original immutable identity unavailable")
	}
	abortRecoveryKindExpire(t, ctx, db, realm)
	recovery := model.CapacityNativeAbortRecoveryBinding{Schema: capacity.NativePreRegistrationAbortRecoverySchema, Native: b, ParentCommandID: parent.CommandID.String(), ParentFencingToken: parent.FencingToken, ParentExpiresAt: parent.ExpiresAt, ExpectedIntentFencingToken: intent.FencingToken}
	recovery.Native.Confirmation = "RECOVER ONLY EXACT CI ORIGINAL"
	wf := create("workflow", "recovery-human", abortRecoveryKindWorkflow(realm, "capacity.recover_unredeemed_native_birth", recovery, recovery.Native.Confirmation))
	store.WorkflowID, store.ExecutorID = wf.ID, uuid.NewString()
	// The unissued candidate below is used only to prove closed decoding.
	// No child command or permission is minted by the fixture: the actual
	// HTTP workflow controller alone resumes, issues, joins, confirms and archives.
	no := false
	unissued, e := json.Marshal(model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest{ExpectedPodUID: podUID, ExpectedPodResourceVersion: observed.Observation.PodResourceVersion, DryRun: &no, Proof: model.CapacityNativeAbortRecoveryProof{Schema: capacity.NativePreRegistrationAbortRecoverySchema, Binding: recovery, Observation: observed.Observation}})
	if e != nil {
		t.Fatal("closed negative candidate unavailable")
	}
	t.Run("new_proof_closed_receiver_refusals", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			change func(map[string]any)
		}{{"unknown_field", func(v map[string]any) { v["proof"].(map[string]any)["caller_ready"] = true }}, {"wrong_schema", func(v map[string]any) { v["proof"].(map[string]any)["schema"] = "unknown_native_recovery" }}} {
			t.Run(test.name, func(t *testing.T) {
				bad := abortRecoveryKindInput(t, unissued, parentToken)
				test.change(bad)
				if _, e := call(capacity.DestroyNativeUnregisteredProtection, bad); e == nil {
					t.Fatal("unqualified new proof reached handler")
				} else if test.name == "unknown_field" && !strings.Contains(e.Error(), "noncanonical or duplicate native field") {
					t.Fatal("new proof did not fail at the actual closed receiver")
				}
				abortRecoveryKindUnredeemed(t, ctx, db, parent.CommandID)
			})
		}
		if puts.Load() != 0 || successfulRedeems.Load() != 0 {
			t.Fatal("negative proof reached native permission")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	// A current named collaborator and the actual synchronous HTTP handler
	// install/recheck the production authorization fence. Only authentication
	// middleware's trusted claims bridge is supplied by this CI fixture.
	if _, e = db.ExecContext(ctx, `INSERT INTO public.collaborators(id,slug,status,display_name,traits) VALUES($1,$2,'active','Native recovery CI human','{}'::jsonb)`, human, human); e != nil {
		t.Fatal("current named human unavailable")
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM public.collaborators WHERE id=$1`, human)
	}()
	humanServer := &Server{db: db, rabbitmq: conn, logger: zap.NewNop()}
	dispatchWorkflow := func(selected model.Manifest, confirmation string) (int, model.RunWorkflowResponse) {
		body, err := json.Marshal(model.RunWorkflowRequest{Workflow: model.ManifestSelector{ManifestID: selected.ID.String()}, Inputs: map[string]any{"confirmation": confirmation}})
		if err != nil {
			t.Fatal("fixed synchronous request unavailable")
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", bytes.NewReader(body)).WithContext(contextWithClaims(ctx, map[string]any{"collaborator_id": human}))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		humanServer.handleWorkflowRun(recorder, request)
		var response model.RunWorkflowResponse
		if json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
			t.Fatal("actual synchronous workflow response unavailable")
		}
		return recorder.Code, response
	}
	dispatch := func() (int, model.RunWorkflowResponse) { return dispatchWorkflow(wf, recovery.Native.Confirmation) }
	if quarantine {
		t.Run("real_original_result_unknown_then_human_quarantine", func(t *testing.T) {
			status, response := dispatch()
			if status != http.StatusCreated || response.Status != "failed" || puts.Load() != 1 || successfulPUTs.Load() != 1 || successfulRedeems.Load() != 1 || successfulResults.Load() != 0 || successfulEvents.Load() != 0 || plaintextResultRequests.Load() != 1 || plaintextResult400.Load() != 1 {
				t.Fatal("real misrouted result did not retain original uncertainty and exact plaintext-handler400")
			}
			var childRaw, seedBefore, identityBefore []byte
			if db.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE namespace=$1 AND sequence=2`, realm).Scan(&childRaw) != nil {
				t.Fatal("original uncertain child unavailable")
			}
			var child model.CapacityNativeCommand
			if capacity.DecodeNativeCapacity(json.RawMessage(childRaw), &child) != nil || child.State != "uncertain" || child.AttemptID == uuid.Nil || child.RedeemedBy != principalID || len(child.OriginalResult) != 0 || child.CallerReturnObservedAt != nil {
				t.Fatal("original child outcome was invented")
			}
			if db.QueryRowContext(ctx, `SELECT row_to_json(r) FROM public.capacity_native_release_results r WHERE command_id=$1`, child.CommandID).Scan(&seedBefore) != nil || db.QueryRowContext(ctx, `SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, child.CommandID).Scan(&identityBefore) != nil {
				t.Fatal("original result seed or identity missing")
			}
			nativeKindAwait(t, ctx, func() bool { return read().Observation.State == "absent" })
			abortRecoveryKindExpire(t, ctx, db, realm)
			q := model.CapacityNativeAbortQuarantineBinding{Schema: capacity.NativeAbortQuarantineSchema, Confirmation: "QUARANTINE ORIGINAL UNCERTAIN ONLY", Native: recovery.Native, ParentCommandID: parent.CommandID.String(), CommandID: child.CommandID.String(), ExpectedIntentFencingToken: child.FencingToken}
			quarantineWF := create("workflow", "quarantine-human", abortRecoveryKindWorkflow(realm, capacity.QuarantineUncertainNativeBirth, q, q.Confirmation))
			status, response = dispatchWorkflow(quarantineWF, q.Confirmation)
			if status != http.StatusCreated || response.Status != "succeeded" || len(response.Steps) != 1 || response.Steps[0].Attempts != 1 || response.Steps[0].Metadata["raw_uncertain_preserved"] != true || response.Steps[0].Metadata["physical_capacity_released"] != false || response.Steps[0].Metadata["sdk_lane_witness"] != false {
				t.Fatal("actual human controller quarantine did not preserve uncertainty")
			}
			counts, e := store.NativeUnsettledCounts(ctx, policy)
			if e != nil || counts.RawUnsettled != 1 || counts.ActiveUnsettled != 0 || counts.Quarantined != 1 {
				t.Fatal("public raw/active/quarantine counts conceal original outcome")
			}
			var after, seedAfter, identityAfter []byte
			if db.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, child.CommandID).Scan(&after) != nil || db.QueryRowContext(ctx, `SELECT row_to_json(r) FROM public.capacity_native_release_results r WHERE command_id=$1`, child.CommandID).Scan(&seedAfter) != nil || db.QueryRowContext(ctx, `SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, child.CommandID).Scan(&identityAfter) != nil || !bytes.Equal(nativeKindCanonicalJSON(t, childRaw), nativeKindCanonicalJSON(t, after)) || !bytes.Equal(nativeKindCanonicalJSON(t, seedBefore), nativeKindCanonicalJSON(t, seedAfter)) || !bytes.Equal(nativeKindCanonicalJSON(t, identityBefore), nativeKindCanonicalJSON(t, identityAfter)) {
				t.Fatal("quarantine rewrote original command/result/identity custody")
			}
			_, repeat := dispatchWorkflow(quarantineWF, q.Confirmation)
			if repeat.Status != "failed" || puts.Load() != 1 || successfulRedeems.Load() != 1 || successfulResults.Load() != 0 || successfulEvents.Load() != 0 || plaintextResultRequests.Load() != 1 || plaintextResult400.Load() != 1 {
				t.Fatal("administrative replay acquired native authority or another receipt")
			}
		})
		return
	}
	t.Run("original_main_http_finalizer_cas_and_retained_pair", func(t *testing.T) {
		status, response := dispatch()
		if status != http.StatusCreated || response.Status != "succeeded" || response.Workflow.ID != wf.ID || len(response.Steps) != 1 || response.Steps[0].Status != "succeeded" || response.Steps[0].Attempts != 1 || response.Steps[0].Metadata["parent_command_id"] != parent.CommandID.String() || response.Steps[0].Metadata["disposition"] != "abort_before_admission_unredeemed_recovery" {
			t.Fatal("actual original HTTP workflow controller did not complete")
		}
		if puts.Load() != 1 || successfulPUTs.Load() != 1 || successfulRedeems.Load() != 1 || successfulResults.Load() != 1 || successfulEvents.Load() != 1 || plaintextResultRequests.Load() != 0 {
			t.Fatal("actual original native one-send/HTTP custody count differs")
		}
		actual := nativeKindGet(t, ctx, "-n", realm, "get", "pod", podName, "-o", "json")
		actualMeta := actual["metadata"].(map[string]any)
		if actualMeta["uid"] != podUID || !reflect.DeepEqual(actual["spec"], pod["spec"]) || !reflect.DeepEqual(actualMeta["finalizers"], []any{"other.example/keep"}) {
			t.Fatal("original native CAS changed UID/spec/foreign finalizer")
		}
		fresh := read()
		if fresh.Observation.Protected {
			t.Fatal("original finalizer still protected")
		}
		child, present, err := store.LoadNativePreRegistrationAbort(ctx, policy, podUID)
		if err != nil || !present || child.CommandID.String() != response.Steps[0].Metadata["command_id"] || child.State != "confirmed" || child.AttemptID == uuid.Nil || child.RedeemedBy != principalID || child.CallerReturnObservedAt == nil || child.OriginalResultSHA256 == "" {
			t.Fatal("actual controller did not retain the confirmed immutable pair")
		}
		var request model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
		if capacity.DecodeNativeCapacity(child.Request, &request) != nil || request.Proof.Observation.Receipt != nil || request.AuthorityToken != "" || request.Proof.History.CommandIdentities != 1 || request.Proof.History.HotCommands != 0 || request.Proof.History.ArchivedCommands != 1 {
			t.Fatal("issued canonical proof lost null receipt or truthful history")
		}
		var canonical map[string]any
		if json.Unmarshal(child.Request, &canonical) != nil {
			t.Fatal("issued canonical proof unavailable")
		}
		if receipt, exists := canonical["proof"].(map[string]any)["observation"].(map[string]any)["receipt"]; !exists || receipt != nil {
			t.Fatal("issued original proof lost explicit null receipt")
		}
		var identity, archivedParent []byte
		if db.QueryRowContext(ctx, `SELECT row_to_json(i) FROM public.capacity_native_command_identities i WHERE id=$1`, parent.CommandID).Scan(&identity) != nil || !bytes.Equal(nativeKindCanonicalJSON(t, identity), nativeKindCanonicalJSON(t, originalIdentity)) || db.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_command_archive WHERE id=$1`, parent.CommandID).Scan(&archivedParent) != nil {
			t.Fatal("original parent custody changed")
		}
		var retained model.CapacityNativeCommand
		if json.Unmarshal(archivedParent, &retained) != nil || retained.State != "refused_no_redemption" || retained.AttemptID != uuid.Nil || retained.RedeemedBy != "" || retained.CallerReturnObservedAt != nil || len(retained.OriginalResult) != 0 {
			t.Fatal("parent discharge invented a native result")
		}
		retained.State, retained.UpdatedAt = parent.State, parent.UpdatedAt
		left, _ := json.Marshal(retained)
		right, _ := json.Marshal(parent)
		if !bytes.Equal(nativeKindCanonicalJSON(t, left), nativeKindCanonicalJSON(t, right)) {
			t.Fatal("parent immutable facts changed")
		}
		var ids, hot, archives, pending, lifetimes, results, acks, eventsCount int
		if db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),(SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1),(SELECT count(*) FROM public.capacity_native_command_archive a JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1),(SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$2 AND state IN('issued','redeemed','uncertain')),(SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1),(SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$3),(SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$3 AND adapter_ack_at IS NOT NULL AND caller_ack_at IS NOT NULL),(SELECT count(*) FROM public.event_log WHERE type='kubernetes.object.destroyed' AND idempotency_key=$4)`, podUID, realm, child.CommandID, "native-abort:"+child.CommandID.String()).Scan(&ids, &hot, &archives, &pending, &lifetimes, &results, &acks, &eventsCount) != nil || ids != 2 || hot != 0 || archives != 2 || pending != 0 || lifetimes != 0 || results != 1 || acks != 1 || eventsCount != 1 {
			t.Fatal("actual complete native/SQL/event census differs")
		}
		var storedResult model.CapacityNativeReleaseResult
		if capacity.DecodeNativeCapacity(child.OriginalResult, &storedResult) != nil || storedResult.CommandID != child.CommandID || storedResult.AttemptID != child.AttemptID || storedResult.RequestSHA256 != child.RequestSHA256 || storedResult.AdapterSourceCommit != source || storedResult.ReturnNonce != "" || !storedResult.OneSend || !storedResult.DoReturned || !storedResult.ReadReturned || !storedResult.CloseReturned {
			t.Fatal("original callback digest/source/return custody differs")
		}
		// A second actual controller invocation cannot mint sequence three or
		// replay the completed child. Its ephemeral credential is never exposed.
		_, replay := dispatch()
		if replay.Status != "failed" || puts.Load() != 1 || successfulRedeems.Load() != 1 || successfulResults.Load() != 1 || successfulEvents.Load() != 1 {
			t.Fatal("replayed workflow acquired another native mutation")
		}
	})
}

func abortRecoveryKindWorkflow(realm, operation string, binding any, confirmation string) map[string]any {
	return map[string]any{"trigger": map[string]any{"mode": "manual"}, "dispatch_mode": "sync", "authorization": map[string]any{"rbac": map[string]string{"namespace": realm, "name": "named-human"}}, "steps": []any{map[string]any{"id": "original-once", "timeout_seconds": 90, "retry": map[string]any{"max_attempts": 1}, "use": map[string]any{"kind": "yggdrasil", "operation": operation}, "with": map[string]any{"binding": binding, "confirmation": confirmation}}}}
}
func abortRecoveryKindInput(t *testing.T, raw json.RawMessage, token string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out map[string]any
	if decoder.Decode(&out) != nil || out == nil {
		t.Fatal("complete original command input unavailable")
	}
	out["authority_token"] = token
	return out
}
func abortRecoveryKindUnredeemed(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) {
	t.Helper()
	var attempt, principal string
	var n int
	if db.QueryRowContext(ctx, `SELECT command_record->>'attempt_id',command_record->>'redeemed_by',(SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1) FROM public.capacity_native_commands WHERE id=$1`, id).Scan(&attempt, &principal, &n) != nil || attempt != uuid.Nil.String() || principal != "" || n != 0 {
		t.Fatal("refusal acquired original permission")
	}
}
func abortRecoveryKindExpire(t *testing.T, ctx context.Context, db *sql.DB, realm string) {
	t.Helper()
	nativeKindAwait(t, ctx, func() bool {
		var expired bool
		return db.QueryRowContext(ctx, `SELECT (intent->>'lease_expires_at')::timestamptz < clock_timestamp() FROM public.capacity_intents WHERE namespace=$1`, realm).Scan(&expired) == nil && expired
	})
}

func abortRecoveryKindBirthWithForeignFinalizer(t *testing.T, ctx context.Context, realm string, foreign bool) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	image, digest := os.Getenv("NATIVE_FIXTURE_IMAGE"), os.Getenv("NATIVE_FIXTURE_DIGEST")
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"namespace": realm, "name": "admission-fixture"}, "stringData": map[string]string{"key": uuid.NewString() + uuid.NewString()}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"namespace": realm, "name": "api"}, "spec": map[string]any{"replicas": 0, "selector": map[string]any{"matchLabels": map[string]string{"app": "abort-original"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "abort-original"}}, "spec": map[string]any{"containers": []map[string]any{{"name": "api", "image": image, "imagePullPolicy": "Never"}}}}}})
	nativeKindAwait(t, ctx, func() bool {
		items := nativeKindGet(t, ctx, "-n", realm, "get", "replicasets", "-l", "app=abort-original", "-o", "json")["items"].([]any)
		return len(items) == 1
	})
	dp := nativeKindGet(t, ctx, "-n", realm, "get", "deployment", "api", "-o", "json")
	uid := dp["metadata"].(map[string]any)["uid"].(string)
	projection := []map[string]any{{"path": "uid", "fieldRef": map[string]string{"fieldPath": "metadata.uid"}}, {"path": "namespace", "fieldRef": map[string]string{"fieldPath": "metadata.namespace"}}, {"path": "name", "fieldRef": map[string]string{"fieldPath": "metadata.name"}}, {"path": "challenge", "fieldRef": map[string]string{"fieldPath": "metadata.annotations['yggdrasil.io/capacity-drain-challenge']"}}}
	finalizers := []string{abortRecoveryKindFinalizer}
	if foreign {
		finalizers = append(finalizers, "other.example/keep")
	}
	template := map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "abort-original"}, "annotations": map[string]string{"yggdrasil.io/capacity-native-deployment-uid": uid}, "finalizers": finalizers}, "spec": map[string]any{"restartPolicy": "Always", "terminationGracePeriodSeconds": 1, "securityContext": map[string]int{"fsGroup": 65532}, "readinessGates": []map[string]string{{"conditionType": "yggdrasil.io/capacity-native-admitted"}}, "containers": []map[string]any{{"name": "api", "image": image, "imagePullPolicy": "Never", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "env": []map[string]any{{"name": "NATIVE_ADMISSION_ENABLED", "value": "true"}, {"name": "NATIVE_ADMISSION_KEY", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "admission-fixture", "key": "key"}}}, {"name": "NATIVE_TERMINATION_PROJECTION_DIR", "value": "/native"}, {"name": "NATIVE_TERMINATION_IMAGE_DIGEST", "value": digest}, {"name": "NATIVE_FIXTURE_MODE", "value": "normal"}}, "volumeMounts": []map[string]any{{"name": "native", "mountPath": "/native", "readOnly": true}, {"name": "state", "mountPath": "/state"}}}}, "volumes": []map[string]any{{"name": "state", "emptyDir": map[string]any{}}, {"name": "native", "downwardAPI": map[string]any{"items": projection}}}}}
	patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": uid}, {"op": "test", "path": "/spec", "value": dp["spec"]}, {"op": "replace", "path": "/spec/template", "value": template}, {"op": "replace", "path": "/spec/replicas", "value": 1}})
	nativeKindCommand(t, ctx, "-n", realm, "patch", "deployment", "api", "--type=json", "-p", string(patch))
	var pod map[string]any
	nativeKindAwait(t, ctx, func() bool {
		items := nativeKindGet(t, ctx, "-n", realm, "get", "pods", "-l", "app=abort-original", "-o", "json")["items"].([]any)
		if len(items) != 1 {
			return false
		}
		current := items[0].(map[string]any)
		status, _ := current["status"].(map[string]any)
		containers, _ := status["containerStatuses"].([]any)
		if len(containers) != 1 {
			return false
		}
		container := containers[0].(map[string]any)
		state, _ := container["state"].(map[string]any)
		if state["running"] == nil || container["containerID"] == "" {
			return false
		}
		pod = current
		return true
	})
	metadata := pod["metadata"].(map[string]any)
	refs := metadata["ownerReferences"].([]any)
	if len(refs) != 1 {
		t.Fatal("actual original ReplicaSet owner missing")
	}
	reference := refs[0].(map[string]any)
	rs := nativeKindGet(t, ctx, "-n", realm, "get", "replicaset", reference["name"].(string), "-o", "json")
	if rs["metadata"].(map[string]any)["uid"] != reference["uid"] {
		t.Fatal("original native owner changed")
	}
	// The DELETE is the genuine original UID-precondition request. The kubelet,
	// not this test, supplies Failed/current terminated native status.
	options, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]any{"uid": metadata["uid"]}})
	command := exec.CommandContext(ctx, "kubectl", "delete", "--raw", "/api/v1/namespaces/"+realm+"/pods/"+metadata["name"].(string), "-f", "-")
	command.Stdin = bytes.NewReader(options)
	if command.Run() != nil {
		t.Fatal("original UID deletion request unavailable")
	}
	name := metadata["name"].(string)
	nativeKindAwait(t, ctx, func() bool {
		current := nativeKindGet(t, ctx, "-n", realm, "get", "pod", name, "-o", "json")
		status, _ := current["status"].(map[string]any)
		containers, _ := status["containerStatuses"].([]any)
		if status["phase"] != "Failed" || len(containers) != 1 {
			return false
		}
		state, _ := containers[0].(map[string]any)["state"].(map[string]any)
		terminated, _ := state["terminated"].(map[string]any)
		if terminated == nil || terminated["exitCode"] == float64(0) {
			return false
		}
		pod = current
		return true
	})
	return pod, rs, nativeKindGet(t, ctx, "-n", realm, "get", "deployment", "api", "-o", "json")
}

// This proxy forwards unchanged actor-authenticated requests/responses to the
// actual Kind API. It cannot invent a PUT outcome; it counts actual sends and
// successful real returns. Neither proxy nor adapter receives admin auth.
func abortRecoveryKindActor(t *testing.T, ctx context.Context, realm, podName, rsName string) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"namespace": realm, "name": "native-abort"}})
	rules := []map[string]any{{"apiGroups": []string{""}, "resources": []string{"pods"}, "resourceNames": []string{podName}, "verbs": []string{"get", "update"}}, {"apiGroups": []string{"apps"}, "resources": []string{"replicasets"}, "resourceNames": []string{rsName}, "verbs": []string{"get"}}, {"apiGroups": []string{"apps"}, "resources": []string{"deployments"}, "resourceNames": []string{"api"}, "verbs": []string{"get"}}, {"apiGroups": []string{"autoscaling"}, "resources": []string{"horizontalpodautoscalers"}, "resourceNames": []string{"api"}, "verbs": []string{"get"}}}
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"namespace": realm, "name": "native-abort"}, "rules": rules})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": map[string]any{"namespace": realm, "name": "native-abort"}, "roleRef": map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "native-abort"}, "subjects": []map[string]string{{"kind": "ServiceAccount", "namespace": realm, "name": "native-abort"}}})
	token := strings.TrimSpace(string(nativeKindCommand(t, ctx, "-n", realm, "create", "token", "native-abort", "--duration=10m")))
	var config map[string]any
	if json.Unmarshal(nativeKindCommand(t, ctx, "config", "view", "--raw", "--minify", "-o", "json"), &config) != nil {
		t.Fatal("native cluster connection unavailable")
	}
	clusters := config["clusters"].([]any)
	cluster := clusters[0].(map[string]any)["cluster"].(map[string]any)
	server, _ := cluster["server"].(string)
	ca, err := base64.StdEncoding.DecodeString(fmt.Sprint(cluster["certificate-authority-data"]))
	if err != nil || len(ca) == 0 {
		t.Fatal("actual native cluster CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("actual native cluster CA invalid")
	}
	origin, err := url.Parse(server)
	if err != nil || origin.Scheme != "https" {
		t.Fatal("actual native TLS origin unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	deferClose := transport.CloseIdleConnections
	t.Cleanup(deferClose)
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.Transport = transport
	director := proxy.Director
	proxy.Director = func(r *http.Request) { director(r); r.Host = origin.Host }
	sends, successes := new(atomic.Int32), new(atomic.Int32)
	path := "/api/v1/namespaces/" + realm + "/pods/" + podName
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.Method == http.MethodPut && response.Request.URL.Path == path && response.StatusCode == 200 {
			successes.Add(1)
		}
		return nil
	}
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == path {
			sends.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(proxyServer.Close)
	actor := map[string]any{"apiVersion": "v1", "kind": "Config", "clusters": []map[string]any{{"name": "native", "cluster": map[string]string{"server": proxyServer.URL, "certificate-authority-data": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyServer.Certificate().Raw}))}}}, "users": []map[string]any{{"name": "actor", "user": map[string]string{"token": token}}}, "contexts": []map[string]any{{"name": "native", "context": map[string]string{"cluster": "native", "user": "actor", "namespace": realm}}}, "current-context": "native"}
	raw, err := json.Marshal(actor)
	if err != nil {
		t.Fatal("scoped native actor unavailable")
	}
	actorPath := filepath.Join(t.TempDir(), "native-abort-private.kubeconfig")
	if os.WriteFile(actorPath, raw, 0600) != nil {
		t.Fatal("private scoped actor write failed")
	}
	nativeKindAwait(t, ctx, func() bool {
		return exec.CommandContext(ctx, "kubectl", "--kubeconfig", actorPath, "-n", realm, "get", "pod", podName, "-o", "name").Run() == nil
	})
	return actorPath, sends, successes
}
func abortRecoveryKindFinalizerPolicy(t *testing.T, ctx context.Context, realm string, pod map[string]any, actorConfig string) {
	t.Helper()
	meta := pod["metadata"].(map[string]any)
	podName := meta["name"].(string)
	policyName := realm + "-finalizer"
	actor := "system:serviceaccount:" + realm + ":native-abort"
	expression := "!oldObject.metadata.finalizers.exists(f,f == '" + abortRecoveryKindFinalizer + "') || (has(object.metadata.finalizers) && object.metadata.finalizers.exists(f,f == '" + abortRecoveryKindFinalizer + "')) || (request.userInfo.username == '" + actor + "' && object.spec == oldObject.spec && object.metadata.uid == oldObject.metadata.uid && object.metadata.labels == oldObject.metadata.labels && object.metadata.annotations == oldObject.metadata.annotations && (has(object.metadata.finalizers) ? object.metadata.finalizers : []) == oldObject.metadata.finalizers.filter(f,f != '" + abortRecoveryKindFinalizer + "'))"
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy", "metadata": map[string]string{"name": policyName}, "spec": map[string]any{"failurePolicy": "Fail", "matchConstraints": map[string]any{"resourceRules": []map[string]any{{"apiGroups": []string{""}, "apiVersions": []string{"v1"}, "operations": []string{"UPDATE"}, "resources": []string{"pods"}}}}, "matchConditions": []map[string]string{{"name": "original", "expression": "object.metadata.namespace == '" + realm + "' && object.metadata.name == '" + podName + "'"}}, "validations": []map[string]string{{"expression": expression, "message": "exact abort actor and finalizer-only native delta required", "reason": "Forbidden"}}}})
	nativeKindApply(t, ctx, map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding", "metadata": map[string]string{"name": policyName}, "spec": map[string]any{"policyName": policyName, "validationActions": []string{"Deny"}}})
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "validatingadmissionpolicybinding", policyName, "--wait=false").Run()
		_ = exec.Command("kubectl", "delete", "validatingadmissionpolicy", policyName, "--wait=false").Run()
	})
	nativeKindAwait(t, ctx, func() bool {
		probe := nativeKindGet(t, ctx, "-n", realm, "get", "pod", podName, "-o", "json")
		if probe["metadata"].(map[string]any)["uid"] != meta["uid"] {
			t.Fatal("original native target replaced before admission proof")
		}
		finalizers, ok := probe["metadata"].(map[string]any)["finalizers"].([]any)
		if !ok {
			t.Fatal("original native finalizer preimage unavailable")
		}
		remaining := make([]any, 0, len(finalizers))
		hadNative := false
		for _, finalizer := range finalizers {
			if finalizer == abortRecoveryKindFinalizer {
				hadNative = true
				continue
			}
			remaining = append(remaining, finalizer)
		}
		if !hadNative {
			t.Fatal("original native finalizer absent before admission proof")
		}
		probe["metadata"].(map[string]any)["finalizers"] = remaining
		body, _ := json.Marshal(probe)
		request := exec.CommandContext(ctx, "kubectl", "replace", "--dry-run=server", "-f", "-")
		request.Stdin = bytes.NewReader(body)
		out, err := request.CombinedOutput()
		return err != nil && strings.Contains(string(out), policyName) && strings.Contains(string(out), "exact abort actor and finalizer-only native delta required")
	})
	denied := exec.CommandContext(ctx, "kubectl", "--kubeconfig", actorConfig, "-n", realm, "auth", "can-i", "delete", "pods")
	out, err := denied.CombinedOutput()
	if err == nil || strings.TrimSpace(string(out)) != "no" {
		t.Fatal("adapter actor unexpectedly has native delete authority")
	}
}
