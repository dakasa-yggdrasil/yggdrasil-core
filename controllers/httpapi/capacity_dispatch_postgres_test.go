package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

type dispatchHTTPFixture struct {
	db                     *sql.DB
	service                *CapacityDispatchService
	server                 *Server
	workflow, policy, rbac model.Manifest
	spec                   model.CapacityPolicySpec
	create                 func(string, string, any) model.Manifest
	allow                  model.RBACManifestSpec
}

func dispatchHTTPPostgresFixture(t *testing.T) dispatchHTTPFixture {
	t.Helper()
	if os.Getenv("DB_URL") == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("strict native PostgreSQL dispatch authorization required")
		}
		t.Skip("remote native PostgreSQL authorization gate")
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(12)
	realm := "dispatch-auth-" + uuid.NewString()
	create := func(kind, name string, value any) model.Manifest {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		m, err := repository.CreateManifestVersion(t.Context(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: realm, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	allow := model.RBACManifestSpec{Roles: []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "allow", Resources: []string{"workflow:" + realm + ":pressure"}, Actions: []string{"run"}}}}}, Bindings: []model.RBACBinding{{Name: "operator", Subjects: []model.RBACSubject{{Type: "service", ID: "dispatch-ci"}}, Roles: []string{"controller"}}}}
	rbac := create("rbac", "dispatch", allow)
	enabled := true
	wf := create("workflow", "pressure", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", Timezone: "UTC"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: realm, Name: "dispatch"}}, Steps: []model.WorkflowStepSpec{{ID: "native", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.execute_bound"}, With: map[string]any{"policy": map[string]any{"namespace": realm, "name": "pods"}}}}})
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64)}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "dispatch-ci", Domain: "auth", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/dispatch", Owner: "capacity-ci", Workflow: model.ManifestSelector{Namespace: realm, Name: "pressure"}, Currency: "USD", Floor: 2, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 60, MinSamples: 1, MaxSampleGapSeconds: 10, DownHoldSeconds: 1, LeaseSeconds: 90, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixture/native", Unit: "ratio", UpAbove: .8, DownBelow: .2}}, Profiles: []model.CapacityProfile{{Name: "pods", Provider: "kubernetes", Region: "fixture", MinUnits: 2, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:scope-only"}}, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: "platform", HPAName: "api", HPAUID: "fixture-hpa", WorkloadName: "api", WorkloadUID: "fixture-workload", Owner: "capacity-ci", Profile: "pods", ProtectedFloor: 2, MaximumReplicas: 4}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: adapter, BindingName: "pressure", BindingSHA256: strings.Repeat("c", 64)}}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "fixture-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", BirthGuardBinding: "api-birth", BirthGuardSHA256: strings.Repeat("d", 64), ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("e", 64), Lanes: []string{"listener"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: realm, Name: "admit"}}, ControllerBinding: &model.CapacityControllerBinding{Mode: repository.CapacityDispatchProtocol, MachinePrincipalID: "dispatch-ci", DispatchLeaseSeconds: 90}}
	if manifest.ValidateCapacityPolicySpec(p) != nil {
		t.Fatal("invalid owning fixture policy")
	}
	policy := create("capacity_policy", "pods", p)
	t.Setenv("YGGDRASIL_ENV", "development")
	t.Setenv(CapacityDispatchEnabledEnv, "true")
	for _, key := range []string{eventPublisherPrincipalsEnv, "YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON", capacityMutationPrincipalsEnv, "YGGDRASIL_WORKFLOW_RUN_TOKEN", legacyScopedWorkflowTokensEnv, "YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", legacyEventPublishTokenEnv, "YGGDRASIL_DEPLOY_TOKEN", "YGGDRASIL_AUTH_ADMIN_TOKEN", "YGGDRASIL_WORKFLOW_DISPATCH_LOCK_JSON"} {
		t.Setenv(key, "")
		if os.Unsetenv(key) != nil {
			t.Fatal("fixture environment isolation failed")
		}
	}
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "dispatch-ci-fixture-credential", "dispatch-ci", machineWorkflowRef{Namespace: realm, Name: "pressure"}))
	var service *CapacityDispatchService
	var server *Server
	_, err = New("dispatch-auth-ci", db, nil, zap.NewNop(), WithCapacityDispatchServiceReceiver(func(s *CapacityDispatchService) { service = s }), func(s *Server) { server = s })
	if err != nil || service == nil || server == nil {
		t.Fatal("owning server service missing", err)
	}
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM public.capacity_dispatch_wakes WHERE realm=$1`, `DELETE FROM public.capacity_dispatch_jobs WHERE realm=$1`, `DELETE FROM public.workflow_runs WHERE workflow_namespace=$1`, `DELETE FROM public.manifests WHERE namespace=$1`} {
			if _, err := db.ExecContext(context.Background(), q, realm); err != nil {
				t.Error(err)
			}
		}
		if db.Close() != nil {
			t.Error("fixture native DB close failed")
		}
	})
	return dispatchHTTPFixture{db: db, service: service, server: server, workflow: wf, policy: policy, rbac: rbac, spec: p, create: create, allow: allow}
}

func (f dispatchHTTPFixture) prepare(t *testing.T) *CapacityDispatchPrepared {
	t.Helper()
	p, err := f.service.PrepareScheduledTick(t.Context(), f.workflow.ID, time.Now().UTC().Truncate(time.Minute))
	if err != nil || p == nil {
		t.Fatal("actual protected admission refused", err)
	}
	return p
}

func (f dispatchHTTPFixture) enqueue(t *testing.T, p *CapacityDispatchPrepared) repository.CapacityDispatchJob {
	t.Helper()
	tx, err := f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	job, _, err := p.Enqueue(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Commit() != nil {
		t.Fatal("original native tx commit failed")
	}
	return job
}

func TestCapacityDispatchAuthorizationPostgres(t *testing.T) {
	t.Run("actual_operator_binding_same_http_kernel", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		p := f.prepare(t)
		job := f.enqueue(t, p)
		if job.MachinePrincipalID != "dispatch-ci" || job.Policy.ID != f.policy.ID || job.RBAC.ID != f.rbac.ID || job.Workflow.ID != f.workflow.ID || job.State != "queued" {
			t.Fatal("operator/current authorization pins changed")
		}
		run, err := repository.GetWorkflowRun(t.Context(), f.db, job.RunID)
		if err != nil || run.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != "dispatch-ci" || run.Status != "pending" {
			t.Fatal("original run actor not server-bound", err)
		}
		encoded, _ := json.Marshal(job.CapacityDispatchEnvelope)
		if strings.Contains(string(encoded), "dispatch-ci-fixture-credential") || strings.Contains(string(encoded), "token_sha256") {
			t.Fatal("credential escaped private source")
		}
	})
	t.Run("caller_metadata_cannot_choose_principal", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		p := f.prepare(t)
		p.envelope.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] = "caller-selected"
		tx, err := f.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, err := p.Enqueue(t.Context(), tx); err == nil {
			t.Fatal("forged metadata became delegation")
		}
	})
	t.Run("current_rbac_revocation_before_start", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		job := f.enqueue(t, f.prepare(t))
		deny := f.allow
		deny.Roles = []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "deny", Resources: []string{"workflow:" + f.workflow.Metadata.Namespace + ":pressure"}, Actions: []string{"run"}}}}}
		f.create("rbac", "dispatch", deny)
		if _, _, err := f.service.authorizeEnvelope(t.Context(), job.CapacityDispatchEnvelope); err == nil {
			t.Fatal("old rbac snapshot adopted after revocation")
		}
		if _, err := repository.ClaimCapacityDispatch(t.Context(), f.db, job.Realm, job.Environment, uuid.New(), time.Minute); !errors.Is(err, repository.ErrCapacityDispatchClaim) {
			t.Fatal("revoked original graph was claimed", err)
		}
	})
	t.Run("revoked_expired_and_rotated_current_principal", func(t *testing.T) {
		for _, mode := range []string{"absent", "revoked", "expired", "rotated"} {
			t.Run(mode, func(t *testing.T) {
				f := dispatchHTTPPostgresFixture(t)
				job := f.enqueue(t, f.prepare(t))
				inventory := f.server.workflowRunAuthConfig()
				principal := &inventory.principals[0]
				switch mode {
				case "absent":
					inventory.principals = nil
				case "revoked":
					principal.Status = "revoked"
				case "expired":
					principal.ExpiresAt = time.Now().Add(-time.Second)
				case "rotated":
					principal.RotationID = "different-operator-rotation"
				}
				if _, _, err := f.service.authorizeEnvelope(t.Context(), job.CapacityDispatchEnvelope); err == nil {
					t.Fatal("changed current inventory retained original delegation")
				}
			})
		}
	})
	t.Run("changed_original_binding_and_workflow_refuse", func(t *testing.T) {
		for _, mode := range []string{"binding", "workflow"} {
			t.Run(mode, func(t *testing.T) {
				f := dispatchHTTPPostgresFixture(t)
				job := f.enqueue(t, f.prepare(t))
				if mode == "binding" {
					p := f.spec
					p.ControllerBinding = &model.CapacityControllerBinding{Mode: repository.CapacityDispatchProtocol, MachinePrincipalID: "different-operator", DispatchLeaseSeconds: 90}
					f.create("capacity_policy", "pods", p)
				} else {
					var wf model.WorkflowManifestSpec
					if json.Unmarshal(f.workflow.Spec, &wf) != nil {
						t.Fatal("fixture original graph missing")
					}
					wf.Steps[0].TimeoutSeconds = 45
					f.create("workflow", "pressure", wf)
				}
				if _, _, err := f.service.authorizeEnvelope(t.Context(), job.CapacityDispatchEnvelope); err == nil {
					t.Fatal("changed graph/binding auto-adopted original dispatch")
				}
			})
		}
	})
	t.Run("fixed_graph_refuses_retries_and_foreach", func(t *testing.T) {
		for _, mode := range []string{"retry", "foreach"} {
			t.Run(mode, func(t *testing.T) {
				f := dispatchHTTPPostgresFixture(t)
				var wf model.WorkflowManifestSpec
				if json.Unmarshal(f.workflow.Spec, &wf) != nil {
					t.Fatal("fixture graph missing")
				}
				if mode == "retry" {
					wf.Steps[0].Retry.MaxAttempts = 2
				} else {
					wf.Steps[0].ForEach = &model.WorkflowForEachSpec{Items: "{{ inputs.policy }}", As: "policy"}
				}
				changed := f.create("workflow", "pressure", wf)
				if _, err := f.service.PrepareScheduledTick(t.Context(), changed.ID, time.Now().UTC()); err == nil {
					t.Fatal("repeating graph became new original send permission")
				}
			})
		}
	})
	t.Run("paused_catalog_and_disabled_binding_hold", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		prepared := f.prepare(t)
		t.Setenv(CapacityDispatchEnabledEnv, "false")
		tx, err := f.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, err := prepared.Enqueue(t.Context(), tx); err == nil {
			t.Fatal("process disable after preparation ignored")
		}
		t.Setenv(CapacityDispatchEnabledEnv, "true")
		if _, err := f.db.ExecContext(t.Context(), `UPDATE public.manifests SET active=false WHERE id=$1`, f.workflow.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.PrepareScheduledTick(t.Context(), f.workflow.ID, time.Now().UTC()); err == nil {
			t.Fatal("paused original workflow admitted")
		}
	})
	t.Run("original_cause_and_private_error_format", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		cause := errors.New("private-native-fixture-cause")
		ctx, cancel := context.WithCancelCause(t.Context())
		cancel(cause)
		ran, err := f.service.RunOne(ctx, f.workflow.Metadata.Namespace, f.spec.Environment)
		if ran || !errors.Is(err, cause) {
			t.Fatal("original cause replaced", err)
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, err), cause.Error()) {
				t.Fatal("private cause formatted publicly")
			}
		}
		encoded, _ := json.Marshal(err)
		if strings.Contains(string(encoded), cause.Error()) {
			t.Fatal("private cause marshaled")
		}
	})
}

// This fixture exercises the actual RunOne -> RunWorkflow -> bound execute ->
// HTTP client Do/Read/Close composition. Only its CI-owned client trust and body
// faults are injected; neither authority nor a source observation is fabricated.
type dispatchOriginalRoundTrip func(*http.Request) (*http.Response, error)

func (f dispatchOriginalRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dispatchOriginalBody struct {
	io.ReadCloser
	read  func([]byte) (int, error)
	close func() error
}

func (b *dispatchOriginalBody) Read(p []byte) (int, error) { return b.read(p) }
func (b *dispatchOriginalBody) Close() error               { return b.close() }

type dispatchOriginalCause struct{ phase string }

func (e *dispatchOriginalCause) Error() string { return "private-native-source-" + e.phase }

func qualifyDispatchOriginalTransport(t *testing.T, mode string) {
	t.Helper()
	f := dispatchHTTPPostgresFixture(t)
	brokerURL := os.Getenv("CAPACITY_DISPATCH_BROKER_URL")
	if brokerURL == "" {
		t.Fatal("actual remote dispatch broker required")
	}
	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		t.Fatal("actual dispatch broker unavailable", err)
	}
	t.Cleanup(func() {
		if conn.Close() != nil {
			t.Error("actual broker Close failed")
		}
	})
	t.Setenv("BROKER_URL", brokerURL)
	f.server.rabbitmq = conn

	operations := []string{capacity.ObserveMetricRange, capacity.ObserveHPAEnvelope, capacity.ObserveCurrentBirthGuard}
	ts := model.IntegrationTypeManifestSpec{
		Provider: "dispatch-native-source", Domain: "infrastructure",
		Adapter:          model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute", Health: "/health"}, TimeoutSeconds: 65},
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"fixture_token": {Type: "string"}}},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}},
		ResourceTypes:    []model.IntegrationResourceType{{Name: "source", CanonicalPrefix: "thirdparty.dispatch-native-source.source", IdentityTemplate: "source.{id}", DefaultActions: operations}},
		Discovery:        model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"},
		Normalization:    model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.dispatch-native-source.source"},
	}
	for _, op := range operations {
		ts.ActionCatalog = append(ts.ActionCatalog, model.IntegrationActionDefinition{Name: op, ResourceTypes: []string{"source"}, Idempotent: true})
	}
	if err := manifest.ValidateIntegrationTypeSpec(ts); err != nil {
		t.Fatal("original native catalog invalid", err)
	}
	rawDescribe, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	var describe model.AdapterDescribeResponse
	if json.Unmarshal(rawDescribe, &describe) != nil {
		t.Fatal("original Describe fixture unavailable")
	}
	privateCredential := "ci-only-private-original-dispatch-credential"
	cause := &dispatchOriginalCause{phase: mode}
	var executes, redirected, closes atomic.Int32
	var readBytes atomic.Int64
	var originalChildDeadline atomic.Value
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sink.Close)
	adapter := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			if r.Method != http.MethodGet {
				t.Error("original health route changed")
			}
			w.WriteHeader(http.StatusOK)
		case "/describe":
			if r.Method != http.MethodPost {
				t.Error("original Describe route changed")
			}
			if json.NewEncoder(w).Encode(describe) != nil {
				t.Error("Describe write failed")
			}
		case "/execute":
			executes.Add(1)
			var request model.AdapterExecuteIntegrationRequest
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Operation != capacity.ObserveMetricRange || request.Capability != request.Operation || len(request.Auth) != 0 || len(request.Metadata) != 0 || request.Integration.InstanceSpec.Credentials["fixture_token"] != privateCredential {
				t.Error("actual original fixed source request missing")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch mode {
			case "redirect_307", "redirect_308":
				status := http.StatusTemporaryRedirect
				if mode == "redirect_308" {
					status = http.StatusPermanentRedirect
				}
				http.Redirect(w, r, sink.URL+"/execute", status)
			case "byte_cap":
				_, _ = io.WriteString(w, strings.Repeat("x", 4<<20))
			case "child_deadline":
				// The ORIGINAL 35s source context expires before the untouched
				// 90s dispatch deadline. No test-selected timer reports a return.
				<-r.Context().Done()
			default:
				if json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: request.Operation, Capability: request.Capability, Status: "succeeded", Output: map[string]any{}}) != nil {
					t.Error("original source response write failed")
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(adapter.Close)
	transport, ok := adapter.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("actual CI-owned TLS transport required")
	}
	// http.Client{} is the production constructor. Override only the process
	// default transport in this serial CI case, wrapping its actual TLS I/O.
	originalTransport := http.DefaultTransport
	http.DefaultTransport = dispatchOriginalRoundTrip(func(r *http.Request) (*http.Response, error) {
		reply, err := transport.RoundTrip(r)
		if r.URL.Path != "/execute" {
			return reply, err
		}
		deadline, hasDeadline := r.Context().Deadline()
		if !hasDeadline {
			t.Error("original source deadline absent")
		} else {
			originalChildDeadline.Store(deadline)
		}
		if reply != nil && reply.Body != nil {
			body := reply.Body
			reply.Body = &dispatchOriginalBody{ReadCloser: body,
				read: func(p []byte) (int, error) {
					if mode == "read_cause" {
						return 0, cause
					}
					n, err := body.Read(p)
					readBytes.Add(int64(n))
					return n, err
				},
				close: func() error {
					closes.Add(1)
					err := body.Close()
					if mode == "close_cause" {
						return errors.Join(err, cause)
					}
					return err
				},
			}
		}
		return reply, err
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
	typ := f.create("integration_type", "source", ts)
	instance := f.create("integration_instance", "source", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: map[string]any{"base_url": adapter.URL}, Credentials: map[string]any{"fixture_token": privateCredential}})
	binding := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	p := f.spec
	p.AssessmentBinding.Snapshot.Adapter = binding
	p.AssessmentBinding.Signals[0].Adapter = binding
	f.policy, f.spec = f.create("capacity_policy", "pods", p), p
	job := f.enqueue(t, f.prepare(t))
	parent, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	parentDeadline, _ := parent.Deadline()
	ran, runErr := f.service.RunOne(parent, job.Realm, job.Environment)
	if !ran || runErr == nil || parent.Err() != nil || !time.Now().Before(parentDeadline) || executes.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("actual original protected call escaped/refused incorrectly: ran=%t execute=%d redirect=%d err=%v", ran, executes.Load(), redirected.Load(), runErr)
	}
	if value := originalChildDeadline.Load(); value == nil || !value.(time.Time).Before(parentDeadline) {
		t.Fatal("source deadline detached from actual owning call")
	}
	if mode == "read_cause" || mode == "close_cause" {
		var typed *dispatchOriginalCause
		if !errors.Is(runErr, cause) || !errors.As(runErr, &typed) || typed != cause || closes.Load() != 1 {
			t.Fatal("original private Read/Close cause erased or copied", runErr)
		}
	}
	if mode == "byte_cap" && (readBytes.Load() != (2<<20)+1 || closes.Load() != 1) {
		t.Fatal("original response bytes or Close escaped the native cap")
	}
	if mode == "child_deadline" {
		var originalDo *url.Error
		if !errors.Is(runErr, context.DeadlineExceeded) || !errors.As(runErr, &originalDo) || originalDo.URL != adapter.URL+"/execute" {
			t.Fatal("original child Do deadline cause lost through RunWorkflow/RunOne", runErr)
		}
	}
	run, err := repository.GetWorkflowRun(t.Context(), f.db, job.RunID)
	if err != nil || run.Status != "failed" || run.Result == nil || run.Result.Status != "failed" || len(run.Result.Steps) != 1 || run.Result.Steps[0].Status != "failed" {
		t.Fatal("actual typed bound failure missing", err)
	}
	var state string
	var returned, ack sql.NullTime
	if err := f.db.QueryRowContext(t.Context(), `SELECT state,returned_at,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, job.JobID).Scan(&state, &returned, &ack); err != nil || !returned.Valid {
		t.Fatal("actual original return was not retained", err)
	}
	if mode == "child_deadline" {
		if state != "unknown" || ack.Valid {
			t.Fatal("original child deadline released uncertain dimension")
		}
		if ran, err := f.service.RunOne(parent, job.Realm, job.Environment); ran || !errors.Is(err, repository.ErrCapacityDispatchClaim) {
			t.Fatal("unknown actual source deadline was replayed", err)
		}
	} else if state != "returned" || !ack.Valid {
		t.Fatal("failed original return acknowledgment missing")
	}
	publicRun, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	privateValues := []string{privateCredential, cause.Error(), adapter.URL, sink.URL}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, value := range privateValues {
			if strings.Contains(fmt.Sprintf(format, runErr), value) {
				t.Fatal("private original cause formatted")
			}
		}
	}
	publicError, err := json.Marshal(runErr)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range privateValues {
		if bytes.Contains(publicRun, []byte(value)) || bytes.Contains(publicError, []byte(value)) {
			t.Fatal("private original source leaked into DTO or JSON")
		}
	}
}

func TestCapacityDispatchOriginalTransportPostgres(t *testing.T) {
	for _, mode := range []string{"redirect_307", "redirect_308", "byte_cap", "read_cause", "close_cause", "child_deadline"} {
		t.Run(mode, func(t *testing.T) { qualifyDispatchOriginalTransport(t, mode) })
	}
}
