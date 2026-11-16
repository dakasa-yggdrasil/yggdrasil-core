package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Both existing PG and KinD owning roots invoke this production dispatcher
// path. The adapter's response is a declared fixture; the original HTTP call,
// pending/running/final rows and owner return are real. No receipt or capacity
// success is inferred from the fixture response.
func qualifyProductionOriginalOwnerPostgres(t *testing.T) {
	t.Helper()
	f := dispatchHTTPPostgresFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	brokerURL := os.Getenv("CAPACITY_DISPATCH_BROKER_URL")
	if brokerURL == "" {
		brokerURL = os.Getenv("BROKER_URL")
	}
	previousBrokerURL, brokerWasSet := os.LookupEnv("BROKER_URL")
	t.Setenv("BROKER_URL", brokerURL)
	defer func() {
		if brokerWasSet {
			_ = os.Setenv("BROKER_URL", previousBrokerURL)
		} else {
			_ = os.Unsetenv("BROKER_URL")
		}
	}()
	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		t.Fatal("original owner requires actual broker", err)
	}
	defer conn.Close()
	f.server.rabbitmq = conn
	owners, err := NewOriginalWorkflowOwners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	WithOriginalWorkflowOwners(owners)(f.server)
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	typeSpec := model.IntegrationTypeManifestSpec{
		Provider: "original-owner-ci", Domain: "infrastructure",
		Adapter:      model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute", Health: "/health"}, TimeoutSeconds: 10},
		Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{}},
		InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}},
		ResourceTypes:  []model.IntegrationResourceType{{Name: "source", CanonicalPrefix: "thirdparty.original-owner-ci.source", IdentityTemplate: "source.{id}", DefaultActions: []string{"observe_state"}}},
		Discovery:      model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.original-owner-ci.source"},
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "observe_state", ResourceTypes: []string{"source"}, Idempotent: true}},
	}
	if err := manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("declared original adapter contract invalid", err)
	}
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/describe":
			_ = json.NewEncoder(w).Encode(typeSpec)
		case "/execute":
			var request model.AdapterExecuteIntegrationRequest
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Operation != "observe_state" {
				http.Error(w, "fixture contract refused", http.StatusBadRequest)
				return
			}
			calls.Add(1)
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-release:
				_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: request.Operation, Capability: request.Capability, Status: "succeeded", Output: map[string]any{"original_return": true}})
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		releaseOnce.Do(func() { close(release) })
		adapter.Close()
	}()
	typ := f.create("integration_type", "owned-source", typeSpec)
	instance := f.create("integration_instance", "owned-source", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active", Config: map[string]any{"base_url": adapter.URL}})
	workflowSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Steps: []model.WorkflowStepSpec{{ID: "original", TimeoutSeconds: 10, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "integration", InstanceRef: &model.ManifestSelector{ManifestID: instance.ID.String()}, Operation: "observe_state"}}}}
	if err := manifest.ValidateWorkflowSpec(workflowSpec); err != nil {
		t.Fatal("declared original workflow invalid", err)
	}
	workflow := f.create("workflow", "owned-original", workflowSpec)
	req := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: workflow.Metadata.Namespace, Name: workflow.Metadata.Name}, Metadata: map[string]any{"idempotency_key": uuid.NewString()}}
	recorder := httptest.NewRecorder()
	f.server.dispatchAsyncWorkflowRun(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", bytes.NewReader(nil)).WithContext(ctx), req, workflowRunActor{})
	var accepted struct {
		RunID string `json:"run_id"`
	}
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &accepted) != nil || accepted.RunID == "" {
		t.Fatal("production original was not accepted", recorder.Code, recorder.Body.String())
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original adapter call did not start", ctx.Err())
	}
	id, err := uuid.Parse(accepted.RunID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := repository.GetWorkflowRun(ctx, f.db, id)
	if err != nil || before.Status != "running" {
		t.Fatal("actual original running row missing", err)
	}
	owners.Seal()
	bounded, stop := context.WithCancel(ctx)
	stop()
	if err := owners.Join(bounded); !errors.Is(err, context.Canceled) {
		t.Fatal("local timeout became original return", err)
	}
	if ctx.Err() != nil {
		t.Fatal("seal canceled original source parent")
	}
	refused := httptest.NewRecorder()
	f.server.dispatchAsyncWorkflowRun(refused, httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil).WithContext(ctx), req, workflowRunActor{})
	var count int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1 AND workflow_name=$2`, workflow.Metadata.Namespace, workflow.Metadata.Name).Scan(&count); err != nil || count != 1 || refused.Code != http.StatusConflict || calls.Load() != 1 {
		t.Fatal("drain inserted or replayed work", count, refused.Code, calls.Load(), err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := owners.Join(ctx); err != nil {
		t.Fatal("actual original HTTP/SQL return did not join", err)
	}
	after, err := repository.GetWorkflowRun(ctx, f.db, id)
	if err != nil || after.Status != "succeeded" || after.FinishedAt == nil || calls.Load() != 1 {
		t.Fatal("join preceded actual durable finalization", after.Status, calls.Load(), err)
	}
}
