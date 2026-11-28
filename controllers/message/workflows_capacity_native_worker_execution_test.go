package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeWorkerExecutionRequiresCurrentSynchronousOwner(t *testing.T) {
	ctx := context.Background()
	db := &sql.DB{}
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Active: true}}
	called := 0
	closed := false
	resolver := func(c context.Context, actualDB *sql.DB, actual model.Manifest, use func(context.Context, NativeWorkerExecutionScope) error) error {
		if closed || actualDB != db || actual.ID != policy.ID {
			return errors.New("closed or foreign owner")
		}
		called++
		return use(c, NativeWorkerExecutionScope{PoolReaderScopeSHA256: strings.Repeat("e", 64)})
	}
	if withNativeWorkerExecutionScope(ctx, db, policy, func(context.Context, NativeWorkerExecutionScope) error {
		t.Fatal("uninstalled owner invoked")
		return nil
	}) == nil {
		t.Fatal("missing owner accepted")
	}
	ctx = WithNativeWorkerExecutionResolver(ctx, resolver)
	if err := withNativeWorkerExecutionScope(ctx, db, policy, func(_ context.Context, scope NativeWorkerExecutionScope) error {
		wire, _ := json.Marshal(scope)
		if strings.Contains(string(wire), scope.PoolReaderScopeSHA256) {
			t.Fatal("scope representation leaked config")
		}
		return nil
	}); err != nil || called != 1 {
		t.Fatal(err, called)
	}
	closed = true
	if err := withNativeWorkerExecutionScope(ctx, db, policy, func(context.Context, NativeWorkerExecutionScope) error {
		t.Fatal("closed owner leaked handles")
		return nil
	}); err == nil || called != 1 {
		t.Fatal("retained stale owner", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if withNativeWorkerExecutionScope(cancelled, db, policy, func(context.Context, NativeWorkerExecutionScope) error { return nil }) == nil {
		t.Fatal("cancelled caller borrowed owner")
	}
}

func TestNativeWorkerExecutionFlagsCannotReplaceProtectedPorts(t *testing.T) {
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED", "true")
	p := model.CapacityPolicySpec{ExecutionEnabled: true, NativeWorkerLifecycleBinding: &model.CapacityNativeWorkerLifecycleBinding{Network: &model.CapacityNativeWorkerNetworkBinding{}, RegistryWriter: &model.CapacityNativeWorkerRegistryWriterBinding{}}}
	policy := model.Manifest{Kind: "capacity_policy", Metadata: model.ManifestMetadata{Active: true}}
	reads := 0
	read := func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error) {
		reads++
		return "", nil
	}
	fail := func(...error) model.WorkflowRunStepResult {
		return model.WorkflowRunStepResult{Status: "failed", Error: "HOLD"}
	}
	for _, operation := range []string{"capacity.execute_bound", "capacity.admit_bound"} {
		got := executeCapacityNativeWorkerExecution(context.Background(), nil, &sql.DB{}, policy, p, model.Manifest{}, model.WorkflowRunStepResult{Operation: operation}, read, fail)
		if got.Status != "failed" || reads != 0 {
			t.Fatal("flags opened uninstalled runtime", got.Status, reads)
		}
	}
}

func TestNativeWorkerExecutionCatalogIsClosedAndNativeOnly(t *testing.T) {
	ts := model.IntegrationTypeManifestSpec{Capabilities: []string{"execute"}}
	// Use JSON to keep this boundary fixture identical to catalog wire fields.
	for _, operation := range []string{"ensure_native_worker", "ensure_native_worker_pool", "destroy_native_worker"} {
		raw := `{"capabilities":["execute"],"action_catalog":[{"name":"` + operation + `","idempotent":false,"resource_types":["native_worker"]}],"resource_types":[{"name":"native_worker","default_actions":["` + operation + `"]}]}`
		if json.Unmarshal([]byte(raw), &ts) != nil || !nativeWorkerExecutionCatalog(ts, operation) {
			t.Fatal("native Source contract refused", operation)
		}
		ts.ActionCatalog[0].Idempotent = true
		if nativeWorkerExecutionCatalog(ts, operation) {
			t.Fatal("replayable mutation accepted")
		}
	}
	for _, operation := range []string{"ensure_server", "destroy_server", "ensure_capacity_pod_drain", "observe_native_worker", "Ensure_native_worker", ""} {
		raw := `{"capabilities":["execute"],"action_catalog":[{"name":"` + operation + `","idempotent":false,"resource_types":["native_worker"]}],"resource_types":[{"name":"native_worker","default_actions":["` + operation + `"]}]}`
		if json.Unmarshal([]byte(raw), &ts) != nil {
			t.Fatal("catalog fixture framing")
		}
		if nativeWorkerExecutionCatalog(ts, operation) {
			t.Fatal("unrelated authority selected", operation)
		}
	}
}
