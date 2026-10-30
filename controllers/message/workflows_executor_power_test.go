package message

import (
	"context"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestExecutorPowerWorkflowRejectsForgedObservationAndActor(t *testing.T) {
	for _, body := range []map[string]any{
		{"operator_id": "forged"},
		{"executor_power": map[string]any{"observation": map[string]any{"account_id": "123456789012"}}},
		{"executor_power": map[string]any{"resource": map[string]any{"instance_id": "i-0123456789abcdef0"}}},
	} {
		result := executeCapacityWorkflowStep(context.Background(), nil, model.ManifestReference{}, model.WorkflowRunStepResult{Operation: "capacity.adopt_executor_power"}, body)
		if result.Status == "succeeded" || !strings.Contains(result.Error, "unknown field") {
			t.Fatal(result)
		}
	}
}
func TestExecutorPowerAdoptionRequiresSeparateWorkflowAndSourceFactory(t *testing.T) {
	for _, correctWorkflow := range []bool{false, true} {
		t.Run(map[bool]string{false: "controller workflow denied", true: "qualified observer absent"}[correctWorkflow], func(t *testing.T) {
			t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
			t.Setenv("YGGDRASIL_EXECUTOR_POWER_ENABLED", "true")
			db, m, _ := sqlmock.New()
			defer db.Close()
			now := time.Now().UTC()
			policyID, wfID := uuid.New(), uuid.New()
			p := model.CapacityPolicySpec{Environment: "lab", Domain: "ai", Dimension: "executor", TargetIdentity: "fixed-lab", Owner: "lab-owner", Workflow: model.ManifestSelector{Namespace: "ops", Name: "controller"}, Currency: "USD", Floor: 1, Ceiling: 1, Step: 1, MaxEvidenceAgeSeconds: 30, MinSamples: 1, MaxSampleGapSeconds: 10, DownHoldSeconds: 10, LeaseSeconds: 30, ExecutionEnabled: true,
				Signals: []model.CapacitySignalRule{{Name: "tasks", SourceIdentity: "sensor", Unit: "count", UpAbove: 1, DownBelow: 0}}, Profiles: []model.CapacityProfile{{Name: "lab", Provider: "aws", Region: "us-east-1", MinUnits: 1, MaxUnits: 1, ValidationRef: "source", QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour)}}, ExecutorActivityBinding: &model.CapacityExecutorActivityBinding{Mode: "executor_activity_v1", LeaseTTLSeconds: 90, IdleAfterSeconds: 600, MaxObservationAgeSeconds: 30, MaxTasks: 10000},
				ExecutorPowerBinding: &executorpower.Binding{Mode: executorpower.Kind, Enabled: true, Resource: executorpower.Resource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", Volumes: []string{"vol-0123456789abcdef0"}}, IntegrationID: uuid.NewString(), IntegrationChecksum: strings.Repeat("a", 64), TypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64), AdapterPrincipal: "adapter", ControllerPrincipal: "controller", Operators: []string{"11111111-1111-4111-8111-111111111111"}, AdoptionWorkflow: executorpower.Workflow{Namespace: "ops", Name: "adopt"}, GrantSeconds: 30}}
			raw, _ := json.Marshal(p)
			cols := []string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}
			m.ExpectQuery(`SELECT .* FROM public.manifests WHERE kind`).WithArgs("capacity_policy", "ops", "lab").WillReturnRows(sqlmock.NewRows(cols).AddRow(policyID, "v1", "capacity_policy", "ops", "lab", 1, true, "", []byte(`{}`), raw, "policy", now, now))
			ref := model.ManifestReference{ID: wfID, Kind: "workflow", Namespace: "ops", Name: "controller", Version: 1}
			if correctWorkflow {
				ref.Name = "adopt"
				wf := []byte(`{"trigger":{"mode":"manual"},"authorization":{"rbac":{"namespace":"ops","name":"rbac"}},"steps":[{"id":"adopt","use":{"kind":"yggdrasil","operation":"capacity.adopt_executor_power"}}]}`)
				m.ExpectQuery(`SELECT .* FROM public.manifests WHERE kind`).WithArgs("workflow", "ops", "adopt").WillReturnRows(sqlmock.NewRows(cols).AddRow(wfID, "v1", "workflow", "ops", "adopt", 1, true, "", []byte(`{}`), wf, "wf", now, now))
			}
			ctx := newCapacityInvocationContext(WithExecutorPowerOperator(context.Background(), p.ExecutorPowerBinding.Operators[0]))
			r := executeCapacityWorkflowStep(ctx, db, ref, model.WorkflowRunStepResult{Operation: "capacity.adopt_executor_power"}, map[string]any{"policy": map[string]any{"namespace": "ops", "name": "lab"}})
			want := "does not authorize this workflow"
			if correctWorkflow {
				want = executorpower.ErrDenied.Error()
			}
			if r.Status == "succeeded" || !strings.Contains(r.Error, want) {
				t.Fatal(r.Error, r.Status)
			}
			if err := m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
