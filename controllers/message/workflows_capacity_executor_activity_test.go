package message

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestCapacityExecutorActivityWorkflowReachesDurableStore(t *testing.T) {
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	policyID, workflowID := uuid.New(), uuid.New()
	p := model.CapacityPolicySpec{Environment: "lab", Domain: "ai", Dimension: "executor", TargetIdentity: "fixed-lab", Owner: "lab-owner", Workflow: model.ManifestSelector{Namespace: "ops", Name: "lab-executor"}, Currency: "USD", Floor: 1, Ceiling: 1, Step: 1, MaxEvidenceAgeSeconds: 30, MinSamples: 1, MaxSampleGapSeconds: 10, DownHoldSeconds: 10, LeaseSeconds: 30, ExecutionEnabled: true,
		Signals: []model.CapacitySignalRule{{Name: "tasks", SourceIdentity: "fixed-sensor", Unit: "count", UpAbove: 1, DownBelow: 0}}, Profiles: []model.CapacityProfile{{Name: "lab", Provider: "aws", Region: "us-east-1", MinUnits: 1, MaxUnits: 1, ValidationRef: "source-only", QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour)}}, ExecutorActivityBinding: &model.CapacityExecutorActivityBinding{Mode: "executor_activity_v1", LeaseTTLSeconds: 90, IdleAfterSeconds: 600, MaxObservationAgeSeconds: 30, MaxTasks: 10000}}
	raw, _ := json.Marshal(p)
	columns := []string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}
	mock.ExpectQuery(`SELECT .* FROM public.manifests WHERE kind`).WithArgs("capacity_policy", "ops", "lab").WillReturnRows(sqlmock.NewRows(columns).AddRow(policyID, "v1", "capacity_policy", "ops", "lab", 1, true, "", []byte(`{}`), raw, "policy-checksum", now, now))
	wf := []byte(`{"trigger":{"mode":"manual"},"authorization":{"rbac":{"namespace":"ops","name":"lab-rbac"}},"steps":[{"id":"activity","use":{"kind":"yggdrasil","operation":"capacity.record_executor_activity"}}]}`)
	mock.ExpectQuery(`SELECT .* FROM public.manifests WHERE kind`).WithArgs("workflow", "ops", "lab-executor").WillReturnRows(sqlmock.NewRows(columns).AddRow(workflowID, "v1", "workflow", "ops", "lab-executor", 1, true, "", []byte(`{}`), wf, "workflow-checksum", now, now))
	key, _ := json.Marshal([]string{"ops", "lab", "ai", "executor"})
	pin, _ := json.Marshal([]string{policyID.String(), "policy-checksum", workflowID.String()})
	binding := fmt.Sprintf("%x", sha256.Sum256(pin))
	state, _ := json.Marshal(executoractivity.ExecutorActivityState{Revision: 3, UpdatedAt: now, Tasks: map[string]executoractivity.ExecutorTaskLease{}})
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(string(key)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT checksum, active`).WithArgs(policyID, "ops", "lab").WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow("policy-checksum", true))
	mock.ExpectQuery(`SELECT active FROM public.manifests`).WithArgs(workflowID, "ops", "lab-executor").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery(`SELECT clock_timestamp`).WillReturnRows(sqlmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
	mock.ExpectQuery(`SELECT revision, state`).WithArgs(string(key), binding).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}).AddRow(3, state))
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WithArgs(string(key), binding, int64(4), sqlmock.AnyArg(), int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	ref := model.ManifestReference{ID: workflowID, Kind: "workflow", Namespace: "ops", Name: "lab-executor", Version: 1}
	result := executeCapacityWorkflowStep(newCapacityInvocationContext(WithExecutorActivityMachinePrincipal(context.Background(), "agent-a")), db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.record_executor_activity", Status: "failed"}, map[string]any{"policy": map[string]any{"namespace": "ops", "name": "lab"}, "executor_activity": map[string]any{"event": map[string]any{"task_id": "run-a", "sequence": 1, "release": false}}})
	if result.Status != "succeeded" || result.Metadata["demand_pending"] != true || result.Metadata["active_tasks"] != float64(1) {
		t.Fatal(result.Status, result.Error, result.Metadata)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
