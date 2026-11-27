package repository

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

func executorActivityRepositoryPolicy(t *testing.T) model.Manifest {
	t.Helper()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	p := model.CapacityPolicySpec{Environment: "lab", Domain: "ai", Dimension: "executor", TargetIdentity: "fixed-lab", Owner: "lab-owner", Workflow: model.ManifestSelector{Namespace: "ops", Name: "lab-executor"}, Currency: "USD", Floor: 1, Ceiling: 1, Step: 1, MaxEvidenceAgeSeconds: 30, MinSamples: 1, MaxSampleGapSeconds: 10, DownHoldSeconds: 10, LeaseSeconds: 30, ExecutionEnabled: true,
		Signals:                 []model.CapacitySignalRule{{Name: "tasks", SourceIdentity: "fixed-sensor", Unit: "count", UpAbove: 1, DownBelow: 0}},
		Profiles:                []model.CapacityProfile{{Name: "lab", Provider: "aws", Region: "us-east-1", MinUnits: 1, MaxUnits: 1, ValidationRef: "source-only", QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour)}},
		ExecutorActivityBinding: &model.CapacityExecutorActivityBinding{Mode: "executor_activity_v1", LeaseTTLSeconds: 90, IdleAfterSeconds: 600, MaxObservationAgeSeconds: 30, MaxTasks: 10000}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Checksum: "policy-checksum", Metadata: model.ManifestMetadata{Namespace: "ops", Name: "lab"}, Spec: raw}
}

func TestCapacityExecutorActivityPreservesExecutionGates(t *testing.T) {
	policy := executorActivityRepositoryPolicy(t)
	for _, store := range []CapacityStore{
		{},
		{ExecutionEnabled: true, WorkflowID: uuid.New()},
		{ExecutionEnabled: true, ExecutorID: "invocation", ExecutorActivityPrincipal: "machine:agent-a"},
		{ExecutionEnabled: true, WorkflowID: uuid.New(), ExecutorID: "invocation", AdmissionOnly: true},
	} {
		if _, err := store.ExecutorActivity(context.Background(), policy, "capacity.initialize_executor_activity", executoractivity.WorkflowRequest{}); err == nil {
			t.Fatal("unbound/disabled store admitted activity")
		}
	}
}

func TestCapacityExecutorActivityChecksCurrentPolicyBeforeState(t *testing.T) {
	policy := executorActivityRepositoryPolicy(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: uuid.New(), ExecutorID: "invocation", ExecutorActivityPrincipal: "machine:agent-a"}
	key, _ := json.Marshal([]string{"ops", "lab", "ai", "executor"})
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(string(key)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT checksum, active FROM public.manifests`).WithArgs(policy.ID, "ops", "lab").WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow("policy-checksum", false))
	mock.ExpectRollback()
	if _, err := store.ExecutorActivity(context.Background(), policy, "capacity.initialize_executor_activity", executoractivity.WorkflowRequest{}); err == nil {
		t.Fatal("revoked policy passed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityExecutorActivityRecordsThroughPinnedWorkflowTransaction(t *testing.T) {
	policy := executorActivityRepositoryPolicy(t)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: uuid.New(), ExecutorID: "invocation", ExecutorActivityPrincipal: "machine:agent-a"}
	key, _ := json.Marshal([]string{"ops", "lab", "ai", "executor"})
	pin, _ := json.Marshal([]string{policy.ID.String(), policy.Checksum, store.WorkflowID.String()})
	binding := fmt.Sprintf("%x", sha256.Sum256(pin))
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	state := executoractivity.ExecutorActivityState{Revision: 3, UpdatedAt: now, Tasks: map[string]executoractivity.ExecutorTaskLease{}}
	raw, _ := json.Marshal(state)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(string(key)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT checksum, active FROM public.manifests`).WithArgs(policy.ID, "ops", "lab").WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow(policy.Checksum, true))
	mock.ExpectQuery(`SELECT active FROM public.manifests`).WithArgs(store.WorkflowID, "ops", "lab-executor").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery(`SELECT clock_timestamp`).WillReturnRows(sqlmock.NewRows([]string{"clock_timestamp"}).AddRow(now))
	mock.ExpectQuery(`SELECT revision, state`).WithArgs(string(key), binding).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}).AddRow(3, raw))
	mock.ExpectExec(`UPDATE public.capacity_executor_activity`).WithArgs(string(key), binding, int64(4), sqlmock.AnyArg(), int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	result, err := store.ExecutorActivity(context.Background(), policy, "capacity.record_executor_activity", executoractivity.WorkflowRequest{Event: executoractivity.ExecutorActivityEvent{TaskID: "run-a", Sequence: 1}})
	if err != nil || result.Revision != 4 || result.ActiveTasks != 1 || !result.DemandPending {
		t.Fatal(result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
