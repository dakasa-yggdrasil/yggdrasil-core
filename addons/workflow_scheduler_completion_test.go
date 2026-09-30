package addons

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type scheduledCompletionPayload struct {
	runID  uuid.UUID
	status string
}

type scheduledResultPayload struct{}

func (scheduledResultPayload) Match(value driver.Value) bool {
	raw, ok := value.(string)
	if !ok {
		return false
	}
	var result struct {
		Status   string         `json:"status"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return false
	}
	return result.Status == "failed" && result.Metadata["failed_step"] == "sync"
}

func (want scheduledCompletionPayload) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false
	}
	return payload["run_id"] == want.runID.String() &&
		payload["status"] == want.status &&
		payload["triggered_by"] == "schedule"
}

func TestFinishScheduledWorkflowRunPersistsTypedFailureAndEmitsDurableCompletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runID := uuid.New()
	workflowID := uuid.New()
	now := time.Now().UTC()
	response := model.RunWorkflowResponse{
		Workflow:   model.ManifestReference{ID: workflowID, Namespace: "dakasa", Name: "ses-suppression-sync", Version: 1},
		Status:     "failed",
		Metadata:   map[string]any{"failed_step": "sync"},
		StartedAt:  now.Add(-time.Minute),
		FinishedAt: now,
	}

	mock.ExpectExec(`UPDATE public\.workflow_runs`).
		WithArgs(runID, "failed", scheduledResultPayload{}, "step sync failed", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO public\.event_log`).
		WithArgs(sqlmock.AnyArg(), "workflow.run.completed", "v1", "workflow_run", runID.String(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			scheduledCompletionPayload{runID: runID, status: "failed"}, sqlmock.AnyArg(),
			sql.NullString{String: runID.String(), Valid: true}).
		WillReturnRows(sqlmock.NewRows([]string{"event_id"}).AddRow(uuid.New()))
	mock.ExpectCommit()

	if err := finishScheduledWorkflowRun(context.Background(), db, nil, runID, response, nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishScheduledWorkflowRunPreservesSuccessfulCompletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runID := uuid.New()
	now := time.Now().UTC()
	response := model.RunWorkflowResponse{
		Workflow:   model.ManifestReference{ID: uuid.New(), Namespace: "dakasa", Name: "ses-suppression-sync", Version: 1},
		Status:     "succeeded",
		StartedAt:  now.Add(-time.Minute),
		FinishedAt: now,
	}
	mock.ExpectExec(`UPDATE public\.workflow_runs`).
		WithArgs(runID, "succeeded", sqlmock.AnyArg(), "", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO public\.event_log`).
		WithArgs(sqlmock.AnyArg(), "workflow.run.completed", "v1", "workflow_run", runID.String(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			scheduledCompletionPayload{runID: runID, status: "succeeded"}, sqlmock.AnyArg(),
			sql.NullString{String: runID.String(), Valid: true}).
		WillReturnRows(sqlmock.NewRows([]string{"event_id"}).AddRow(uuid.New()))
	mock.ExpectCommit()

	if err := finishScheduledWorkflowRun(context.Background(), db, nil, runID, response, nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishScheduledWorkflowRunDoesNotEmitCompletionWithoutTypedResponse(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runID := uuid.New()
	mock.ExpectExec(`UPDATE public\.workflow_runs`).
		WithArgs(runID, "failed", "", "manifest unavailable", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := finishScheduledWorkflowRun(context.Background(), db, nil, runID,
		model.RunWorkflowResponse{}, errors.New("manifest unavailable")); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishScheduledWorkflowRunDoesNotEmitBeforeDurableFinalization(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runID := uuid.New()
	mock.ExpectExec(`UPDATE public\.workflow_runs`).
		WithArgs(runID, "succeeded", sqlmock.AnyArg(), "", sqlmock.AnyArg()).
		WillReturnError(errors.New("database unavailable"))

	err = finishScheduledWorkflowRun(context.Background(), db, nil, runID,
		model.RunWorkflowResponse{Status: "succeeded"}, nil)
	if err == nil || err.Error() != "finalize workflow_run: database unavailable" {
		t.Fatalf("finalize error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
