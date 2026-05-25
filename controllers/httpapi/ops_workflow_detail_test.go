package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestHandleOpsWorkflowDetail_HappyPath_ReturnsRun verifies that the detail
// endpoint queries workflow_runs using the actual column names defined in
// 00018_workflow_runs.sql (id, workflow_name, metadata, result), not the
// stale aliases (run_id, integration, outputs, steps) that produced a 500
// "pq: column run_id does not exist".
func TestHandleOpsWorkflowDetail_HappyPath_ReturnsRun(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	runUUID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// Query must reference `id` (not run_id), metadata JSON paths for
	// integration + trigger_source, `result` (not outputs), and a defaulted
	// steps blob from metadata->'steps'.
	mock.ExpectQuery(`SELECT .* FROM public\.workflow_runs WHERE id = \$1`).
		WithArgs(runUUID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "workflow_name", "integration", "status",
			"started_at", "finished_at", "trigger_source", "error",
			"inputs", "result", "steps",
		}).AddRow(
			runUUID.String(), "heimdall-ci-pulse", "github", "succeeded",
			nil, nil, "cron", "",
			"{}", "{}", "[]",
		))

	s := &Server{db: db}

	req := httptest.NewRequest("GET", "/api/v1/ops/workflows/"+runUUID.String(), nil)
	req.SetPathValue("runId", runUUID.String())
	rec := httptest.NewRecorder()
	s.handleOpsWorkflowDetail(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var out map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	require.Equal(t, runUUID.String(), out["run_id"])
	require.Equal(t, "heimdall-ci-pulse", out["workflow_name"])
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleOpsWorkflowDetail_InvalidUUID_Returns400 verifies that non-UUID
// path params produce a 400 instead of a pq cast-error 500. Operators
// occasionally request /api/v1/ops/workflows/{workflow-name} expecting
// lookup-by-name; we should return a clean error explaining the contract.
func TestHandleOpsWorkflowDetail_InvalidUUID_Returns400(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/workflows/heimdall-ci-pulse", nil)
	req.SetPathValue("runId", "heimdall-ci-pulse")
	rec := httptest.NewRecorder()
	s.handleOpsWorkflowDetail(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code, "body=%s", rec.Body.String())
}

// TestHandleOpsWorkflowDetail_NotFound_Returns404 verifies the sql.ErrNoRows
// branch returns 404 (run not found) rather than 500.
func TestHandleOpsWorkflowDetail_NotFound_Returns404(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	runUUID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	mock.ExpectQuery(`SELECT .* FROM public\.workflow_runs WHERE id = \$1`).
		WithArgs(runUUID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "workflow_name", "integration", "status",
			"started_at", "finished_at", "trigger_source", "error",
			"inputs", "result", "steps",
		}))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/workflows/"+runUUID.String(), nil)
	req.SetPathValue("runId", runUUID.String())
	rec := httptest.NewRecorder()
	s.handleOpsWorkflowDetail(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code, "body=%s", rec.Body.String())
}
