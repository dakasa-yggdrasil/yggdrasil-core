package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/require"
)

func TestHandleOpsWorkflowsList_DefaultLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT .* FROM workflow_runs`).
		WillReturnRows(sqlmock.NewRows([]string{
			"run_id", "workflow_name", "integration", "status",
			"started_at", "finished_at", "trigger_source", "error",
		}))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/workflows", nil)
	rec := httptest.NewRecorder()
	s.handleOpsWorkflowsList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got model.OpsWorkflowsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsWorkflowsList_StatusFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT .* FROM workflow_runs WHERE .*status = ANY\(\$1\)`).
		WillReturnRows(sqlmock.NewRows([]string{
			"run_id", "workflow_name", "integration", "status",
			"started_at", "finished_at", "trigger_source", "error",
		}))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/workflows?status=failed&status=aborted", nil)
	rec := httptest.NewRecorder()
	s.handleOpsWorkflowsList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, mock.ExpectationsWereMet())
}
