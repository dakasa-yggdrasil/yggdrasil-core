package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/require"
)

func TestListOpsWorkflowRuns_NoFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "workflow_name", "integration", "status", "started_at", "finished_at", "trigger_source", "error"}).
		AddRow("r1", "wf-a", "heimdall", "running", nil, nil, "manual", "")

	mock.ExpectQuery(`SELECT .* FROM public\.workflow_runs`).WillReturnRows(rows)

	out, err := ListOpsWorkflowRuns(context.Background(), db, model.ListOpsWorkflowsFilter{Limit: 50})
	require.NoError(t, err)
	require.Len(t, out.Runs, 1)
	require.Equal(t, "r1", out.Runs[0].RunID)
	require.Equal(t, "active", out.Runs[0].Status)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestListOpsWorkflowRuns_StatusFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "workflow_name", "integration", "status", "started_at", "finished_at", "trigger_source", "error"})
	mock.ExpectQuery(`SELECT .* FROM public\.workflow_runs WHERE .*status = ANY\(\$1\)`).
		WithArgs(sqlmock.AnyArg(), 50).
		WillReturnRows(rows)

	_, err = ListOpsWorkflowRuns(context.Background(), db, model.ListOpsWorkflowsFilter{
		Status: []string{"failed"}, Limit: 50,
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
