package repository

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

func ListOpsWorkflowRuns(ctx context.Context, db *sql.DB, filter model.ListOpsWorkflowsFilter) (model.OpsWorkflowsResponse, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var clauses []string
	var args []any

	if len(filter.Status) > 0 {
		args = append(args, pq.Array(filter.Status))
		clauses = append(clauses, "status = ANY($"+strconv.Itoa(len(args))+")")
	}
	if filter.Integration != "" {
		args = append(args, filter.Integration)
		clauses = append(clauses, "integration = $"+strconv.Itoa(len(args)))
	}
	if filter.Search != "" {
		args = append(args, "%"+filter.Search+"%")
		ph := "$" + strconv.Itoa(len(args))
		clauses = append(clauses, "(run_id ILIKE "+ph+" OR workflow_name ILIKE "+ph+")")
	}

	args = append(args, limit)
	limitArg := "$" + strconv.Itoa(len(args))

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	q := `SELECT run_id, COALESCE(workflow_name, ''),
	             COALESCE(integration, ''), status,
	             started_at, finished_at,
	             COALESCE(trigger_source, 'unknown'),
	             COALESCE(error, '')
	      FROM workflow_runs ` + where + `
	      ORDER BY COALESCE(started_at, NOW()) DESC LIMIT ` + limitArg

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return model.OpsWorkflowsResponse{}, err
	}
	defer rows.Close()

	out := model.OpsWorkflowsResponse{Runs: []model.OpsWorkflowRun{}}
	for rows.Next() {
		var r model.OpsWorkflowRun
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(&r.RunID, &r.WorkflowName, &r.Integration, &r.Status,
			&startedAt, &finishedAt, &r.TriggerSource, &r.Error); err != nil {
			return model.OpsWorkflowsResponse{}, err
		}
		if startedAt.Valid {
			t := startedAt.Time
			r.StartedAt = &t
		}
		if startedAt.Valid && finishedAt.Valid {
			d := finishedAt.Time.Sub(startedAt.Time).Milliseconds()
			r.DurationMS = &d
		}
		out.Runs = append(out.Runs, r)
	}
	if err := rows.Err(); err != nil {
		return model.OpsWorkflowsResponse{}, err
	}
	return out, nil
}
