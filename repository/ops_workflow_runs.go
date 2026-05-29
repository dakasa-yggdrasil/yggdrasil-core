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
		args = append(args, pq.Array(toWorkflowRunStatuses(filter.Status)))
		clauses = append(clauses, "status = ANY($"+strconv.Itoa(len(args))+")")
	}
	if filter.Integration != "" {
		args = append(args, filter.Integration)
		clauses = append(clauses, "COALESCE(metadata->>'integration', '') = $"+strconv.Itoa(len(args)))
	}
	if filter.Search != "" {
		args = append(args, "%"+filter.Search+"%")
		ph := "$" + strconv.Itoa(len(args))
		clauses = append(clauses, "(id::text ILIKE "+ph+" OR workflow_name ILIKE "+ph+")")
	}

	args = append(args, limit)
	limitArg := "$" + strconv.Itoa(len(args))

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	// Integration + source fields ride along workflow_runs.metadata, but
	// the three writers that create runs (workflow_scheduler,
	// workflow_event_triggers, heimdall_inbox_dispatcher) all stamp
	// `triggered_by` and none of them stamp `integration` or `source`.
	// The /ops/workflows listing fed off the never-written keys and
	// surfaced "Sem integração / Sem origem" on every row.
	//
	// Resolution chain (first non-empty wins):
	//   integration:
	//     metadata->>'integration' (legacy + manual ops UI)
	//     → first dash-segment of workflow_name (heimdall-cycle-stale-pulse → heimdall)
	//   source:
	//     metadata->>'source'        (explicit override from an operator)
	//     → metadata->>'trigger_source' (legacy key from older code paths)
	//     → metadata->>'triggered_by'   (canonical key all live writers use)
	//     → 'unknown' (safe default)
	q := `SELECT id::text, COALESCE(workflow_name, ''),
	             COALESCE(
	                 NULLIF(metadata->>'integration', ''),
	                 split_part(COALESCE(workflow_name, ''), '-', 1),
	                 ''
	             ),
	             status,
	             started_at, finished_at,
	             COALESCE(
	                 NULLIF(metadata->>'source', ''),
	                 NULLIF(metadata->>'trigger_source', ''),
	                 NULLIF(metadata->>'triggered_by', ''),
	                 'unknown'
	             ),
	             COALESCE(error, '')
	      FROM public.workflow_runs ` + where + `
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
		r.Status = toOpsWorkflowStatus(r.Status)
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

func toWorkflowRunStatuses(statuses []string) []string {
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		switch strings.TrimSpace(strings.ToLower(status)) {
		case "active":
			out = append(out, "running")
		case "scheduled":
			out = append(out, "pending")
		case "aborted":
			out = append(out, "cancelled")
		case "cancelled":
			out = append(out, "cancelled")
		case "running", "pending", "succeeded", "failed":
			out = append(out, strings.TrimSpace(strings.ToLower(status)))
		default:
			if trimmed := strings.TrimSpace(status); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func toOpsWorkflowStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "running":
		return "active"
	case "pending":
		return "scheduled"
	case "cancelled":
		return "aborted"
	default:
		return status
	}
}
