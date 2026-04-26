package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrWorkflowRunNotFound is returned by GetWorkflowRun when the id has no
// matching row. Callers map this to HTTP 404.
var ErrWorkflowRunNotFound = errors.New("workflow run not found")

// InsertWorkflowRun creates one workflow_runs row in pending status. Used
// as the first step of an async run — the goroutine that executes the
// workflow updates the same row to running → succeeded/failed.
func InsertWorkflowRun(
	ctx context.Context,
	db *sql.DB,
	id uuid.UUID,
	selector model.ManifestSelector,
	inputs map[string]any,
	metadata map[string]any,
) error {
	inputsJSON := mustEncodeJSON(inputs, "{}")
	metadataJSON := mustEncodeJSON(metadata, "{}")

	const q = `
		INSERT INTO public.workflow_runs
			(id, workflow_namespace, workflow_name, workflow_version, status, inputs, metadata)
		VALUES ($1, $2, $3, $4, 'pending', $5::jsonb, $6::jsonb)
	`

	var version any
	if selector.Version != nil {
		version = *selector.Version
	}

	if _, err := db.ExecContext(ctx, q, id, selector.Namespace, selector.Name, version, inputsJSON, metadataJSON); err != nil {
		return fmt.Errorf("insert workflow_run: %w", err)
	}
	return nil
}

// MarkWorkflowRunRunning records that execution has started. Idempotent —
// safe to call once per run.
func MarkWorkflowRunRunning(ctx context.Context, db *sql.DB, id uuid.UUID, startedAt time.Time) error {
	const q = `
		UPDATE public.workflow_runs
		SET status = 'running', started_at = $2, updated_at = NOW()
		WHERE id = $1 AND status = 'pending'
	`
	if _, err := db.ExecContext(ctx, q, id, startedAt); err != nil {
		return fmt.Errorf("update workflow_run running: %w", err)
	}
	return nil
}

// FinalizeWorkflowRun records the terminal status of an async execution.
// The result payload is the full RunWorkflowResponse encoded as JSON so a
// poller can reconstruct exactly what the sync caller would have seen.
func FinalizeWorkflowRun(
	ctx context.Context,
	db *sql.DB,
	id uuid.UUID,
	status string,
	result any,
	errMessage string,
	finishedAt time.Time,
) error {
	resultJSON := mustEncodeJSON(result, "")
	const q = `
		UPDATE public.workflow_runs
		SET status = $2,
		    result = NULLIF($3, '')::jsonb,
		    error = NULLIF($4, ''),
		    finished_at = $5,
		    updated_at = NOW()
		WHERE id = $1
	`
	if _, err := db.ExecContext(ctx, q, id, status, string(resultJSON), errMessage, finishedAt); err != nil {
		return fmt.Errorf("finalize workflow_run: %w", err)
	}
	return nil
}

// GetWorkflowRun fetches one row by id. Returns ErrWorkflowRunNotFound on
// no match so callers can map it to HTTP 404 without parsing sql.ErrNoRows.
func GetWorkflowRun(ctx context.Context, db *sql.DB, id uuid.UUID) (model.WorkflowRunRecord, error) {
	const q = `
		SELECT id, workflow_namespace, workflow_name, workflow_version, status,
		       inputs, metadata, result, error, started_at, finished_at, created_at, updated_at
		FROM public.workflow_runs
		WHERE id = $1
	`
	var rec model.WorkflowRunRecord
	var inputsRaw, metadataRaw []byte
	var resultRaw, errMsg sql.NullString
	var startedAt, finishedAt sql.NullTime
	var version sql.NullInt32

	err := db.QueryRowContext(ctx, q, id).Scan(
		&rec.ID, &rec.WorkflowNamespace, &rec.WorkflowName, &version, &rec.Status,
		&inputsRaw, &metadataRaw, &resultRaw, &errMsg,
		&startedAt, &finishedAt, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.WorkflowRunRecord{}, ErrWorkflowRunNotFound
	}
	if err != nil {
		return model.WorkflowRunRecord{}, fmt.Errorf("query workflow_run: %w", err)
	}

	if version.Valid {
		v := int(version.Int32)
		rec.WorkflowVersion = &v
	}
	if startedAt.Valid {
		t := startedAt.Time
		rec.StartedAt = &t
	}
	if finishedAt.Valid {
		t := finishedAt.Time
		rec.FinishedAt = &t
	}
	if errMsg.Valid {
		rec.Error = errMsg.String
	}
	if len(inputsRaw) > 0 {
		_ = json.Unmarshal(inputsRaw, &rec.Inputs)
	}
	if len(metadataRaw) > 0 {
		_ = json.Unmarshal(metadataRaw, &rec.Metadata)
	}
	if resultRaw.Valid && resultRaw.String != "" {
		var result model.RunWorkflowResponse
		if err := json.Unmarshal([]byte(resultRaw.String), &result); err == nil {
			rec.Result = &result
		}
	}
	return rec, nil
}

func mustEncodeJSON(value any, fallback string) string {
	if value == nil {
		return fallback
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fallback
	}
	return string(raw)
}
