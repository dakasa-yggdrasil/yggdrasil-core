package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// RecordOpsAuditEvent inserts one ops audit row. Best-effort — caller logs
// errors but never gates the user request on audit success.
func RecordOpsAuditEvent(ctx context.Context, db *sql.DB, ev model.OpsAuditEvent) error {
	requestBody, err := marshalJSONOrEmpty(ev.RequestBody)
	if err != nil {
		return fmt.Errorf("marshal request_body: %w", err)
	}
	result, err := marshalJSONOrEmpty(ev.Result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	const q = `
		INSERT INTO public.audit_events
			(actor, actor_collaborator_id, actor_session_id,
			 action, resource_kind, resource_id, outcome,
			 result_status, correlation_id, request_body, result, metadata)
		VALUES
			($1, $2, NULLIF($3, ''),
			 $4, $5, $6, COALESCE(NULLIF($7, ''), 'success'),
			 NULLIF($8, ''), NULLIF($9, ''), $10::jsonb, $11::jsonb, '{}'::jsonb)
	`
	_, err = db.ExecContext(ctx, q,
		ev.Actor, ev.ActorCollaboratorID, ev.ActorSessionID,
		ev.Action, ev.TargetKind, ev.TargetID, ev.ResultStatus,
		ev.ResultStatus, ev.CorrelationID, requestBody, result,
	)
	if err != nil {
		return fmt.Errorf("insert ops audit: %w", err)
	}
	return nil
}

// ListOpsAuditEvents queries audit_events using the rich ops filter shape.
func ListOpsAuditEvents(ctx context.Context, db *sql.DB, f model.ListOpsAuditEventsFilter) ([]model.OpsAuditEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	clauses := []string{"1=1"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf(cond, len(args)))
	}
	if f.Actor != "" {
		add("actor = $%d", f.Actor)
	}
	if f.ActorCollaboratorID != nil {
		add("actor_collaborator_id = $%d", *f.ActorCollaboratorID)
	}
	if f.ActionPrefix != "" {
		add("action LIKE $%d", f.ActionPrefix+"%")
	}
	if f.TargetKind != "" {
		add("resource_kind = $%d", f.TargetKind)
	}
	if f.TargetID != "" {
		add("resource_id = $%d", f.TargetID)
	}
	if f.ResultStatus != "" {
		add("result_status = $%d", f.ResultStatus)
	}
	if f.CorrelationID != "" {
		add("correlation_id = $%d", f.CorrelationID)
	}
	if !f.Since.IsZero() {
		add("created_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("created_at <= $%d", f.Until)
	}

	order := "DESC"
	if !f.OrderDesc {
		order = "DESC"
	}

	args = append(args, limit, f.Offset)
	q := fmt.Sprintf(`
		SELECT id, actor,
		       COALESCE(actor_collaborator_id::text, ''),
		       COALESCE(actor_session_id, ''),
		       action,
		       COALESCE(resource_kind, ''),
		       COALESCE(resource_id, ''),
		       COALESCE(result_status, ''),
		       COALESCE(correlation_id, ''),
		       COALESCE(request_body::text, '{}'),
		       COALESCE(result::text, '{}'),
		       created_at
		FROM public.audit_events
		WHERE %s
		ORDER BY created_at %s
		LIMIT $%d OFFSET $%d`,
		strings.Join(clauses, " AND "), order, len(args)-1, len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list ops audit: %w", err)
	}
	defer rows.Close()

	out := make([]model.OpsAuditEvent, 0, limit)
	for rows.Next() {
		var (
			ev          model.OpsAuditEvent
			collabIDStr string
			reqBodyJSON string
			resultJSON  string
		)
		if err := rows.Scan(
			&ev.ID, &ev.Actor, &collabIDStr, &ev.ActorSessionID,
			&ev.Action, &ev.TargetKind, &ev.TargetID, &ev.ResultStatus,
			&ev.CorrelationID, &reqBodyJSON, &resultJSON, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ops audit: %w", err)
		}
		if collabIDStr != "" {
			ev.ActorCollaboratorID = parseUUIDPtr(collabIDStr)
		}
		_ = json.Unmarshal([]byte(reqBodyJSON), &ev.RequestBody)
		_ = json.Unmarshal([]byte(resultJSON), &ev.Result)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func marshalJSONOrEmpty(m map[string]any) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func parseUUIDPtr(s string) *uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
