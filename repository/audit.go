package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// RecordAuditEvent inserts one event. Best-effort: errors are returned to
// the caller, but callers should NOT fail the originating user request when
// audit insertion fails (log and continue). Audit is observability, not
// business logic.
func RecordAuditEvent(ctx context.Context, db *sql.DB, ev model.AuditEvent) error {
	metadata := []byte("{}")
	if len(ev.Metadata) > 0 {
		raw, err := json.Marshal(ev.Metadata)
		if err == nil {
			metadata = raw
		}
	}
	const q = `
		INSERT INTO public.audit_events
			(actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::jsonb, NULLIF($8, ''), NULLIF($9, ''))
	`
	_, err := db.ExecContext(ctx, q,
		ev.Actor, ev.Action, ev.ResourceKind, ev.ResourceID, ev.Outcome,
		ev.TenantSlug, metadata, ev.TraceID, ev.SpanID,
	)
	if err != nil {
		return fmt.Errorf("insert audit_event: %w", err)
	}
	return nil
}

// ListAuditEvents queries audit_events with filters and a hard limit (max 1000).
func ListAuditEvents(ctx context.Context, db *sql.DB, f model.ListAuditEventsFilter) ([]model.AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var (
		clauses = []string{"1=1"}
		args    []any
	)
	add := func(cond string, val any) {
		args = append(args, val)
		clauses = append(clauses, fmt.Sprintf(cond, len(args)))
	}
	if f.Actor != "" {
		add("actor = $%d", f.Actor)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.ResourceKind != "" {
		add("resource_kind = $%d", f.ResourceKind)
	}
	if f.ResourceID != "" {
		add("resource_id = $%d", f.ResourceID)
	}
	if f.TenantSlug != "" {
		add("tenant_slug = $%d", f.TenantSlug)
	}
	if !f.Since.IsZero() {
		add("created_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("created_at <= $%d", f.Until)
	}

	q := fmt.Sprintf(`
		SELECT id, actor, action, resource_kind, resource_id, outcome,
		       COALESCE(tenant_slug, ''), COALESCE(metadata::text, '{}'),
		       COALESCE(trace_id, ''), COALESCE(span_id, ''),
		       created_at
		FROM public.audit_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT %d
	`, strings.Join(clauses, " AND "), limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit_events: %w", err)
	}
	defer rows.Close()

	var out []model.AuditEvent
	for rows.Next() {
		var ev model.AuditEvent
		var metaRaw string
		var createdAt time.Time
		if err := rows.Scan(
			&ev.ID, &ev.Actor, &ev.Action, &ev.ResourceKind, &ev.ResourceID, &ev.Outcome,
			&ev.TenantSlug, &metaRaw, &ev.TraceID, &ev.SpanID, &createdAt,
		); err != nil {
			return nil, err
		}
		ev.CreatedAt = createdAt
		if metaRaw != "" {
			_ = json.Unmarshal([]byte(metaRaw), &ev.Metadata)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
