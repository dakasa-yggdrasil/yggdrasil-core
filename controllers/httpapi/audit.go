package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"time"

	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// handleAuditList queries audit events with filters.
//
//	GET /api/v1/audit?actor=&action=&resource_kind=&resource_id=&tenant=&since=&until=&limit=
//
// Filters are AND-combined. `since` / `until` accept RFC3339 (default: open
// interval). `limit` defaults to 100, capped at 1000. No auth in v2.9.0;
// adopters expose behind their ingress policy. v3 adds RBAC scope.
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	filter := model.ListAuditEventsFilter{
		Actor:        queryString(r, "actor"),
		Action:       queryString(r, "action"),
		ResourceKind: queryString(r, "resource_kind"),
		ResourceID:   queryString(r, "resource_id"),
		TenantSlug:   queryString(r, "tenant"),
	}
	if v := queryString(r, "since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := queryString(r, "until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}
	if v := queryString(r, "limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}

	events, err := repository.ListAuditEvents(r.Context(), s.db, filter)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if events == nil {
		events = []model.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// recordAudit is a fire-and-forget convenience for handlers. Failures are
// logged via s.logger but do not propagate: audit is observability, never
// gate the user request.
//
// The row is built on the caller's goroutine from the request, then inserted
// on a detached goroutine with context.Background() and a 5-second timeout,
// NOT r.Context(): the inbound request context cancels as soon as the
// handler returns, which races the goroutine and silently drops audit rows.
// The audit insert must outlive the handler.
func (s *Server) recordAudit(r *http.Request, action, kind, resourceID, outcome string, metadata map[string]any) {
	event := requestAuditEvent(r, action, kind, resourceID, outcome, metadata)
	safego.SafeGo("audit_emit", func() {
		_ = s.recordAuditSync(event)
	})
}

// requestAuditEvent builds the audit row for one handler outcome. The actor
// comes from the request headers through actorFromRequest and the trace
// reference only from a well-formed W3C traceparent (requestTraceIDs); no
// caller-controlled header reaches the row raw, because a value the
// audit_events columns cannot hold would make the database reject the whole
// row.
func requestAuditEvent(r *http.Request, action, kind, resourceID, outcome string, metadata map[string]any) model.AuditEvent {
	traceID, spanID := requestTraceIDs(r)
	return model.AuditEvent{
		Actor:        actorFromRequest(r),
		Action:       action,
		ResourceKind: kind,
		ResourceID:   resourceID,
		Outcome:      outcome,
		TraceID:      traceID,
		SpanID:       spanID,
		Metadata:     metadata,
	}
}

// recordAuditSync is the synchronous insert behind recordAudit, shared with
// the tests that assert the row landed instead of polling the goroutine.
func (s *Server) recordAuditSync(event model.AuditEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := repository.RecordAuditEvent(ctx, s.db, event)
	if err != nil && s.logger != nil {
		s.logger.Sugar().Warnw("audit insert failed",
			"action", event.Action,
			"resource", event.ResourceKind+"/"+event.ResourceID,
			"error", err.Error(),
		)
	}
	return err
}

// auditActorHeader lets a caller declare the actor an audit row is attributed
// to, in the vocabulary model.AuditEvent documents: "user:<id>" or
// "service:<name>". The value is stored as sent, so it is accepted only when
// it has that shape and fits audit_events.actor (VARCHAR(255), migration
// 00017); anything else is dropped and the actor is derived from the
// credential instead. Stored raw, a header wider than the column made
// Postgres reject the whole row, which erased the audit line of the very
// manifest write or template instantiation being recorded.
const (
	auditActorHeader = "X-Yggdrasil-Actor"
	auditActorMaxLen = 255
)

var auditActorPattern = regexp.MustCompile(`^(user|service):[A-Za-z0-9._:@/-]+$`)

func actorFromRequest(r *http.Request) string {
	if v := declaredAuditActor(r.Header.Get(auditActorHeader)); v != "" {
		return v
	}
	if tok := bearerToken(r.Header.Get("Authorization")); tok != "" {
		return "service:bearer-token"
	}
	return "anonymous"
}

// declaredAuditActor returns the header value when it is an actor the row can
// hold, or an empty string when it is absent, too wide for the column, or
// outside the documented "user:<id>" / "service:<name>" shape. The pattern is
// ASCII only, so the byte length it checks is the character length Postgres
// measures.
func declaredAuditActor(v string) string {
	if v == "" || len(v) > auditActorMaxLen || !auditActorPattern.MatchString(v) {
		return ""
	}
	return v
}
