package httpapi

import (
	"net/http"
	"strconv"
	"time"

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
// logged via s.logger but do not propagate — audit is observability, never
// gate the user request.
func (s *Server) recordAudit(r *http.Request, action, kind, resourceID, outcome string, metadata map[string]any) {
	actor := actorFromRequest(r)
	go func() {
		if err := repository.RecordAuditEvent(r.Context(), s.db, model.AuditEvent{
			Actor:        actor,
			Action:       action,
			ResourceKind: kind,
			ResourceID:   resourceID,
			Outcome:      outcome,
			TraceID:      r.Header.Get("traceparent"),
			Metadata:     metadata,
		}); err != nil && s.logger != nil {
			s.logger.Sugar().Warnw("audit insert failed",
				"action", action,
				"resource", kind+"/"+resourceID,
				"error", err.Error(),
			)
		}
	}()
}

func actorFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-Yggdrasil-Actor"); v != "" {
		return v
	}
	if tok := bearerToken(r.Header.Get("Authorization")); tok != "" {
		return "service:bearer-token"
	}
	return "anonymous"
}
