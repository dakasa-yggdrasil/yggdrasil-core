package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Task 6 — GET /api/v1/ops/workflows/:runId
// -----------------------------------------------------------------------------

type opsWorkflowRunDetail struct {
	RunID         string         `json:"run_id"`
	WorkflowName  string         `json:"workflow_name"`
	Integration   string         `json:"integration"`
	Status        string         `json:"status"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	FinishedAt    *time.Time     `json:"finished_at,omitempty"`
	TriggerSource string         `json:"trigger_source"`
	Error         string         `json:"error,omitempty"`
	Inputs        map[string]any `json:"inputs,omitempty"`
	Outputs       map[string]any `json:"outputs,omitempty"`
	Steps         []any          `json:"steps"`
}

func (s *Server) handleOpsWorkflowDetail(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("runId")
	if runID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing runId")
		return
	}
	// runId is the workflow_runs.id UUID. Reject non-UUID early so we
	// return a friendly 400 instead of leaking the pq cast error as 500.
	if _, err := uuid.Parse(runID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "runId must be a uuid")
		return
	}

	// Column names match the workflow_runs schema (00018_workflow_runs.sql):
	// the row id is `id` (not run_id), integration/trigger_source live in
	// `metadata` JSON, the result blob is `result` (not outputs), and
	// `steps` is not a stored column (intermediate progress lives in metadata
	// for the few workflows that report it). Integration + source use the
	// same multi-key COALESCE chain as the list endpoint — see
	// repository.ListOpsWorkflowRuns for the rationale (writers stamp
	// `triggered_by`, not `source`/`integration`).
	const q = `
		SELECT id::text, COALESCE(workflow_name, ''),
		       COALESCE(
		           NULLIF(metadata->>'integration', ''),
		           split_part(COALESCE(workflow_name, ''), '-', 1),
		           ''
		       ),
		       status, started_at, finished_at,
		       COALESCE(
		           NULLIF(metadata->>'source', ''),
		           NULLIF(metadata->>'trigger_source', ''),
		           NULLIF(metadata->>'triggered_by', ''),
		           'unknown'
		       ),
		       COALESCE(error, ''),
		       COALESCE(inputs::text, '{}'),
		       COALESCE(result::text, '{}'),
		       COALESCE((metadata->'steps')::text, '[]')
		FROM public.workflow_runs WHERE id = $1`

	var (
		d               opsWorkflowRunDetail
		inputs, outputs string
		steps           string
	)
	err := s.db.QueryRowContext(r.Context(), q, runID).Scan(
		&d.RunID, &d.WorkflowName, &d.Integration, &d.Status,
		&d.StartedAt, &d.FinishedAt, &d.TriggerSource, &d.Error,
		&inputs, &outputs, &steps,
	)
	if err == sql.ErrNoRows {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = json.Unmarshal([]byte(inputs), &d.Inputs)
	_ = json.Unmarshal([]byte(outputs), &d.Outputs)
	_ = json.Unmarshal([]byte(steps), &d.Steps)
	if d.Steps == nil {
		d.Steps = []any{}
	}
	writeJSON(w, http.StatusOK, d)
}

// -----------------------------------------------------------------------------
// Task 7 — POST retry / abort / replay
// -----------------------------------------------------------------------------
//
// Phase 1+2 surface the action endpoints; the actual dispatch (re-enqueue
// to Temporal/AMQP) is wired by integration-yggdrasil-self.dispatch_workflow_run
// in subsequent phases. For now, these handlers validate the run exists,
// mark intent, and return a synthetic new_run_id for the audit trail.

type retryRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (s *Server) handleOpsWorkflowRetry(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("runId")
	if runID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing runId")
		return
	}
	var req retryRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if !s.workflowRunExists(r.Context(), runID) {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return
	}
	newRunID := "retry_" + uuid.NewString()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"new_run_id": newRunID,
		"source":     runID,
		"reason":     req.Reason,
	})
}

func (s *Server) handleOpsWorkflowAbort(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("runId")
	if runID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing runId")
		return
	}
	if !s.workflowRunExists(r.Context(), runID) {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return
	}
	// best-effort status flip — actual cancellation handled by the engine.
	// workflow_runs.status CHECK only allows pending|running|succeeded|failed|
	// cancelled (see 00018_workflow_runs.sql); use 'cancelled' here and let
	// the ops surface display "aborted" via toOpsWorkflowStatus.
	_, _ = s.db.ExecContext(r.Context(),
		`UPDATE public.workflow_runs SET status='cancelled', finished_at=NOW()
		 WHERE id=$1 AND status IN ('pending','running')`, runID)
	writeJSON(w, http.StatusAccepted, map[string]string{"run_id": runID, "status": "aborted"})
}

type replayRequest struct {
	Inputs map[string]any `json:"inputs,omitempty"`
}

func (s *Server) handleOpsWorkflowReplay(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("runId")
	if runID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing runId")
		return
	}
	var req replayRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !s.workflowRunExists(r.Context(), runID) {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return
	}
	newRunID := "replay_" + uuid.NewString()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"new_run_id": newRunID,
		"source":     runID,
		"inputs":     req.Inputs,
	})
}

func (s *Server) workflowRunExists(ctx context.Context, runID string) bool {
	if _, err := uuid.Parse(runID); err != nil {
		return false
	}
	var exists bool
	_ = s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM public.workflow_runs WHERE id=$1)`,
		runID).Scan(&exists)
	return exists
}

// -----------------------------------------------------------------------------
// Task 8 — Approvals
// -----------------------------------------------------------------------------
// approvals_queue table will be wired by Phase 4 when actions begin to enqueue.
// For now, we return empty list + 404 on decide actions.

type opsApproval struct {
	ID            string         `json:"id"`
	WorkflowRunID string         `json:"workflow_run_id"`
	Step          string         `json:"step"`
	Reason        string         `json:"reason,omitempty"`
	RequestedBy   string         `json:"requested_by,omitempty"`
	RequestedAt   time.Time      `json:"requested_at"`
	Diff          map[string]any `json:"diff,omitempty"`
}

func (s *Server) handleOpsApprovalsList(w http.ResponseWriter, r *http.Request) {
	// Source: guardian_approvals table exists in some clusters; query
	// safely with try/empty fallback.
	const q = `
		SELECT id::text,
		       COALESCE(workflow_run_id::text, ''),
		       COALESCE(step, ''),
		       COALESCE(reason, ''),
		       COALESCE(requested_by, ''),
		       requested_at,
		       COALESCE(diff::text, '{}')
		FROM public.guardian_approvals
		WHERE status = 'pending'
		ORDER BY requested_at DESC
		LIMIT 200`
	out := []opsApproval{}
	rows, err := s.db.QueryContext(r.Context(), q)
	if err != nil {
		// table missing is fine — empty list
		writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a opsApproval
		var diffJSON string
		if err := rows.Scan(&a.ID, &a.WorkflowRunID, &a.Step, &a.Reason,
			&a.RequestedBy, &a.RequestedAt, &diffJSON); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(diffJSON), &a.Diff)
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (s *Server) handleOpsApprovalDecide(decision string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing id")
			return
		}
		result, err := s.db.ExecContext(r.Context(),
			`UPDATE public.guardian_approvals
			 SET status=$2, decided_at=NOW()
			 WHERE id=$1 AND status='pending'`, id, decision)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		rows, err := result.RowsAffected()
		if err != nil {
			writeMappedError(w, err)
			return
		}
		if rows != 1 {
			writeProblemJSON(w, http.StatusNotFound, "approval.not_found",
				"The pending approval does not exist or was already decided.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": decision})
	}
}

// -----------------------------------------------------------------------------
// Task 9 — Drift
// -----------------------------------------------------------------------------

type opsDriftObject struct {
	ID              string         `json:"id"`
	ResourceKind    string         `json:"resource_kind"`
	Name            string         `json:"name"`
	Integration     string         `json:"integration"`
	Severity        string         `json:"severity,omitempty"`
	LastReconcileAt *time.Time     `json:"last_reconcile_at,omitempty"`
	Diff            map[string]any `json:"diff,omitempty"`
}

func (s *Server) handleOpsDriftList(w http.ResponseWriter, r *http.Request) {
	out := []opsDriftObject{}
	const q = `
		SELECT 'collab:'||id::text,
		       'collaborator_provider_state',
		       provider||':'||collaborator_id::text,
		       provider,
		       'warn',
		       last_drift_detected_at,
		       COALESCE(drift_summary::text, '{}')
		FROM public.collaborator_provider_state
		WHERE last_drift_detected_at IS NOT NULL
		ORDER BY last_drift_detected_at DESC
		LIMIT 200`
	rows, err := s.db.QueryContext(r.Context(), q)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"drift": out})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var d opsDriftObject
		var diffJSON string
		if err := rows.Scan(&d.ID, &d.ResourceKind, &d.Name, &d.Integration,
			&d.Severity, &d.LastReconcileAt, &diffJSON); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(diffJSON), &d.Diff)
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift": out})
}

func (s *Server) handleOpsDriftReconcile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing id")
		return
	}
	// best-effort: drop the drift marker so the next reconcile loop picks
	// up clean. Actual reconcile is dispatched by the integration adapter.
	if strings.HasPrefix(id, "collab:") {
		uid := strings.TrimPrefix(id, "collab:")
		_, _ = s.db.ExecContext(r.Context(),
			`UPDATE public.collaborator_provider_state
			 SET last_drift_detected_at = NULL
			 WHERE id = $1`, uid)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": "reconcile_dispatched"})
}

// -----------------------------------------------------------------------------
// Task 10 — Catalog
// -----------------------------------------------------------------------------

func (s *Server) handleOpsCatalog(w http.ResponseWriter, r *http.Request) {
	cat := map[string]any{
		"adapters":     s.catalogAdapters(r.Context()),
		"capabilities": s.catalogCapabilities(r.Context()),
		"workflows":    s.catalogWorkflows(r.Context()),
		"types":        []any{},
		"templates":    []any{},
	}
	writeJSON(w, http.StatusOK, cat)
}

func (s *Server) catalogAdapters(ctx context.Context) []map[string]any {
	const q = `
		SELECT name, COALESCE(version, ''), COALESCE(domain, ''),
		       COALESCE(section, ''), COALESCE(entry, '')
		FROM public.integration_catalog_entries
		ORDER BY domain, section, entry, name
		LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var n, v, d, sec, e string
		if err := rows.Scan(&n, &v, &d, &sec, &e); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"name": n, "version": v, "domain": d, "section": sec, "entry": e,
		})
	}
	return out
}

func (s *Server) catalogCapabilities(ctx context.Context) []map[string]any {
	const q = `
		SELECT capability_name, COALESCE(integration, ''), COALESCE(version, '')
		FROM public.capabilities_catalog
		ORDER BY integration, capability_name LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var n, ig, v string
		if err := rows.Scan(&n, &ig, &v); err != nil {
			continue
		}
		out = append(out, map[string]any{"capability": n, "integration": ig, "version": v})
	}
	return out
}

func (s *Server) catalogWorkflows(ctx context.Context) []map[string]any {
	const q = `
		SELECT name, namespace, COALESCE(description, '')
		FROM public.workflow_manifests
		ORDER BY namespace, name LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var n, ns, d string
		if err := rows.Scan(&n, &ns, &d); err != nil {
			continue
		}
		out = append(out, map[string]any{"name": n, "namespace": ns, "description": d})
	}
	return out
}

// -----------------------------------------------------------------------------
// Task 11 — System health
// -----------------------------------------------------------------------------

func (s *Server) handleOpsSystemHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"db":         dbStatus(r.Context(), s.db),
		"queues":     []any{},
		"outbox":     opsOutboxLag(r.Context(), s.db),
		"reconcile":  map[string]any{"loops": 0, "last_run_at": nil},
		"secrets":    map[string]any{"sync_state": "unknown"},
		"migrations": opsMigrationStatus(r.Context(), s.db),
		"checked_at": time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func dbStatus(ctx context.Context, db *sql.DB) map[string]any {
	if err := db.PingContext(ctx); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}

func opsOutboxLag(ctx context.Context, db *sql.DB) map[string]any {
	var lagSeconds *float64
	_ = db.QueryRowContext(ctx,
		`SELECT EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))
		 FROM public.outbox WHERE published_at IS NULL`).Scan(&lagSeconds)
	if lagSeconds == nil {
		return map[string]any{"pending_count": 0, "lag_seconds": 0}
	}
	var pending int64
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM public.outbox WHERE published_at IS NULL`).Scan(&pending)
	return map[string]any{"pending_count": pending, "lag_seconds": *lagSeconds}
}

func opsMigrationStatus(ctx context.Context, db *sql.DB) map[string]any {
	var version int64
	_ = db.QueryRowContext(ctx,
		`SELECT MAX(version_id) FROM public.goose_db_version WHERE is_applied = true`).Scan(&version)
	return map[string]any{"applied_version": version}
}

// -----------------------------------------------------------------------------
// Task 12 — Audit (rich filter)
// -----------------------------------------------------------------------------

func (s *Server) handleOpsAuditList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.ListOpsAuditEventsFilter{
		Actor:         q.Get("actor"),
		ActionPrefix:  q.Get("action_prefix"),
		TargetKind:    q.Get("target_kind"),
		TargetID:      q.Get("target_id"),
		ResultStatus:  q.Get("result_status"),
		CorrelationID: q.Get("correlation_id"),
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			f.Limit = n
		}
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			f.Since = t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			f.Until = t
		}
	}
	rows, err := repository.ListOpsAuditEvents(r.Context(), s.db, f)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": rows, "count": len(rows)})
}

// -----------------------------------------------------------------------------
// GET /api/v1/ops/collaborators/missing-mfa
// -----------------------------------------------------------------------------

type opsCollaboratorMissingMFA struct {
	ID           string     `json:"id"`
	Slug         string     `json:"slug,omitempty"`
	DisplayName  string     `json:"display_name,omitempty"`
	PrimaryEmail string     `json:"primary_email,omitempty"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// handleOpsCollaboratorsMissingMFA returns active collaborators whose
// auth_identities row either does not exist yet (never logged in) or has
// mfa_enrolled_at NULL. Backs the surface-console "Compliance > MFA"
// panel; ops uses it to nudge users into completing enrollment.
func (s *Server) handleOpsCollaboratorsMissingMFA(w http.ResponseWriter, r *http.Request) {
	const q = `
		SELECT c.id::text,
		       COALESCE(c.slug, ''),
		       COALESCE(c.display_name, ''),
		       COALESCE(c.primary_email, ''),
		       c.status,
		       c.created_at,
		       ai.last_login_at
		FROM public.collaborators c
		LEFT JOIN public.auth_identities ai ON ai.collaborator_id = c.id
		WHERE c.status = 'active'
		  AND (ai.collaborator_id IS NULL OR ai.mfa_enrolled_at IS NULL)
		ORDER BY c.created_at DESC
		LIMIT 500`
	rows, err := s.db.QueryContext(r.Context(), q)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := []opsCollaboratorMissingMFA{}
	for rows.Next() {
		var c opsCollaboratorMissingMFA
		if err := rows.Scan(&c.ID, &c.Slug, &c.DisplayName, &c.PrimaryEmail, &c.Status, &c.CreatedAt, &c.LastLoginAt); err != nil {
			continue
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborators": out, "count": len(out)})
}
