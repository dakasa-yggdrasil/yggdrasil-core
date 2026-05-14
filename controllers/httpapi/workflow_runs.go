package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

var errWorkflowRunUnauthorized = errors.New("workflow run unauthorized")

// handleWorkflowRun routes between sync and async execution. The default
// is sync (HTTP 201 with the full RunWorkflowResponse) for back-compat.
// `?async=true` returns 202 + {run_id, status} immediately and persists
// the run for polling via GET /api/v1/workflow-runs/{id}. Async is the
// only viable path for runs that exceed the ingress 60s timeout (SES
// multi-step bootstrap, large infra provisioning, etc.).
func (s *Server) handleWorkflowRun(w http.ResponseWriter, r *http.Request) {
	if err := authorizeWorkflowRunRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var req model.RunWorkflowRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	if isAsyncWorkflowRunRequest(r) {
		s.dispatchAsyncWorkflowRun(w, r, req)
		return
	}

	response, err := messagecontroller.RunWorkflow(r.Context(), s.rabbitmq, s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Emit workflow.run.completed even when the run aborted on a failed
	// step — the AMQP-path handler did this from day one, but the HTTP
	// path silently skipped it, which is why event-triggered workflows
	// (alert-on-reconcile-failure) never fired for runs dispatched via
	// curl + console UI.
	messagecontroller.EmitWorkflowRunCompletedEvent(r.Context(), s.db, s.logger, response)
	writeJSON(w, http.StatusCreated, response)
}

// dispatchAsyncWorkflowRun persists a pending row, returns 202 with the
// run_id, and kicks off a background goroutine that runs the workflow.
// On completion (success or failure) the goroutine updates the same row
// so a subsequent GET can return the full RunWorkflowResponse.
func (s *Server) dispatchAsyncWorkflowRun(w http.ResponseWriter, r *http.Request, req model.RunWorkflowRequest) {
	runID := uuid.New()
	if err := repository.InsertWorkflowRun(r.Context(), s.db, runID, req.Workflow, req.Inputs, req.Metadata); err != nil {
		writeMappedError(w, err)
		return
	}

	go func(req model.RunWorkflowRequest, runID uuid.UUID) {
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, s.db, runID, startedAt)

		response, runErr := messagecontroller.RunWorkflow(bg, s.rabbitmq, s.db, req)

		status := "succeeded"
		errMsg := ""
		var resultPayload any
		if runErr != nil {
			status = "failed"
			errMsg = runErr.Error()
		} else {
			resultPayload = response
			if strings.EqualFold(response.Status, "failed") {
				status = "failed"
				if response.Metadata != nil {
					if v, ok := response.Metadata["failed_step"].(string); ok && v != "" {
						errMsg = "step " + v + " failed"
					}
				}
			}
			// Emit workflow.run.completed for async HTTP-dispatched runs so
			// downstream event-triggered workflows fire (parity with AMQP).
			// Only emit when RunWorkflow returned a typed response — runErr
			// already captures the precondition-failed case.
			messagecontroller.EmitWorkflowRunCompletedEvent(bg, s.db, s.logger, response)
		}
		_ = repository.FinalizeWorkflowRun(bg, s.db, runID, status, resultPayload, errMsg, time.Now().UTC())
	}(req, runID)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":   runID.String(),
		"status":   "pending",
		"workflow": req.Workflow,
	})
}

// handleWorkflowRunGet exposes the persisted record for a previous async
// run. Returns 404 when the id is unknown so pollers can distinguish a
// transient error from a missing run.
func (s *Server) handleWorkflowRunGet(w http.ResponseWriter, r *http.Request) {
	if err := authorizeWorkflowRunRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	idStr := r.PathValue("run_id")
	id, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid run_id"})
		return
	}

	rec, err := repository.GetWorkflowRun(r.Context(), s.db, id)
	if errors.Is(err, repository.ErrWorkflowRunNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "workflow run not found"})
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func isAsyncWorkflowRunRequest(r *http.Request) bool {
	if v := strings.TrimSpace(r.URL.Query().Get("async")); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes":
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Yggdrasil-Workflow-Mode")), "async") {
		return true
	}
	return false
}

func authorizeWorkflowRunRequest(r *http.Request) error {
	expected := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN"))
	if expected == "" {
		return nil
	}

	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Workflow-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	for _, candidate := range candidates {
		if candidate != "" && candidate == expected {
			return nil
		}
	}
	return errWorkflowRunUnauthorized
}

func bearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}
