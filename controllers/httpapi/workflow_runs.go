package httpapi

import (
	"errors"
	"net/http"
	"os"
	"strings"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var errWorkflowRunUnauthorized = errors.New("workflow run unauthorized")

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

	response, err := messagecontroller.RunWorkflow(r.Context(), s.rabbitmq, s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, response)
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
