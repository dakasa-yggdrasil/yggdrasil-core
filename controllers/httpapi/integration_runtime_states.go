package httpapi

import (
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// handleIntegrationRuntimeStateList exposes the observed runtime checks
// (describe_handshake, transport_connectivity) stored for integration
// instances so operators can see the exact live-vs-stored diff that
// marked an instance unhealthy — without needing DB access or core logs.
//
// Query params:
//
//	namespace  — optional, filters by integration_instance namespace
//	name       — optional, filters by integration_instance name
//	check_kind — optional, e.g. "describe_handshake"
//	status     — optional, e.g. "contract_mismatch"
func (s *Server) handleIntegrationRuntimeStateList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := model.ListIntegrationRuntimeStatesRequest{
		Namespace: strings.TrimSpace(q.Get("namespace")),
		Name:      strings.TrimSpace(q.Get("name")),
		Status:    strings.TrimSpace(q.Get("status")),
		CheckKind: strings.TrimSpace(q.Get("check_kind")),
	}

	states, err := repository.ListIntegrationRuntimeStates(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime_states": states,
	})
}
