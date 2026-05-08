package httpapi

import (
	"net/http"
	"strconv"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func (s *Server) handleOpsWorkflowsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := model.ListOpsWorkflowsFilter{
		Status:      q["status"],
		Integration: q.Get("integration"),
		Search:      q.Get("search"),
		Cursor:      q.Get("cursor"),
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			filter.Limit = n
		}
	}
	out, err := repository.ListOpsWorkflowRuns(r.Context(), s.db, filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
