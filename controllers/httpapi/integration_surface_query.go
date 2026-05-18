package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type surfaceQueryReqBody struct {
	QueryName string         `json:"query_name"`
	Params    map[string]any `json:"params,omitempty"`
}

func (s *Server) handleIntegrationSurfaceQuery() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.surfaceQueryDispatcher == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "surface query dispatcher not configured")
			return
		}
		instanceID := strings.TrimSpace(r.PathValue("instance_id"))
		if instanceID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing instance_id")
			return
		}
		var body surfaceQueryReqBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
			return
		}
		if strings.TrimSpace(body.QueryName) == "" {
			writeJSONError(w, http.StatusBadRequest, "query_name required")
			return
		}
		req := model.ExecuteIntegrationRequest{
			Integration: model.ManifestSelector{ManifestID: instanceID},
			Operation:   model.OperationOnSurfaceQuery,
			Capability:  model.OperationOnSurfaceQuery,
			Input: map[string]any{
				"query_name": body.QueryName,
				"params":     body.Params,
			},
		}
		resp, err := s.surfaceQueryDispatcher.Execute(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":   "adapter_dispatch_failed",
				"message": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
