package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func presendRetirementRecoverySummary(r repository.FailedInstalledRetirementRecovery) map[string]any {
	requestID := ""
	if r.SuccessorIntent != nil {
		requestID = r.SuccessorIntent.RequestID
	}
	return map[string]any{"schema": r.Schema, "id": r.ID, "stage": r.Stage, "disposal_id": r.DisposalID, "preregistration_id": r.PreregistrationID, "expired_parent_retirement_request_id": r.ParentIntentID, "successor_retirement_request_id": requestID, "old_original_deadline_and_results_unchanged": true, "maximum_successor_operations": 1, "Guest_quiescence_or_native_cleanup_qualified": false}
}

func (s *Server) handleOpsPresendRetirementRecovery(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	pre, parent, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "expired_retirement_request_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_and_expired_retirement_UUIDs_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 15*time.Second)
	defer stop()
	value, err := (repository.CapacityStore{DB: s.db}).RequestFailedInstalledRetirementRecovery(ctx, pre, parent, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "never_sent_retirement_recovery_not_admitted")
		return
	}
	writeJSON(w, http.StatusCreated, presendRetirementRecoverySummary(value))
}

func (s *Server) handleOpsPresendRetirementRecoveryRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	pre := r.PathValue("preregistrationId")
	if !dispositionGrantID(pre) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	rows, err := (repository.CapacityStore{DB: s.db}).ReadFailedInstalledRetirementRecoveries(r.Context(), pre)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "never_sent_retirement_recovery_not_readable")
		return
	}
	values := []map[string]any{}
	for _, v := range rows {
		values = append(values, presendRetirementRecoverySummary(v))
	}
	writeJSON(w, http.StatusOK, values)
}
