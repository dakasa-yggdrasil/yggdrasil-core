package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// A cleanup is an explicit, separately admitted failed-expansion operation.
// It never changes the accounting/read-only original-create-dispositions API.
func witnessedUnenrolledExpansionCleanupSummary(r repository.WitnessedUnenrolledExpansionCleanup, events []repository.WitnessedUnenrolledExpansionCleanupEvent) map[string]any {
	stage := "admission"
	if len(events) != 0 {
		stage = events[len(events)-1].Stage
	}
	return map[string]any{
		"schema": r.Schema, "id": r.ID, "grant_id": r.GrantID, "child_grant_id": r.ChildGrantID,
		"job_id": r.JobID, "run_id": r.RunID, "preregistration_id": r.PreregistrationID,
		"stage": stage, "event_count": len(events), "slot": r.Slot,
		"resource_id": r.ResourceID, "resource_created_at": r.ResourceCreatedAt,
		"original_auxiliary_inventory_complete": r.OriginalAuxiliaryKnown,
		"original_SDK_return_sha256":            r.OriginalSDKReturnSHA256,
		"original_guest_success":                false, "clean_cycle_credit": false,
		"serving_or_business_or_savings_authority": false,
	}
}

func (s *Server) handleOpsWitnessedUnenrolledExpansionCleanup(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	grant, job, err := decodeFailedOriginalDisposition(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_and_failed_UNKNOWN_job_UUIDs_required")
		return
	}
	store := repository.CapacityStore{DB: s.db}
	result, err := store.RequestWitnessedUnenrolledExpansionCleanup(r.Context(), grant, job, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "witnessed_unenrolled_expansion_cleanup_not_admitted")
		return
	}
	_, events, err := store.ReadWitnessedUnenrolledExpansionCleanup(r.Context(), grant)
	if err != nil {
		// An admitted record survives an uncertain HTTP result. GET by original
		// grant is the only reconciliation; repeating POST is not authority.
		writeJSONError(w, http.StatusConflict, "cleanup_admission_committed_exact_GET_required")
		return
	}
	writeJSON(w, http.StatusCreated, witnessedUnenrolledExpansionCleanupSummary(result, events))
}

func (s *Server) handleOpsWitnessedUnenrolledExpansionCleanupRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("grantId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_UUID_required")
		return
	}
	result, events, err := (repository.CapacityStore{DB: s.db}).ReadWitnessedUnenrolledExpansionCleanup(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "witnessed_unenrolled_expansion_cleanup_not_found")
		return
	}
	writeJSON(w, http.StatusOK, witnessedUnenrolledExpansionCleanupSummary(result, events))
}
