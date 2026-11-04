package httpapi

import (
	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
)

func nativeDeniedDispositionSummary(v model.CapacityNativeDeniedDisposition) map[string]any {
	summary := map[string]any{"schema": v.Schema, "id": v.ID, "grant_id": v.GrantID, "preregistration_id": v.PreregistrationID, "job_id": v.JobID, "run_id": v.RunID, "issuer": v.Issuer, "recorded_at": v.RecordedAt, "observation_sha256": v.ObservationSHA256, "closed_generation": v.ClosedGeneration, "closed_fencing_token": v.ClosedFencingToken, "historical_core_source_commit": v.HistoricalCoreSourceCommit, "historical_create_source_commit": v.Observation.Request.OriginalAdapterSourceCommit, "observer_source_commit": v.Observation.AdapterSourceCommit, "decision": v.Observation.Decision, "event_id": v.Observation.EventID, "request_id": v.Observation.RequestID, "original_uncertain_and_NULL_identities_unchanged": v.OriginalUncertainAndNullIdentitiesUnchanged, "original_unknown_ACK_preserved": v.OriginalUnknownACKPreserved, "witness_enrollment_installation_absent": v.WitnessEnrollmentInstallationAbsent, "original_HTTP_response_available": false, "dispatch_state": "native_denied_disposed", "original_finalization_ack_present": false, "new_assessment_decision_and_single_use_grant_still_required": true, "serving_or_business_or_savings_authority": false, "provider_mutations": 0}
	if v.Schema == model.NativeDeniedReturnedACKDispositionSchema {
		summary["original_finalization_ack_present"] = v.OriginalFinalizationACKAt != nil
		summary["original_dispatch_state"] = v.OriginalDispatchState
		summary["original_finalization_ack_at"] = v.OriginalFinalizationACKAt
		summary["original_failed_workflow_ACK_preserved"] = v.OriginalFailedWorkflowACKPreserved
	}
	return summary
}
func (s *Server) handleOpsNativeDeniedDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	grant, job, err := decodeFailedOriginalDisposition(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_and_job_uuids_required")
		return
	}
	v, err := messagecontroller.RecordNativeDeniedDisposition(r.Context(), s.db, s.brokerConnection(), grant, job, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "native_authorization_denied_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, nativeDeniedDispositionSummary(v))
}
func (s *Server) handleOpsNativeDeniedDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("grantId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_uuid_required")
		return
	}
	v, err := (repository.CapacityStore{DB: s.db}).ReadNativeDeniedDisposition(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "native_authorization_denied_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, nativeDeniedDispositionSummary(v))
}
