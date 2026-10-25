package httpapi

import (
	"net/http"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func enrolledFailedOriginalDispositionSummary(v model.CapacityEnrolledFailedOriginalDisposition) map[string]any {
	return map[string]any{
		"schema":                            v.Schema,
		"original_registration_sha256":      v.OriginalRegistrationSHA256,
		"original_receipt_sha256":           v.OriginalReceiptSHA256,
		"original_enrollment_sha256":        v.OriginalEnrollmentSHA256,
		"original_enrollment_preserved":     v.OriginalEnrollmentPreserved,
		"Guest_quiescence_proved":           v.GuestQuiescenceProved,
		"installation_or_serving_authority": v.InstallationOrServingAuthority, "id": v.ID, "grant_id": v.GrantID, "preregistration_id": v.PreregistrationID,
		"job_id": v.JobID, "run_id": v.RunID, "issuer": v.Issuer, "recorded_at": v.RecordedAt,
		"original_witness_sha256": v.OriginalWitnessSHA256, "observation_sha256": v.ObservationSHA256,
		"original_dispatch_sha256": v.OriginalDispatchSHA256, "original_run_sha256": v.OriginalRunSHA256,
		"closed_generation": v.ClosedGeneration, "closed_fencing_token": v.ClosedFencingToken,
		"historical_core_source_commit":   v.HistoricalCoreSourceCommit,
		"historical_create_source_commit": v.Observation.OriginalAdapterSourceCommit,
		"observer_source_commit":          v.Observation.AdapterSourceCommit,
		"original_accepted_unchanged":     v.OriginalAcceptedUnchanged,
		"original_witness_preserved":      v.OriginalWitnessPreserved,
		"original_unknown_ACK_preserved":  v.OriginalUnknownACKPreserved,
		"historical_writer_start_state":   v.HistoricalWriterStartState,
		"dispatch_state":                  "enrolled_failed_disposed", "original_finalization_ack_present": false,
		"new_assessment_decision_and_single_use_grant_still_required": true,
		"serving_or_business_or_savings_authority":                    false, "provider_mutations": 0,
	}
}

func (s *Server) handleOpsEnrolledFailedOriginalDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	grantID, jobID, err := decodeFailedOriginalDisposition(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_and_job_uuids_required")
		return
	}
	result, err := messagecontroller.RecordEnrolledFailedOriginalDisposition(r.Context(), s.db, s.brokerConnection(), grantID, jobID, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "enrolled_failed_original_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, enrolledFailedOriginalDispositionSummary(result))
}

func (s *Server) handleOpsEnrolledFailedOriginalDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("grantId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_uuid_required")
		return
	}
	result, err := (repository.CapacityStore{DB: s.db}).ReadEnrolledFailedOriginalDisposition(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "enrolled_failed_original_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, enrolledFailedOriginalDispositionSummary(result))
}
