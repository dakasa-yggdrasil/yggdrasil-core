package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// The body names only the original life and an exact current-frame CAS. Native
// observations, authority, timestamps and health never come from the caller.
func decodeFailedServingGuestDisposalRequest(reader io.Reader) (model.CapacityFailedServingGuestDisposalRequest, error) {
	var out model.CapacityFailedServingGuestDisposalRequest
	d := json.NewDecoder(reader)
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return out, repository.ErrCapacityMutationAuthorization
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return out, repository.ErrCapacityMutationAuthorization
		}
		seen[key] = true
		switch key {
		case "preregistration_id":
			err = d.Decode(&out.PreregistrationID)
		case "policy_id":
			err = d.Decode(&out.PolicyID)
		case "policy_checksum":
			err = d.Decode(&out.PolicyChecksum)
		case "generation":
			err = d.Decode(&out.Generation)
		case "fencing_token":
			err = d.Decode(&out.FencingToken)
		case "intent_sha256":
			err = d.Decode(&out.IntentSHA256)
		default:
			return out, repository.ErrCapacityMutationAuthorization
		}
		if err != nil {
			return out, repository.ErrCapacityMutationAuthorization
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 6 || d.Decode(new(any)) != io.EOF ||
		!dispositionGrantID(out.PreregistrationID) || !dispositionGrantID(out.PolicyID) ||
		!capacity.ValidDigest(out.PolicyChecksum) || !capacity.ValidDigest(out.IntentSHA256) ||
		out.Generation < 1 || out.FencingToken < 1 {
		return out, repository.ErrCapacityMutationAuthorization
	}
	return out, nil
}

// Explicit public projection: the private record also retains candidate data,
// original intent bytes and historical canary/job bodies. None is API output.
func failedServingGuestDisposalSummary(r repository.FailedServingGuestDisposal) map[string]any {
	return map[string]any{
		"schema":                                       r.Schema,
		"id":                                           r.ID,
		"record_id":                                    r.RecordID,
		"stage":                                        r.Stage,
		"preregistration_id":                           r.PreregistrationID,
		"actual_core_source":                           r.ActualCoreSource,
		"original_intent_sha256":                       r.OriginalIntentSHA256,
		"quarantine_intent_sha256":                     r.QuarantineIntentSHA256,
		"terminal_intent_sha256":                       r.TerminalIntentSHA256,
		"installation_sha256":                          r.InstallationSHA256,
		"enrollment_sha256":                            r.EnrollmentSHA256,
		"original_slot_sha256":                         r.OriginalSlotSHA256,
		"quarantine_slot_sha256":                       r.QuarantineSlotSHA256,
		"current_stable_event_sha256":                  r.CurrentStableEventSHA256,
		"native_off_record_id":                         r.NativeOffRecordID,
		"historical_accepted_read_count":               r.HistoricalAcceptedReadCount,
		"historical_promoted_count":                    r.HistoricalPromotedCount,
		"business_effects_preserved":                   r.BusinessEffectsPreserved,
		"Core_or_Guest_native_write_sent":              r.CoreOrGuestNativeWriteSent,
		"Guest_writer_drain_claimed":                   r.GuestWriterDrainClaimed,
		"native_off_observed":                          r.Stage == "quiescent" || r.Stage == "terminal",
		"native_absence_observed":                      r.Stage == "terminal",
		"operator_native_action_ACK_claimed":           false,
		"original_failure_cause_fixed_claimed":         false,
		"historical_zero_useful_capacity_claimed":      false,
		"replacement_requires_new_original_enrollment": true,
	}
}

func (s *Server) handleOpsFailedServingGuestDisposal(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeFailedServingGuestDisposalRequest(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_UUIDs_current_epoch_and_full_intent_CAS_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 35*time.Second)
	defer stop()
	result, err := messagecontroller.RequestFailedServingGuestQuarantine(ctx, s.db, s.brokerConnection(), request, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_serving_quarantine_not_admitted")
		return
	}
	writeJSON(w, http.StatusCreated, failedServingGuestDisposalSummary(result))
}

func (s *Server) handleOpsFailedServingGuestDisposalRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	preID := r.PathValue("preregistrationId")
	if !dispositionGrantID(preID) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 10*time.Second)
	defer stop()
	rows, err := (repository.CapacityStore{DB: s.db}).ReadFailedServingGuestDisposals(ctx, preID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "failed_serving_disposal_not_found")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, failedServingGuestDisposalSummary(row))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleOpsFailedServingGuestNativeOff(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	preID, admissionID, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "admission_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_and_admission_UUIDs_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 35*time.Second)
	defer stop()
	result, err := messagecontroller.ObserveFailedServingGuestNativeOff(ctx, s.db, s.brokerConnection(), preID, admissionID, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_serving_native_off_not_qualified")
		return
	}
	writeJSON(w, http.StatusCreated, failedServingGuestDisposalSummary(result))
}

func (s *Server) handleOpsFailedServingGuestDisposalComplete(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	preID, admissionID, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "admission_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_and_admission_UUIDs_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 35*time.Second)
	defer stop()
	result, err := messagecontroller.CompleteFailedServingGuestAbsence(ctx, s.db, s.brokerConnection(), preID, admissionID, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_serving_native_absence_not_qualified")
		return
	}
	writeJSON(w, http.StatusCreated, failedServingGuestDisposalSummary(result))
}
