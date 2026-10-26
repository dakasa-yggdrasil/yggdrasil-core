package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func decodeFailedInstalledGuestDisposal(r io.Reader) (string, string, error) {
	return decodeFailedInstalledGuestIDs(r, "expected_failed_run_id")
}
func decodeFailedInstalledGuestIDs(r io.Reader, second string) (string, string, error) {
	d := json.NewDecoder(r)
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return "", "", repository.ErrCapacityMutationAuthorization
	}
	values := map[string]string{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "preregistration_id" && key != second) || values[key] != "" {
			return "", "", repository.ErrCapacityMutationAuthorization
		}
		var value string
		if err = d.Decode(&value); err != nil || !dispositionGrantID(value) {
			return "", "", repository.ErrCapacityMutationAuthorization
		}
		values[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return "", "", repository.ErrCapacityMutationAuthorization
	}
	if len(values) != 2 || d.Decode(new(any)) != io.EOF {
		return "", "", repository.ErrCapacityMutationAuthorization
	}
	return values["preregistration_id"], values[second], nil
}

// Public summaries contain no raw workflow result, token, nonce or private
// lifetime credential. They explicitly preserve possible business effects.
func failedInstalledGuestDisposalSummary(r repository.FailedInstalledGuestDisposal) map[string]any {
	return map[string]any{"schema": r.Schema, "retirement_mode": r.RetirementMode, "id": r.ID, "stage": r.Stage, "preregistration_id": r.PreregistrationID, "useful_capacity_before": r.UsefulCapacityBefore, "business_effects_preserved": r.BusinessEffectsPreserved, "retirement_request_id": r.RetirementRequestID, "native_poweroff_sha256": r.NativePoweroffSHA256, "observation_sha256": r.ObservationSHA256, "replacement_requires_different_approved_Guest": r.ReplacementMode == "", "replacement_mode": r.ReplacementMode, "original_failed_issuer_core_source": r.OriginalFailedIssuerCoreSource, "replacement_core_source": r.ReplacementCoreSource, "same_profile_replacement_requires_recorded_Core_and_current_approval": r.ReplacementMode == repository.FailedInstalledCoreReplacementMode, "original_failure_cause_fixed_claimed": false, "original_CREATE_installation_ACK_and_canaries_unchanged": true}
}

func (s *Server) handleOpsFailedInstalledGuestDisposal(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	preID, lastRunID, mode, err := decodeFailedInstalledGuestDisposalRequest(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_UUIDs_and_optional_closed_replacement_mode_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 15*time.Second)
	defer stop()
	store := repository.CapacityStore{DB: s.db}
	var result repository.FailedInstalledGuestDisposal
	if mode == repository.FailedInstalledCoreReplacementMode {
		result, err = store.RequestFailedInstalledGuestCoreReplacement(ctx, preID, lastRunID, issuer)
	} else {
		result, err = store.RequestFailedInstalledGuestDisposal(ctx, preID, lastRunID, issuer)
	}
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_installed_disposal_not_admitted")
		return
	}
	writeJSON(w, http.StatusCreated, failedInstalledGuestDisposalSummary(result))
}

func (s *Server) handleOpsFailedInstalledGuestDisposalRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("preregistrationId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	rows, err := (repository.CapacityStore{DB: s.db}).ReadFailedInstalledGuestDisposal(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "failed_installed_disposal_not_found")
		return
	}
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, failedInstalledGuestDisposalSummary(r))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleOpsFailedInstalledGuestDisposalComplete(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	pre, id, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "admission_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_and_admission_UUIDs_required")
		return
	}
	result, err := messagecontroller.RecordFailedInstalledGuestNativeAbsence(r.Context(), s.db, s.brokerConnection(), pre, id, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_installed_native_absence_not_qualified")
		return
	}
	writeJSON(w, http.StatusCreated, failedInstalledGuestDisposalSummary(result))
}
func (s *Server) handleOpsFailedInstalledGuestDisposalAdvance(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	pre, id, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "admission_id")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_and_admission_UUIDs_required")
		return
	}
	result, err := messagecontroller.AdvanceFailedInstalledGuestNativeCleanup(r.Context(), s.db, s.brokerConnection(), pre, id, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_installed_native_poweroff_not_qualified")
		return
	}
	writeJSON(w, http.StatusCreated, failedInstalledGuestDisposalSummary(result))
}
