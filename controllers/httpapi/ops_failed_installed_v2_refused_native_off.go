package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// decodeFailedInstalledV2RefusedNativeOff accepts exactly the closed body
// {preregistration_id, admission_id, retirement_request_id}: three distinct
// canonical non-nil UUIDs, no other key, no duplicate, no trailing value.
func decodeFailedInstalledV2RefusedNativeOff(r io.Reader) (string, string, string, error) {
	d := json.NewDecoder(r)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	values := map[string]string{}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		if e != nil || !ok || (key != "preregistration_id" && key != "admission_id" && key != "retirement_request_id") {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		if _, exists := values[key]; exists {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		var value *string
		if e = d.Decode(&value); e != nil || value == nil || !dispositionGrantID(*value) {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		values[key] = *value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(values) != 3 || d.Decode(new(any)) != io.EOF {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	pre, admission, retirement := values["preregistration_id"], values["admission_id"], values["retirement_request_id"]
	if pre == admission || pre == retirement || admission == retirement {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	return pre, admission, retirement, nil
}

// The public summary carries ids, stages and hashes only. It never states
// that the Guest quiesced its writers, that the poweroff command returned or
// that the original caller succeeded.
func failedInstalledV2RefusedNativeOffSummary(v repository.FailedInstalledV2RefusedNativeOff) map[string]any {
	return map[string]any{"schema": v.Schema, "id": v.ID, "stage": v.Stage, "disposal_id": v.DisposalID, "preregistration_id": v.PreregistrationID, "retirement_request_id": v.RetirementRequestID, "native_read_id": v.NativeReadID, "native_off_sha256": v.NativeOffSHA256, "original_caller_status": v.Evidence.CallerStatus, "proof_kind": "V2_nonce_and_possible_start_then_closed_caller_refusal_and_native_OFF", "Guest_writer_quiescence_claimed": false, "original_poweroff_command_returned_or_caller200_claimed": false, "new_Guest_request_or_poweroff_or_delete_sent": false, "business_effects_preserved": true, "maximum_read_attempts": repository.V2RefusedNativeOffMaximumReads, "quiescent_qualified": v.Stage == "qualified"}
}

func (s *Server) handleOpsFailedInstalledV2RefusedNativeOff(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	pre, admission, retirement, err := decodeFailedInstalledV2RefusedNativeOff(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_admission_and_retirement_UUIDs_required")
		return
	}
	lineage, disposal, err := messagecontroller.QuiesceFailedInstalledV2RefusedNativeOff(r.Context(), s.db, s.brokerConnection(), pre, admission, retirement, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_installed_v2_refused_native_off_not_qualified")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"schema": "failed_installed_v2_refused_native_off_result_v1", "lineage": failedInstalledV2RefusedNativeOffSummary(lineage), "disposal": failedInstalledGuestDisposalSummary(disposal)})
}

func (s *Server) handleOpsFailedInstalledV2RefusedNativeOffRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	pre := r.PathValue("preregistrationId")
	if !dispositionGrantID(pre) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	store := repository.CapacityStore{DB: s.db}
	rows, err := store.ReadFailedInstalledV2RefusedNativeOff(r.Context(), pre)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_installed_v2_refused_native_off_not_readable")
		return
	}
	values := []map[string]any{}
	for _, v := range rows {
		row := failedInstalledV2RefusedNativeOffSummary(v)
		challenges, returns, e := store.ReadFailedInstalledV2RefusedNativeOffReads(r.Context(), v.RetirementRequestID)
		if e != nil {
			writeJSONError(w, http.StatusConflict, "failed_installed_v2_refused_native_off_reads_not_readable")
			return
		}
		row["native_read_challenges"] = challenges
		row["native_read_returns"] = returns
		values = append(values, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": "failed_installed_v2_refused_native_off_public_ledger_v1", "preregistration_id": pre, "rows": values, "GET_only_no_native_call": true})
}
