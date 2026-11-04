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

func partialNativeOffSummary(v repository.FailedInstalledPartialNativeOff) map[string]any {
	return map[string]any{"schema": v.Schema, "id": v.ID, "stage": v.Stage, "disposal_id": v.DisposalID, "preregistration_id": v.PreregistrationID, "retirement_request_id": v.RetirementRequestID, "native_read_id": v.NativeReadID, "native_off_sha256": v.NativeOffSHA256, "proof_kind": "three_authenticated_Guest_records_and_separate_native_OFF", "original_failed_caller409_preserved": true, "original_command_returned4_or_caller200_claimed": false, "new_Guest_request_or_poweroff_or_delete_sent": false, "business_effects_preserved": true, "maximum_read_attempts": repository.PartialNativeOffMaximumReads, "quiescent_qualified": v.Stage == "qualified"}
}
func (s *Server) handleOpsPartialNativeOffReconciliation(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	pre, ret, err := decodeFailedInstalledGuestIDs(http.MaxBytesReader(w, r.Body, 4096), "retirement_request_id")
	if err != nil {
		writeJSONError(w, 400, "only_original_preregistration_and_retirement_UUIDs_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 15*time.Second)
	defer stop()
	v, err := (repository.CapacityStore{DB: s.db}).RequestFailedInstalledPartialNativeOff(ctx, pre, ret, issuer)
	if err != nil {
		writeJSONError(w, 409, "partial_native_off_reconciliation_not_admitted")
		return
	}
	writeJSON(w, 201, partialNativeOffSummary(v))
}
func (s *Server) handleOpsPartialNativeOffReconciliationRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	pre := r.PathValue("preregistrationId")
	if !dispositionGrantID(pre) {
		writeJSONError(w, 400, "only_original_preregistration_UUID_required")
		return
	}
	store := repository.CapacityStore{DB: s.db}
	rows, err := store.ReadFailedInstalledPartialNativeOff(r.Context(), pre)
	if err != nil {
		writeJSONError(w, 409, "partial_native_off_reconciliation_not_readable")
		return
	}
	values := []map[string]any{}
	for _, v := range rows {
		row := partialNativeOffSummary(v)
		reads, e := store.ReadFailedInstalledPartialNativeOffReads(r.Context(), v.ID)
		if e != nil {
			writeJSONError(w, 409, "partial_native_off_reads_not_readable")
			return
		}
		row["reads"] = reads
		values = append(values, row)
	}
	writeJSON(w, 200, map[string]any{"schema": "partial_native_off_reconciliation_public_ledger_v1", "preregistration_id": pre, "rows": values, "GET_only_no_native_call": true})
}
func decodePartialNativeOffRead(r io.Reader) (string, string, string, error) {
	d := json.NewDecoder(r)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	values := map[string]string{}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		if e != nil || !ok || (key != "preregistration_id" && key != "reconciliation_id" && key != "expected_previous_read_id") {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		if _, exists := values[key]; exists {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		var value *string
		if e = d.Decode(&value); e != nil || value == nil {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		v := *value
		if !dispositionGrantID(v) && (key != "expected_previous_read_id" || v != "") {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		values[key] = v
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(values) != 3 || d.Decode(new(any)) != io.EOF {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	return values["preregistration_id"], values["reconciliation_id"], values["expected_previous_read_id"], nil
}
func (s *Server) handleOpsPartialNativeOffReconciliationObserve(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	pre, id, previous, err := decodePartialNativeOffRead(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, 400, "only_exact_reconciliation_and_previous_read_IDs_required")
		return
	}
	value, err := messagecontroller.ObserveFailedInstalledPartialNativeOff(r.Context(), s.db, s.brokerConnection(), pre, id, previous)
	if err != nil {
		writeJSONError(w, 409, "partial_native_off_not_qualified_read_ledger_without_replay")
		return
	}
	writeJSON(w, 201, map[string]any{"schema": "partial_native_off_original_read_result_v1", "read_id": value.ReadID, "ordinal": value.Ordinal, "reconciliation_id": value.ReconciliationID, "quiescent_qualified": value.QuiescentQualified, "Guest_request_or_poweroff_or_delete_sent": false, "read_ledger_before_any_separate_next_read": true})
}
