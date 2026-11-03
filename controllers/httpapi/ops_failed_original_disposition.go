package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func decodeFailedOriginalDisposition(input io.Reader) (string, string, error) {
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return "", "", errors.New("bounded original identities required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return "", "", errors.New("closed original identities required")
	}
	values := map[string]string{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || (name != "grant_id" && name != "job_id") {
			return "", "", errors.New("only grant and job identities permitted")
		}
		if _, exists := values[name]; exists {
			return "", "", errors.New("duplicate original identity")
		}
		var value string
		if d.Decode(&value) != nil || !dispositionGrantID(value) {
			return "", "", errors.New("canonical original identities required")
		}
		values[name] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(values) != 2 || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return "", "", errors.New("two original identities required")
	}
	return values["grant_id"], values["job_id"], nil
}

func failedOriginalDispositionSummary(v model.CapacityFailedOriginalDisposition) map[string]any {
	return map[string]any{
		"schema": v.Schema, "id": v.ID, "grant_id": v.GrantID, "preregistration_id": v.PreregistrationID,
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
		"dispatch_state":                  "failed_disposed", "original_finalization_ack_present": false,
		"new_assessment_decision_and_single_use_grant_still_required": true,
		"serving_or_business_or_savings_authority":                    false, "provider_mutations": 0,
	}
}

func (s *Server) handleOpsFailedOriginalDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	grantID, jobID, err := decodeFailedOriginalDisposition(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_and_job_uuids_required")
		return
	}
	result, err := messagecontroller.RecordFailedOriginalDisposition(r.Context(), s.db, s.brokerConnection(), grantID, jobID, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "failed_original_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, failedOriginalDispositionSummary(result))
}

func (s *Server) handleOpsFailedOriginalDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("grantId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_uuid_required")
		return
	}
	result, err := (repository.CapacityStore{DB: s.db}).ReadFailedOriginalDisposition(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "failed_original_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, failedOriginalDispositionSummary(result))
}
