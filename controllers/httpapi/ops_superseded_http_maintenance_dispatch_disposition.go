package httpapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Twelve closed CAS fields. Reuse the old nine-field decoder unchanged after
// rejecting duplicate, missing, null and caller-authority keys in the full body.
func decodeSupersededHTTPMaintenanceDispatchDisposition(input io.Reader) (repository.CapacityDispatchSupersededHTTPMaintenanceDispositionRequest, error) {
	var request repository.CapacityDispatchSupersededHTTPMaintenanceDispositionRequest
	refused := errors.New("closed superseded-policy HTTP maintenance CAS required")
	raw, err := io.ReadAll(io.LimitReader(input, unknownMaintenanceDispatchBodyLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > unknownMaintenanceDispatchBodyLimit {
		return request, refused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return request, refused
	}
	fields := map[string]json.RawMessage{}
	extra := map[string]bool{"expected_replacement_policy_id": true, "expected_replacement_policy_version": true, "expected_replacement_policy_checksum": true}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		if e != nil || !ok || (!unknownMaintenanceDispatchRequestFields[key] && !extra[key]) {
			return request, refused
		}
		if _, exists := fields[key]; exists {
			return request, refused
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, refused
		}
		fields[key] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(fields) != 12 || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return request, refused
	}
	var id string
	if json.Unmarshal(fields["expected_replacement_policy_id"], &id) != nil || !dispositionGrantID(id) {
		return request, refused
	}
	request.ExpectedReplacementPolicyID, _ = uuid.Parse(id)
	if json.Unmarshal(fields["expected_replacement_policy_version"], &request.ExpectedReplacementPolicyVersion) != nil || request.ExpectedReplacementPolicyVersion < 1 || request.ExpectedReplacementPolicyVersion > 2147483647 || json.Unmarshal(fields["expected_replacement_policy_checksum"], &request.ExpectedReplacementPolicyChecksum) != nil {
		return request, refused
	}
	checksum, e := hex.DecodeString(request.ExpectedReplacementPolicyChecksum)
	if e != nil || len(checksum) != 32 || hex.EncodeToString(checksum) != request.ExpectedReplacementPolicyChecksum {
		return request, refused
	}
	for key := range extra {
		delete(fields, key)
	}
	nine, e := json.Marshal(fields)
	if e != nil {
		return request, refused
	}
	request.CapacityDispatchUnknownMaintenanceDispositionRequest, e = decodeUnknownMaintenanceDispatchDisposition(bytes.NewReader(nine))
	if e != nil {
		return request, refused
	}
	return request, nil
}

func supersededHTTPMaintenanceDispatchDispositionSummary(v repository.CapacityDispatchSupersededHTTPMaintenanceDisposition) map[string]any {
	return map[string]any{
		"schema": "capacity_dispatch_superseded_http_maintenance_disposition_v1", "id": v.ID, "job_id": v.JobID, "run_id": v.RunID,
		"original_dispatch_sha256": v.OriginalDispatchSHA256, "original_dispatch_updated_at": v.OriginalDispatchUpdatedAt, "original_run_sha256": v.OriginalRunSHA256, "original_returned_at": v.OriginalReturnedAt,
		"original_policy_id": v.OriginalPolicyID, "original_policy_version": v.OriginalPolicyVersion, "original_policy_checksum": v.OriginalPolicyChecksum,
		"replacement_policy_id": v.ReplacementPolicyID, "replacement_policy_version": v.ReplacementPolicyVersion, "replacement_policy_checksum": v.ReplacementPolicyChecksum,
		"current_members_sha256": v.CurrentMembersSHA256, "current_member_count": v.EffectScan.CurrentMemberCount,
		"executor_barrier": v.ExecutorBarrier, "disposing_core_process_started_at": v.CoreProcessStartedAt, "disposing_core_hostname": v.CoreHostname, "disposing_core_pid": v.CorePID, "disposing_core_source_commit": v.CoreSourceCommit,
		"minimum_lease_age_seconds": 900, "recorded_at": v.RecordedAt, "issuer": v.Issuer, "reason": v.Reason, "historical_return": v.HistoricalReturn, "dispatch_state": v.State,
		"original_return_recorded": true, "original_finalization_ack_present": false, "finalization_ack_at": nil, "workflow_run_preserved": true,
		"provider_mutation_evidence": v.EffectScan.Base, "canary_evidence": v.EffectScan.CanaryEvidence,
		"replayed": false, "provider_read_performed": false, "provider_quiescence_proved": false, "other_core_replicas_excluded": false, "new_current_admission_required": true,
	}
}

func (s *Server) handleOpsSupersededHTTPMaintenanceDispatchDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeSupersededHTTPMaintenanceDispatchDisposition(http.MaxBytesReader(w, r.Body, unknownMaintenanceDispatchBodyLimit))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_superseded_http_maintenance_dispatch_disposition_expectations")
		return
	}
	request.Issuer = issuer
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	revalidate := func(checkCtx context.Context) error {
		return s.capacityDispatchPrestartOperatorCurrent(checkCtx, issuer[len("collaborator:"):])
	}
	record, err := repository.DisposeSupersededHTTPMaintenanceDispatch(ctx, s.db, request, currentAbandonedDispatchBarrier(), revalidate)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "superseded_http_maintenance_dispatch_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, supersededHTTPMaintenanceDispatchDispositionSummary(record))
}

func (s *Server) handleOpsSupersededHTTPMaintenanceDispatchDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	value := r.PathValue("jobId")
	if !dispositionGrantID(value) {
		writeJSONError(w, http.StatusBadRequest, "only_original_job_uuid_required")
		return
	}
	id, _ := uuid.Parse(value)
	record, err := repository.GetSupersededHTTPMaintenanceDispatchDisposition(r.Context(), s.db, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "superseded_http_maintenance_dispatch_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, supersededHTTPMaintenanceDispatchDispositionSummary(record))
}
