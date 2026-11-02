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

var errFinalizationLostDispatchRequest = errors.New("closed finalization-lost dispatch disposition request required")

// 8 KiB of evidence may grow under JSON escaping; the body bound stays fixed.
const finalizationLostDispatchBodyLimit = 65536

var finalizationLostDispatchRequestFields = map[string]bool{
	"job_id": true, "expected_run_id": true, "expected_envelope_sha256": true,
	"expected_fencing_token": true, "expected_lease_owner": true, "expected_pending_wake_count": true,
	"finalization_evidence": true,
}

// The request carries the ADR-0089 compare-and-swap expectations plus the
// operator's opaque evidence text of the observed return. Lease age, run
// state, the tolerated effect scan and the executor barrier come from Core.
func decodeFinalizationLostDispatchDisposition(input io.Reader) (repository.CapacityDispatchFinalizationLostDispositionRequest, error) {
	var request repository.CapacityDispatchFinalizationLostDispositionRequest
	raw, err := io.ReadAll(io.LimitReader(input, finalizationLostDispatchBodyLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > finalizationLostDispatchBodyLimit {
		return request, errFinalizationLostDispatchRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return request, errFinalizationLostDispatchRequest
	}
	fields := make(map[string]json.RawMessage, len(finalizationLostDispatchRequestFields))
	for d.More() {
		token, tokenErr := d.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok || !finalizationLostDispatchRequestFields[key] {
			return request, errFinalizationLostDispatchRequest
		}
		if _, exists := fields[key]; exists {
			return request, errFinalizationLostDispatchRequest
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, errFinalizationLostDispatchRequest
		}
		fields[key] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(fields) != len(finalizationLostDispatchRequestFields) || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return request, errFinalizationLostDispatchRequest
	}
	decodeID := func(name string) (uuid.UUID, error) {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || !dispositionGrantID(value) {
			return uuid.Nil, errFinalizationLostDispatchRequest
		}
		return uuid.Parse(value)
	}
	if request.JobID, err = decodeID("job_id"); err != nil {
		return request, err
	}
	if request.ExpectedRunID, err = decodeID("expected_run_id"); err != nil {
		return request, err
	}
	if request.ExpectedLeaseOwner, err = decodeID("expected_lease_owner"); err != nil {
		return request, err
	}
	if json.Unmarshal(fields["expected_envelope_sha256"], &request.ExpectedEnvelopeSHA256) != nil ||
		json.Unmarshal(fields["expected_fencing_token"], &request.ExpectedFencingToken) != nil ||
		json.Unmarshal(fields["expected_pending_wake_count"], &request.ExpectedPendingWakeCount) != nil ||
		json.Unmarshal(fields["finalization_evidence"], &request.Evidence) != nil ||
		request.ExpectedFencingToken < 1 || request.ExpectedFencingToken > 9007199254740991 ||
		request.ExpectedPendingWakeCount < 1 || request.ExpectedPendingWakeCount > repository.MaxCapacityDispatchPendingWakes ||
		!repository.ValidCapacityDispatchFinalizationEvidence(request.Evidence) {
		return request, errFinalizationLostDispatchRequest
	}
	decoded, decodeErr := hex.DecodeString(request.ExpectedEnvelopeSHA256)
	if decodeErr != nil || len(request.ExpectedEnvelopeSHA256) != 64 || hex.EncodeToString(decoded) != request.ExpectedEnvelopeSHA256 {
		return request, errFinalizationLostDispatchRequest
	}
	return request, nil
}

// Identities, hashes, times and the tolerated counts only: no envelope body,
// inputs, metadata, credentials, provider data or the evidence body itself.
func finalizationLostDispatchDispositionSummary(v repository.CapacityDispatchFinalizationLostDisposition) map[string]any {
	return map[string]any{
		"schema": "capacity_dispatch_finalization_lost_disposition_v1", "id": v.ID, "job_id": v.JobID, "run_id": v.RunID,
		"realm": v.Realm, "environment": v.Environment, "domain": v.Domain, "dimension": v.Dimension,
		"envelope_sha256": v.EnvelopeSHA256, "fencing_token": v.FencingToken, "lease_owner": v.LeaseOwner,
		"lease_expires_at": v.LeaseExpiresAt, "started_at": v.StartedAt, "pending_wake_count": v.PendingWakeCount,
		"original_dispatch_sha256": v.OriginalDispatchSHA256, "original_run_sha256": v.OriginalRunSHA256,
		"executor_barrier": v.ExecutorBarrier, "disposing_core_process_started_at": v.CoreProcessStartedAt,
		"disposing_core_hostname": v.CoreHostname, "disposing_core_pid": v.CorePID, "disposing_core_source_commit": v.CoreSourceCommit,
		"minimum_lease_age_seconds": v.MinimumLeaseAgeSeconds, "recorded_at": v.RecordedAt, "issuer": v.Issuer, "reason": v.Reason,
		"return_observation": v.ReturnObservation, "operator_evidence_sha256": v.EvidenceSHA256, "operator_evidence_bytes": v.EvidenceBytes,
		"operator_evidence_is_authority": false, "provider_mutation_evidence": v.EffectScan,
		"dispatch_state": v.State, "returned_at": v.ReturnedAt, "finalization_ack_at": v.FinalizationAckAt,
		"workflow_run_status": v.WorkflowRunStatus, "workflow_run_error": v.RunError, "workflow_run_finished_at": v.WorkflowRunFinishedAt,
		"workflow_run_finished_at_is_original_return": false, "workflow_run_result_present": v.WorkflowRunResultPresent,
		"historical_return": v.HistoricalReturn, "original_return_recorded": false, "original_finalization_ack_present": false,
		"replayed": false, "provider_read_performed": false, "provider_quiescence_proved": false,
		"other_core_replicas_excluded": false, "new_current_admission_required": true,
	}
}

func (s *Server) handleOpsFinalizationLostDispatchDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeFinalizationLostDispatchDisposition(http.MaxBytesReader(w, r.Body, finalizationLostDispatchBodyLimit))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_finalization_lost_dispatch_disposition_expectations")
		return
	}
	request.Issuer = issuer
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// No Enqueue, claim or workflow execution occurs here. The next ordinary
	// tick must independently pass current admission after this decision.
	revalidate := func(checkCtx context.Context) error {
		return s.capacityDispatchPrestartOperatorCurrent(checkCtx, issuer[len("collaborator:"):])
	}
	record, err := repository.DisposeFinalizationLostStartedDispatch(ctx, s.db, request, currentAbandonedDispatchBarrier(), revalidate)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "finalization_lost_dispatch_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, finalizationLostDispatchDispositionSummary(record))
}

func (s *Server) handleOpsFinalizationLostDispatchDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	value := r.PathValue("jobId")
	if !dispositionGrantID(value) {
		writeJSONError(w, http.StatusBadRequest, "only_original_job_uuid_required")
		return
	}
	id, _ := uuid.Parse(value)
	record, err := repository.ReadCapacityDispatchFinalizationLostDisposition(r.Context(), s.db, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "finalization_lost_dispatch_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, finalizationLostDispatchDispositionSummary(record))
}
