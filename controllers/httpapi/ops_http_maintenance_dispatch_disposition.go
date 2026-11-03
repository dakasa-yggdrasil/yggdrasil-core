package httpapi

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This distinct terminal uses the existing closed nine-field CAS contract.
// Neither the caller nor this decoder supplies the recorded failure or proof.
func decodeHTTPMaintenanceDispatchDisposition(input io.Reader) (repository.CapacityDispatchHTTPMaintenanceDispositionRequest, error) {
	request, err := decodeUnknownMaintenanceDispatchDisposition(input)
	return repository.CapacityDispatchHTTPMaintenanceDispositionRequest{CapacityDispatchUnknownMaintenanceDispositionRequest: request}, err
}

// Publish only receipt identities, hashes, times and aggregate evidence. The
// immutable workflow, dispatch, membership and canary bodies stay in Core.
func httpMaintenanceDispatchDispositionSummary(v repository.CapacityDispatchHTTPMaintenanceDisposition) map[string]any {
	return map[string]any{
		"schema": "capacity_dispatch_http_maintenance_disposition_v1", "id": v.ID, "job_id": v.JobID, "run_id": v.RunID,
		"original_dispatch_sha256": v.OriginalDispatchSHA256, "original_run_sha256": v.OriginalRunSHA256,
		"original_dispatch_updated_at": v.OriginalDispatchUpdatedAt, "original_returned_at": v.OriginalReturnedAt,
		"current_members_sha256": v.CurrentMembersSHA256, "current_member_count": v.EffectScan.CurrentMemberCount,
		"executor_barrier": v.ExecutorBarrier, "disposing_core_process_started_at": v.CoreProcessStartedAt,
		"disposing_core_hostname": v.CoreHostname, "disposing_core_pid": v.CorePID, "disposing_core_source_commit": v.CoreSourceCommit,
		"minimum_lease_age_seconds": 900, "recorded_at": v.RecordedAt, "issuer": v.Issuer, "reason": v.Reason,
		"historical_return": v.HistoricalReturn, "dispatch_state": v.State, "original_return_recorded": true,
		"original_finalization_ack_present": false, "finalization_ack_at": nil, "workflow_run_preserved": true,
		"provider_mutation_evidence": v.EffectScan.Base, "replayed": false, "provider_read_performed": false,
		"provider_quiescence_proved": false, "other_core_replicas_excluded": false, "new_current_admission_required": true,
	}
}

func (s *Server) handleOpsHTTPMaintenanceDispatchDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeHTTPMaintenanceDispatchDisposition(http.MaxBytesReader(w, r.Body, unknownMaintenanceDispatchBodyLimit))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_http_maintenance_dispatch_disposition_expectations")
		return
	}
	request.Issuer = issuer
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// This records no success ACK and performs no dispatch or provider call.
	// A later ordinary tick still needs independent current admission.
	revalidate := func(checkCtx context.Context) error {
		return s.capacityDispatchPrestartOperatorCurrent(checkCtx, issuer[len("collaborator:"):])
	}
	record, err := repository.DisposeHTTPMaintenanceDispatch(ctx, s.db, request, currentAbandonedDispatchBarrier(), revalidate)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "http_maintenance_dispatch_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, httpMaintenanceDispatchDispositionSummary(record))
}

func (s *Server) handleOpsHTTPMaintenanceDispatchDispositionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	value := r.PathValue("jobId")
	if !dispositionGrantID(value) {
		writeJSONError(w, http.StatusBadRequest, "only_original_job_uuid_required")
		return
	}
	id, _ := uuid.Parse(value)
	record, err := repository.ReadCapacityDispatchHTTPMaintenanceDisposition(r.Context(), s.db, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "http_maintenance_dispatch_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, httpMaintenanceDispatchDispositionSummary(record))
}
