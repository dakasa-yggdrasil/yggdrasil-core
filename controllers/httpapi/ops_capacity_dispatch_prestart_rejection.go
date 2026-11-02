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

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// The request contains compare-and-swap expectations only. Catalog activity,
// prestart absence, lease expiry and current authorization come from Core.
func decodeCapacityDispatchPrestartRejection(input io.Reader) (repository.CapacityDispatchPrestartRejectionRequest, error) {
	var request repository.CapacityDispatchPrestartRejectionRequest
	refused := errors.New("closed capacity dispatch prestart rejection request required")
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return request, refused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return request, refused
	}
	fields := make(map[string]json.RawMessage, 7)
	for d.More() {
		token, tokenErr := d.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok {
			return request, refused
		}
		switch key {
		case "job_id", "expected_run_id", "expected_envelope_sha256", "expected_fencing_token", "expected_superseding_policy_id", "expected_superseding_policy_version", "expected_superseding_policy_checksum":
		default:
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
	if err != nil || last != json.Delim('}') || len(fields) != 7 || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return request, refused
	}
	decodeID := func(name string) (uuid.UUID, error) {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || !dispositionGrantID(value) {
			return uuid.Nil, refused
		}
		return uuid.Parse(value)
	}
	if request.JobID, err = decodeID("job_id"); err != nil {
		return request, refused
	}
	if request.ExpectedRunID, err = decodeID("expected_run_id"); err != nil {
		return request, refused
	}
	if request.ExpectedSupersedingPolicyID, err = decodeID("expected_superseding_policy_id"); err != nil {
		return request, refused
	}
	if json.Unmarshal(fields["expected_envelope_sha256"], &request.ExpectedEnvelopeSHA256) != nil ||
		json.Unmarshal(fields["expected_fencing_token"], &request.ExpectedFencingToken) != nil ||
		json.Unmarshal(fields["expected_superseding_policy_version"], &request.ExpectedSupersedingPolicyVersion) != nil ||
		json.Unmarshal(fields["expected_superseding_policy_checksum"], &request.ExpectedSupersedingPolicyChecksum) != nil ||
		request.ExpectedFencingToken < 0 || request.ExpectedFencingToken > 9007199254740991 || request.ExpectedSupersedingPolicyVersion <= 0 {
		return request, refused
	}
	for _, digest := range []string{request.ExpectedEnvelopeSHA256, request.ExpectedSupersedingPolicyChecksum} {
		decoded, decodeErr := hex.DecodeString(digest)
		if decodeErr != nil || len(digest) != 64 || hex.EncodeToString(decoded) != digest {
			return request, refused
		}
	}
	return request, nil
}

func capacityDispatchPrestartRejectionSummary(record repository.CapacityDispatchPrestartRejection) map[string]any {
	return map[string]any{"schema": "capacity_dispatch_prestart_rejection_v1", "state": record.State,
		"realm": record.Realm, "environment": record.Environment, "domain": record.Domain, "dimension": record.Dimension,
		"job_id": record.JobID, "run_id": record.RunID, "envelope_sha256": record.EnvelopeSHA256,
		"fencing_token": record.FencingToken, "reason": record.Reason, "issuer": record.Issuer, "recorded_at": record.RecordedAt,
		"superseded_policy_id": record.SupersededPolicyID, "superseded_policy_checksum": record.SupersededPolicyChecksum,
		"superseding_policy_id": record.SupersedingPolicyID, "superseding_policy_checksum": record.SupersedingPolicyChecksum,
		"lease_owner": record.LeaseOwner, "lease_expires_at": record.LeaseExpiresAt,
		"started_at": record.StartedAt, "returned_at": record.ReturnedAt, "finalization_ack_at": record.FinalizationAckAt,
		"workflow_run_status": record.WorkflowRunStatus, "workflow_run_started_at": record.WorkflowRunStartedAt,
		"workflow_run_finished_at": record.WorkflowRunFinishedAt, "workflow_run_result_present": record.WorkflowRunResultPresent,
		"workflow_run_error":        record.WorkflowRunError,
		"original_policy":           record.OriginalPolicy,
		"original_workflow_started": false, "provider_mutations": 0, "new_current_admission_required": true}
}

// Administrative rejection spans multiple authorization checks. The ordinary
// request cache deliberately keeps its initial collaborator snapshot, so these
// commit-boundary checks must load the current operator row directly from DB.
func (s *Server) capacityDispatchPrestartOperatorCurrent(ctx context.Context, actor string) error {
	id, err := uuid.Parse(actor)
	if s == nil || s.db == nil || err != nil || id == uuid.Nil || id.String() != actor || dispatchContext(ctx) != nil {
		return errCapacityDispatch
	}
	collaborator, err := repository.GetCollaborator(ctx, s.db, actor)
	if err != nil || collaborator.ID != id || collaborator.Status != "active" {
		return errCapacityDispatch
	}
	permissions, err := repository.ResolveYggdrasilPermissions(ctx, s.db, id, collaborator.Traits)
	if err != nil || dispatchContext(ctx) != nil {
		return errCapacityDispatch
	}
	for _, permission := range permissions {
		if permission == repository.YggdrasilGodModeAction {
			return nil
		}
	}
	return errCapacityDispatch
}

func (s *Server) handleOpsCapacityDispatchPrestartRejection(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeCapacityDispatchPrestartRejection(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_capacity_dispatch_prestart_rejection_expectations")
		return
	}
	request.Issuer = issuer
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	old, err := repository.ReadCapacityDispatchForPrestartRejection(ctx, s.db, request.JobID)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	policy, err := repository.ResolveManifest(ctx, s.db, "capacity_policy", old.Policy.Namespace, old.Policy.Name, nil, true)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	policySpec, err := manifestengine.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifestengine.ValidateCapacityPolicySpec(policySpec) != nil {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	workflow, err := repository.ResolveManifest(ctx, s.db, "workflow", policySpec.Workflow.Namespace, policySpec.Workflow.Name, nil, true)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	service := &CapacityDispatchService{server: s}
	prepared, err := service.PrepareScheduledTick(ctx, workflow.ID, time.Now().UTC())
	if err != nil || prepared == nil || prepared.envelope.Realm != old.Realm || prepared.envelope.Environment != old.Environment ||
		prepared.envelope.Domain != old.Domain || prepared.envelope.Dimension != old.Dimension ||
		prepared.envelope.Policy.Namespace != old.Policy.Namespace || prepared.envelope.Policy.Name != old.Policy.Name ||
		prepared.envelope.Policy.ID != request.ExpectedSupersedingPolicyID || prepared.envelope.Policy.Version != request.ExpectedSupersedingPolicyVersion ||
		prepared.envelope.Policy.Checksum != request.ExpectedSupersedingPolicyChecksum {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	// No Enqueue or workflow execution occurs here. The next ordinary tick must
	// independently pass current admission after this administrative decision.
	revalidate := func(checkCtx context.Context, envelope repository.CapacityDispatchEnvelope) error {
		if permissionErr := s.capacityDispatchPrestartOperatorCurrent(checkCtx, issuer[len("collaborator:"):]); permissionErr != nil {
			return permissionErr
		}
		_, _, authErr := prepared.service.authorizeEnvelope(checkCtx, envelope)
		return authErr
	}
	record, err := repository.RejectCapacityDispatchBeforeStart(ctx, s.db, request, prepared.envelope, revalidate)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "capacity_dispatch_prestart_rejection_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, capacityDispatchPrestartRejectionSummary(record))
}

func (s *Server) handleOpsCapacityDispatchPrestartRejectionRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	value := r.PathValue("jobId")
	if !dispositionGrantID(value) {
		writeJSONError(w, http.StatusBadRequest, "only_original_job_uuid_required")
		return
	}
	id, _ := uuid.Parse(value)
	record, err := repository.ReadCapacityDispatchPrestartRejection(r.Context(), s.db, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "capacity_dispatch_prestart_rejection_not_found")
		return
	}
	writeJSON(w, http.StatusOK, capacityDispatchPrestartRejectionSummary(record))
}
