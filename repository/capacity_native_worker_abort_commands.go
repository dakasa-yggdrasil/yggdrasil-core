package repository

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// MachineAuthorized checks a fixed, authenticated execution instance before a
// callback body is read. It selects no target and grants no destructive right.
func (s CapacityNativeWorkerAbortStore) MachineAuthorized(ctx context.Context, instance, source string, capabilities map[string]bool) bool {
	if s.Workers.Capacity.DB == nil {
		return false
	}
	rows, err := s.Workers.Capacity.DB.QueryContext(ctx, `SELECT DISTINCT record#>>'{attempt,execution,destroy_capability}' FROM public.capacity_native_worker_abort_permits WHERE record#>>'{attempt,execution,adapter,manifest_id}'=$1 AND record#>>'{attempt,execution,sdk_source_commit}'=$2 LIMIT 33`, instance, source)
	if err != nil {
		return false
	}
	defer rows.Close()
	found, count := false, 0
	for rows.Next() {
		var capability string
		if rows.Scan(&capability) != nil {
			return false
		}
		count++
		if count > 32 || (!strings.HasPrefix(capability, "destroy_") && !strings.HasPrefix(capability, "terminate_")) {
			return false
		}
		found = found || capabilities[capability]
	}
	return rows.Err() == nil && found
}

// ResolveAbortCaller restores only the private Source-written context of this
// original permit. A caller cannot choose policy, recovery workflow or executor.
// Historical receiving stays available when runtime mutation gates are off.
func (s CapacityNativeWorkerAbortStore) ResolveAbortCaller(ctx context.Context, id uuid.UUID, binding, instance, source string, capabilities map[string]bool) (CapacityNativeWorkerAbortStore, model.Manifest, model.CapacityNativeWorkerCommandCaller, error) {
	var policy model.Manifest
	var caller model.CapacityNativeWorkerCommandCaller
	if s.Workers.Capacity.DB == nil {
		return s, policy, caller, ErrCapacityDisabled
	}
	var raw []byte
	if err := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_abort_permits WHERE id=$1`, id).Scan(&raw); err != nil {
		return s, policy, caller, ErrCapacityMutationAuthorization
	}
	var record nativeWorkerAbortRecord
	if json.Unmarshal(raw, &record) != nil || record.Context.PermitID != id || record.Context.AttemptID != record.Attempt.ID ||
		record.Context.BindingName != binding || record.Attempt.Execution.BindingName != binding || record.Attempt.Execution.Adapter.ManifestID != instance ||
		record.Attempt.Execution.SDKSourceCommit != source || !capabilities[record.Attempt.Execution.DestroyCapability] ||
		record.Context.Capability != record.Attempt.Execution.DestroyCapability || record.Context.SDKSourceCommit != source ||
		record.Context.ExecutionScopeSHA256 != record.Attempt.Execution.ScopeSHA256 || !validCapacityExecutor(record.ExecutorID) || record.WorkflowID == uuid.Nil {
		return s, policy, caller, ErrCapacityMutationAuthorization
	}
	var err error
	policy, err = GetManifestByID(ctx, s.Workers.Capacity.DB, record.Attempt.PolicyID)
	if err != nil || policy.Kind != "capacity_policy" || policy.Metadata.Namespace != record.Attempt.Namespace || policy.Checksum != record.Attempt.PolicyChecksum {
		return s, model.Manifest{}, caller, ErrCapacityMutationAuthorization
	}
	s.Workers.Capacity.ExecutorID, s.RecoveryWorkflowID = record.ExecutorID, record.WorkflowID
	caller = model.CapacityNativeWorkerCommandCaller{BindingName: binding, InstanceID: instance, SDKSourceCommit: source, Capability: record.Attempt.Execution.DestroyCapability}
	return s, policy, caller, nil
}
