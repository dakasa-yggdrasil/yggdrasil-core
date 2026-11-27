package repository

import (
	"context"
	"encoding/json"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Authentication checks only the exact private issuance owner before a callback
// body is read. It neither selects a target nor exposes a mutation grant.
func (s CapacityNativeWorkerNetworkStore) MachineAuthorized(ctx context.Context, principal, instance, source string, caps map[string]bool) bool {
	if s.Workers.Capacity.DB == nil {
		return false
	}
	rows, e := s.Workers.Capacity.DB.QueryContext(ctx, `SELECT DISTINCT record#>>'{context,capability}' FROM public.capacity_native_worker_network_permits WHERE record#>>'{binding,writer,principal_id}'=$1 AND record#>>'{binding,writer,adapter_id}'=$2 AND record#>>'{binding,writer,system_source_commit}'=$3 LIMIT 3`, principal, instance, source)
	if e != nil {
		return false
	}
	defer rows.Close()
	count, found := 0, false
	for rows.Next() {
		var capability string
		if rows.Scan(&capability) != nil {
			return false
		}
		count++
		if count > 2 || capability != "ensure_native_worker_network" && capability != "destroy_native_worker_network" {
			return false
		}
		found = found || caps[capability]
	}
	return rows.Err() == nil && found
}

// The machine never supplies policy, namespace, executor or recovery workflow.
// Original private identities remain resolvable for historical late custody.
func (s CapacityNativeWorkerNetworkStore) ResolveCaller(ctx context.Context, id uuid.UUID, binding, principal, instance, source string, caps map[string]bool) (CapacityNativeWorkerNetworkStore, model.Manifest, CapacityNativeWorkerNetworkCaller, error) {
	var policy model.Manifest
	var caller CapacityNativeWorkerNetworkCaller
	if s.Workers.Capacity.DB == nil {
		return s, policy, caller, ErrCapacityDisabled
	}
	var raw []byte
	var r nativeWorkerNetworkRecord
	e := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE id=$1`, id).Scan(&raw)
	if e != nil || json.Unmarshal(raw, &r) != nil || r.Context.PermitID != id.String() || r.Context.BindingName != binding || r.Context.AttemptID != r.Attempt.ID.String() || !caps[r.Context.Capability] || !validCapacityExecutor(r.ExecutorID) || r.WorkflowID == uuid.Nil {
		return s, policy, caller, ErrCapacityMutationAuthorization
	}
	caller = CapacityNativeWorkerNetworkCaller{PrincipalID: principal, InstanceID: instance, SystemSourceCommit: source, BindingName: binding, Capability: r.Context.Capability}
	if !nativeNetworkCaller(r, caller) {
		return s, policy, caller, ErrCapacityMutationAuthorization
	}
	policy, e = GetManifestByID(ctx, s.Workers.Capacity.DB, r.Attempt.PolicyID)
	if e != nil || policy.Kind != "capacity_policy" || policy.Metadata.Namespace != r.Attempt.Namespace || policy.Checksum != r.Attempt.PolicyChecksum {
		return s, model.Manifest{}, caller, ErrCapacityMutationAuthorization
	}
	s.Workers.Capacity.ExecutorID, s.Workers.Capacity.WorkflowID, s.RecoveryWorkflowID = r.ExecutorID, r.WorkflowID, r.RecoveryWorkflowID
	return s, policy, caller, nil
}
