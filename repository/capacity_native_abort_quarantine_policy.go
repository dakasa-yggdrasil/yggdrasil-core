package repository

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A permanent administrative receipt retains its original policy. A later
// revision may replace physical/catalog identities, never that receipt's origin
// or the logical scope whose other UIDs may disregard its active blocker.
func nativeAbortQuarantineOriginPolicy(ctx context.Context, tx *sql.Tx, current model.Manifest, p model.CapacityPolicySpec, binding model.CapacityNativeAbortQuarantineBinding) (model.Manifest, model.CapacityPolicySpec, error) {
	id, err := uuid.Parse(binding.Native.PolicyID)
	if err != nil || id == uuid.Nil {
		return model.Manifest{}, model.CapacityPolicySpec{}, ErrCapacityConflict
	}
	origin, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, id))
	if err != nil || origin.Checksum != binding.Native.PolicyChecksum {
		return model.Manifest{}, model.CapacityPolicySpec{}, ErrCapacityConflict
	}
	op, err := parseCapacityPolicy(origin)
	if err != nil || !nativeAbortQuarantineSameLogicalScope(current, p, origin, op) {
		return model.Manifest{}, model.CapacityPolicySpec{}, ErrCapacityConflict
	}
	return origin, op, nil
}

func nativeAbortQuarantineSameLogicalScope(current model.Manifest, p model.CapacityPolicySpec, origin model.Manifest, op model.CapacityPolicySpec) bool {
	if current.Kind != "capacity_policy" || current.Metadata.Namespace != origin.Metadata.Namespace || current.Metadata.Name != origin.Metadata.Name || p.Environment != op.Environment || p.Domain != op.Domain || p.Dimension != op.Dimension || p.Owner != op.Owner || p.AssessmentBinding == nil || op.AssessmentBinding == nil || p.HPAExecutionBinding == nil || op.HPAExecutionBinding == nil {
		return false
	}
	a, b := p.AssessmentBinding.Snapshot, op.AssessmentBinding.Snapshot
	h, oh := p.HPAExecutionBinding, op.HPAExecutionBinding
	return a.Mode == b.Mode && a.Unit == b.Unit && a.Namespace == b.Namespace && a.HPAName == b.HPAName && a.WorkloadName == b.WorkloadName && a.Owner == b.Owner && a.Profile == b.Profile &&
		p.Workflow.Namespace == op.Workflow.Namespace && p.Workflow.Name == op.Workflow.Name &&
		h.Mode == capacity.HPALifetimeExecutionMode && h.Mode == oh.Mode && h.AdmissionMode == "process_v2" && h.AdmissionMode == oh.AdmissionMode &&
		h.AdapterPrincipalID == oh.AdapterPrincipalID && h.PodTerminationBinding == oh.PodTerminationBinding && h.ContainerName == oh.ContainerName &&
		h.AdmissionWorkflow.Namespace == oh.AdmissionWorkflow.Namespace && h.AdmissionWorkflow.Name == oh.AdmissionWorkflow.Name
}
