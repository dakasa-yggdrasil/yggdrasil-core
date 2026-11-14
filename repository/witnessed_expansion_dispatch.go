package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only Enqueue, under its canonical scope lock, derives this selector. The
// original UNKNOWN job/envelope stays immutable. Storage independently binds
// the new marked job to the same admission and exact current intent.
func witnessedExpansionDispatchParentTx(ctx context.Context, tx *sql.Tx, next CapacityDispatchEnvelope) (string, uuid.UUID, error) {
	var intentWire []byte
	err := tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE`, next.Realm, next.Environment, next.Domain, next.Dimension).Scan(&intentWire)
	if errors.Is(err, sql.ErrNoRows) {
		return "", uuid.Nil, nil
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(intentWire, &fields) != nil {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	if _, present := fields["witnessed_unenrolled_expansion_cleanup_id"]; !present {
		return "", uuid.Nil, nil
	}
	var current model.CapacityIntent
	if json.Unmarshal(intentWire, &current) != nil || !canonicalDemandUUID(current.WitnessedUnenrolledExpansionCleanupID) {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return "", uuid.Nil, err
	}
	a, events, err := loadWitnessedExpansionTx(ctx, tx, current.WitnessedUnenrolledExpansionCleanupID)
	if err != nil {
		return "", uuid.Nil, err
	}
	if len(events) == 0 {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	if events[len(events)-1].Stage == "terminal" {
		return "", uuid.Nil, nil
	}
	parent, err := readCapacityDispatchJob(ctx, tx, uuid.MustParse(a.JobID), true)
	if err != nil {
		return "", uuid.Nil, err
	}
	if parent.State != "unknown" || parent.FinalizationAckAt != nil || parent.WitnessedUnenrolledExpansionCleanupID != "" || !installedProvisionTimeoutAuthorityEqual(parent.CapacityDispatchEnvelope, next) || current.PolicyID.String() != a.PolicyID || current.PolicyChecksum != a.PolicyChecksum || current.Decision.Reason != WitnessedUnenrolledExpansionCleanupMode || a.PolicyID != next.Policy.ID.String() || a.WorkflowID != next.Workflow.ID.String() || a.WorkflowChecksum != next.Workflow.Checksum {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	if err = witnessedExpansionOriginalsTx(ctx, tx, a); err != nil {
		return "", uuid.Nil, err
	}
	var policy model.Manifest
	policy.Kind = "capacity_policy"
	policy.ID = next.Policy.ID
	policy.Metadata.Namespace = next.Realm
	policy.Metadata.Name = next.Policy.Name
	policy.Checksum = next.Policy.Checksum
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND checksum=$2 FOR SHARE`, policy.ID, policy.Checksum).Scan(&policy.Spec, &active); err != nil || !active {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	spec, err := parseCapacityPolicy(policy)
	if err != nil {
		return "", uuid.Nil, err
	}
	var graph model.WorkflowManifestSpec
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT spec,active FROM public.manifests WHERE id=$1 AND kind='workflow' AND checksum=$2 FOR SHARE`, next.Workflow.ID, next.Workflow.Checksum).Scan(&raw, &active); err != nil || !active || json.Unmarshal(raw, &graph) != nil || capacity.ValidateOriginalGuestReconcileGraph(graph, policy, spec) != nil {
		return "", uuid.Nil, ErrCapacityDispatchEnvelope
	}
	return a.ID, parent.JobID, nil
}
