//go:build linux && nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ReadSourceRecoveryHistoricalPreregistration observes a qualification-only
// preregistration after the original lease has expired. It is not current
// authority, and cannot admit any mutation, callback or provider effect.
func (s CapacityStore) ReadSourceRecoveryHistoricalPreregistration(ctx context.Context, policy model.Manifest, workflowID uuid.UUID, grantID, preregID string, slot int, generation, fence int64) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	return s.readSourceRecoveryHistoricalPreregistration(ctx, policy, workflowID, grantID, preregID, slot, generation, fence, capacity.CurrentGuestCoreSource())
}

func (s CapacityStore) readSourceRecoveryHistoricalPreregistration(ctx context.Context, policy model.Manifest, workflowID uuid.UUID, grantID, preregID string, slot int, generation, fence int64, source string) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	var result model.CapacityGuestOriginalProvisioningPreregistration
	var p model.CapacityPolicySpec
	if s.DB == nil || ctx.Err() != nil || !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || policy.Kind != "capacity_policy" || policy.ID == uuid.Nil || !capacity.ValidDigest(policy.Checksum) || policy.Metadata.Namespace == "" || workflowID == uuid.Nil || !validCapacityExecutor(grantID) || !validCapacityExecutor(preregID) || slot != 1 || generation < 1 || fence < 1 || source == "" || json.Unmarshal(policy.Spec, &p) != nil || p.GuestRetirementBinding == nil {
		return result, ErrCapacityConflict
	}
	err := s.guestStoredTransaction(ctx, preregID, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
		if !sourceRecoveryHistoricalJoin(stored, policy, p, workflowID, grantID, preregID, slot, generation, fence, source) {
			return ErrCapacityConflict
		}
		var namespace string
		if err := tx.QueryRowContext(ctx, `SELECT namespace FROM public.capacity_mutation_grants WHERE id=$1`, grantID).Scan(&namespace); err != nil || namespace != policy.Metadata.Namespace {
			return ErrCapacityConflict
		}
		result = stored.pre
		return nil
	})
	if err != nil || ctx.Err() != nil {
		return model.CapacityGuestOriginalProvisioningPreregistration{}, ErrCapacityConflict
	}
	return result, nil
}

func sourceRecoveryHistoricalJoin(stored guestOriginalStored, policy model.Manifest, p model.CapacityPolicySpec, workflowID uuid.UUID, grantID, preregID string, slot int, generation, fence int64, source string) bool {
	pre, binding := stored.pre, stored.binding
	return source != "" && p.GuestRetirementBinding != nil && reflect.DeepEqual(binding, *p.GuestRetirementBinding) && capacity.GuestOriginalProfileEnabled(p, binding, "native-qemu") && pre.PreregistrationID == preregID && pre.OriginalCreateGrantID == grantID && pre.PolicyID == policy.ID.String() && pre.PolicyChecksum == policy.Checksum && pre.WorkflowID == workflowID.String() && pre.Slot == slot && slot == 1 && pre.Generation == generation && pre.Fence == fence && pre.CoreSourceCommit == source && binding.CoreAuthoritySourceCommit == source && pre.BindingName == stored.member.Name && stored.member.Slot == slot && pre.ProfileManifestSHA256 == binding.ProfileManifestSHA256
}
