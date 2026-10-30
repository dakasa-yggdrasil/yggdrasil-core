package capacity

import (
	"context"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const ProvisionOriginalGuestOperation = "capacity.provision_original_guest"
const RetireOriginalGuestOperation = "capacity.retire_original_guest"

// This is the SAME first retirement's bound, not a renewed context or a
// provisioning budget. The current lease and the 30s original actor cap can
// only shorten the already captured source context.
func GuestOriginalRetirementDeadline(ctx context.Context, issuedAt, leaseExpiresAt time.Time) (time.Time, error) {
	deadline, exists := ctx.Deadline()
	if !exists || ctx.Err() != nil || issuedAt.IsZero() || !deadline.After(issuedAt) || !leaseExpiresAt.After(issuedAt) {
		return time.Time{}, fmt.Errorf("live original retirement context and lease required")
	}
	for _, bound := range []time.Time{issuedAt.Add(30 * time.Second), leaseExpiresAt} {
		if bound.Before(deadline) {
			deadline = bound
		}
	}
	return deadline.UTC(), nil
}

// The caller supplies the ACTUAL resolved protected workflow step, never a
// rendered workflow input. Its original context is made from that step before
// reservation/create. Existing bound HPA90s and provider write60s stay separate.
func GuestOriginalProvisioningDeadline(ctx context.Context, profile model.CapacityGuestProtectedProfileManifest, originalStep model.WorkflowStepSpec, reservedAt time.Time) (time.Time, error) {
	deadline, exists := ctx.Deadline()
	if !exists || ctx.Err() != nil || reservedAt.IsZero() || !deadline.After(reservedAt) || profile.OriginalProvisioningBudgetSeconds < 1 || profile.OriginalProvisioningBudgetSeconds > 86400 || !guestText(profile.OriginalProvisioningStepID, 64) || originalStep.ID != profile.OriginalProvisioningStepID || originalStep.Use.Kind != "yggdrasil" || originalStep.Use.Operation != ProvisionOriginalGuestOperation || originalStep.TimeoutSeconds < profile.OriginalProvisioningBudgetSeconds || originalStep.TimeoutSeconds > 86400 || originalStep.Retry.MaxAttempts > 1 || originalStep.ForEach != nil {
		return time.Time{}, fmt.Errorf("explicit original protected provisioning budget required")
	}
	budgetEnd := reservedAt.Add(time.Duration(profile.OriginalProvisioningBudgetSeconds) * time.Second)
	if deadline.Before(budgetEnd) {
		return deadline, nil
	}
	return budgetEnd, nil
}

// A stored preregistration is immutable even after its original deadline.
// Recent observation, lease renewal or current configuration is not an input.
func GuestOriginalProvisioningDeadlineMatches(record model.CapacityGuestOriginalProvisioningPreregistration, profile model.CapacityGuestProtectedProfileManifest) bool {
	if record.Schema != "original_guest_provisioning_preregistration_v1" || !guestUUID(record.PreregistrationID) || !guestUUID(record.OriginalCreateGrantID) || !ValidDigest(record.OriginalCreateRequestSHA256) || !ValidDigest(record.NonceSHA256) || record.ProfileManifestSHA256 != GuestRetirementSHA(profile) || !guestUUID(record.PolicyID) || !ValidDigest(record.PolicyChecksum) || !guestUUID(record.WorkflowID) || !ValidDigest(record.WorkflowChecksum) || record.Generation < 1 || record.Fence < 1 || !guestUUID(record.LeaseOwner) || !guestUUID(record.ExecutorID) || !businessSource.MatchString(record.CoreSourceCommit) || record.Slot < 1 || record.Slot > 64 || record.OriginalWorkflowStepID != profile.OriginalProvisioningStepID || !guestText(record.OriginalWorkflowStepID, 64) || profile.OriginalProvisioningBudgetSeconds < 1 || profile.OriginalProvisioningBudgetSeconds > 86400 || record.OriginalWorkflowStepTimeoutSeconds < profile.OriginalProvisioningBudgetSeconds || record.OriginalWorkflowStepTimeoutSeconds > 86400 || record.ReservedAt.IsZero() || !record.OriginalWorkflowContextDeadline.After(record.ReservedAt) {
		return false
	}
	deadline := record.ReservedAt.Add(time.Duration(profile.OriginalProvisioningBudgetSeconds) * time.Second)
	if record.OriginalWorkflowContextDeadline.Before(deadline) {
		deadline = record.OriginalWorkflowContextDeadline
	}
	return record.OriginalDeadline.Equal(deadline)
}
