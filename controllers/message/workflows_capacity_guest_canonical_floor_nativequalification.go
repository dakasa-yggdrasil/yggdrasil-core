//go:build linux && nativequalification

package message

import (
	"context"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"path/filepath"
)

// Called after this SAME resolved source-owned step generated its original
// nonce/context. It never accepts caller-supplied private Source authority.
func guestOriginalCanonicalFloorPermission(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, issue model.CapacityMutationIssue, permissionOnly bool) (any, bool, error) {
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "canonical_failed_floor_recovery" || input.Slot != 2 {
		return nil, false, nil
	}
	handled, err := store.CanonicalFloorNextPermission(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner)
	return completeCanonicalFloorPermission(permissionOnly, handled, err, func() (any, error) {
		grant, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, issue)
		if err != nil || grant.State != "issued" || grant.CompensationOf != "" {
			return nil, errOriginalGuestStep
		}
		pre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
		if err != nil || pre.OriginalCreateGrantID != grant.GrantID || pre.Generation != input.Generation {
			return nil, errOriginalGuestStep
		}
		// No Redeem/Create/actor/bootstrap command occurs in this branch.
		if _, err = q.Publish(ctx, filepath.Join(originalGuestNativeRealm.PrivateDirectory, "canonical-floor-next-grant.json"), grant); err != nil {
			return nil, err
		}
		return map[string]any{"schema": "canonical_original_next_floor_permission_v1", "grant_id": grant.GrantID, "preregistration_id": pre.PreregistrationID, "state": "issued", "redeemed": false, "physical_create_called": false, "provider_prepare_performed": false}, nil
	})
}

// Verify the two observations before issuing or publishing any grant.
func completeCanonicalFloorPermission(permissionOnly, handled bool, err error, issue func() (any, error)) (any, bool, error) {
	if err != nil {
		return nil, handled, err
	}
	if permissionOnly != handled {
		return nil, handled, errOriginalGuestStep
	}
	if !handled {
		return nil, false, nil
	}
	output, err := issue()
	return output, true, err
}

func guestOriginalCanonicalFloorPreparing(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput) (bool, error) {
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "canonical_failed_floor_recovery" || input.Slot != 2 {
		return false, nil
	}
	return store.CanonicalFloorNextPermission(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner)
}
