//go:build !linux || !nativequalification

package message

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestCanonicalFloorPermissionDefaultDisabled(t *testing.T) {
	ctx := context.Background()
	store := repository.CapacityStore{}
	policy := model.Manifest{}
	input := guestOriginalStepInput{}
	permissionOnly, err := guestOriginalCanonicalFloorPreparing(ctx, store, policy, input)
	if err != nil || permissionOnly {
		t.Fatalf("default preparation: permissionOnly=%t err=%v", permissionOnly, err)
	}
	output, handled, err := guestOriginalCanonicalFloorPermission(ctx, store, policy, input, model.CapacityMutationIssue{}, permissionOnly)
	if err != nil || handled || output != nil {
		t.Fatalf("default permission: output=%v handled=%t err=%v", output, handled, err)
	}
}
