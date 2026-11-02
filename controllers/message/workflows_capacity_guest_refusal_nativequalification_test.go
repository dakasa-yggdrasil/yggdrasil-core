//go:build linux && nativequalification

package message

import (
	"context"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestOriginalGuestQualificationMissingRealmStillRefuses(t *testing.T) {
	if originalGuestNativeRealm != nil {
		t.Fatal("test requires uninstalled realm")
	}
	_, err := sourceGuestQualificationStep(context.Background(), repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, guestOriginalStepInput{}, nil, "capacity.qualify_original_guest_echo")
	if !errors.Is(err, errOriginalGuestStep) || capacity.GuestQualificationPredicate(err) != "original-guest-step-77" {
		t.Fatal("missing original realm no longer fails closed")
	}
}
