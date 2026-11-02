//go:build !linux || !nativequalification

package httpapi

import (
	"context"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

func TestQualificationRegistrationClockDefaultUnavailable(t *testing.T) {
	if _, err := guestQualificationRegistrationClock(context.Background(), repository.CapacityStore{}, "", "", "", nil); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		t.Fatal("qualification route available in default build")
	}
}
