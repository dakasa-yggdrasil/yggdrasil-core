//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestProbeMissingOriginalEnrollmentClosedRefusal(t *testing.T) {
	r := &Realm{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := r.Probe(ctx, repository.CapacityStore{}, model.Manifest{}, 1, 1, "owner", 1, nil, nil, time.Now().Add(time.Second))
	if !errors.Is(err, ErrOriginalUnknown) || capacity.GuestQualificationPredicate(err) != "original-guest-step-78" {
		t.Fatal("original missing enrollment refusal lost or misclassified")
	}
}
