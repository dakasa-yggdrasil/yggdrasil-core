//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Partial recovery now approves a prospective logical third slot. Its private
// config directory must not expand the fixed native realm or reach any sender,
// filesystem waiter or SQL dependency, including with otherwise absent owners.
func TestProspectiveThirdSlotCannotReachNative(t *testing.T) {
	private := t.TempDir()
	if SlotDirectory(private, 3) != filepath.Join(private, "slot-3") {
		t.Fatal("prospective source config directory missing")
	}
	r := &Realm{PrivateDirectory: private}
	for _, slot := range []int{0, 3, 4} {
		if err := r.Prepare(context.Background(), slot); !errors.Is(err, ErrOriginalUnknown) {
			t.Fatalf("prospective slot%d reached Prepare: %v", slot, err)
		}
		proof, err := r.Create(context.Background(), repository.CapacityStore{}, model.Manifest{}, model.CapacityMutationGrant{Slot: slot}, model.CapacityGuestOriginalProvisioningPreregistration{})
		if !errors.Is(err, ErrOriginalUnknown) || proof.ResourceID != "" || len(r.started) != 0 || len(r.prepared) != 0 {
			t.Fatalf("prospective slot%d reached native create: %#v %v", slot, proof, err)
		}
	}
}
