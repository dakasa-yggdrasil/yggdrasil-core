//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalReadoptionPresenceClosedRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	b := model.CapacityMutationBinding{Name: "fixture"}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Slot: 2, OriginalCreateRequestSHA256: "request", OriginalCreateGrantID: "grant"}
	native := IndependentReturn{Original: CreatorReturn{ResourceID: "resource", OriginalCreateReturnedAt: now}}
	fresh := IndependentReturn{CloseReturnedAt: now}
	proof := originalReadoptionPresenceProof(2, b, pre, native, fresh, []byte("native read"))
	if proof.Slot != 2 || proof.ResourceID != "resource" || proof.ActionIDs == nil || len(proof.ActionIDs) != 0 {
		t.Fatal("presence invented an action or lost original identity")
	}
	path := filepath.Join(t.TempDir(), "presence.json")
	if _, err := Publish(context.Background(), path, proof); err != nil {
		t.Fatal(err)
	}
	var decoded model.CapacityMutationProof
	if _, err := ReadPrivate(context.Background(), path, &decoded); err != nil || decoded.ActionIDs == nil || len(decoded.ActionIDs) != 0 {
		t.Fatal("closed presence roundtrip", err)
	}
	proof.ActionIDs = nil
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if capacity.DecodeGuestLifecycle(raw, &decoded) == nil {
		t.Fatal("null array weakened closed decoder")
	}
}
