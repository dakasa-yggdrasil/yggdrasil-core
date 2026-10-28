//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
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

func TestReadoptionNativeReturnPreservesCreatorHash(t *testing.T) {
	ctx := context.Background()
	native := IndependentReturn{OriginalCreatorSHA256: strings.Repeat("a", 64)}
	fresh := IndependentReturn{Schema: "core_independent_original_qemu_read_v1", Original: CreatorReturn{OriginalIO: []OriginalIO{}}, IO: []OriginalIO{}}
	path := filepath.Join(t.TempDir(), "native.json")
	raw, err := publishReadoptionOriginalNativeRead(ctx, path, native, fresh)
	if err != nil {
		t.Fatal(err)
	}
	var decoded IndependentReturn
	if _, err := ReadPrivate(ctx, path, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OriginalCreatorSHA256 != native.OriginalCreatorSHA256 {
		t.Fatal("fresh return lost original creator hash")
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil || wire["original_creator_sha256"] != native.OriginalCreatorSHA256 {
		t.Fatal("published wire lost creator hash", err)
	}
	invalidPath := filepath.Join(t.TempDir(), "invalid.json")
	if _, err := publishReadoptionOriginalNativeRead(ctx, invalidPath, IndependentReturn{}, fresh); err == nil {
		t.Fatal("missing creator hash accepted")
	}
}
