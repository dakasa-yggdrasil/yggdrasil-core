//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestPG17TerminalPhysicalOriginalWire(t *testing.T) {
	proof := model.CapacityMutationProof{BindingName: "native", Slot: 1, ResourceID: "original", ObservedAt: time.Now().UTC(), OwnerVerified: true, SpecVerified: true}
	wire, err := json.Marshal(proof)
	if err != nil || !bytes.Contains(wire, []byte(`"action_ids":null`)) {
		t.Fatal("original producer representation unavailable")
	}
	for _, mode := range []string{"nil_original", "empty_array", "missing_action", "bad_action", "other_null", "unknown", "duplicate", "missing_file", "symlink", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			input := append([]byte(nil), wire...)
			switch mode {
			case "empty_array":
				input = bytes.Replace(input, []byte(`"action_ids":null`), []byte(`"action_ids":[]`), 1)
			case "missing_action":
				input = bytes.Replace(input, []byte(`,"action_ids":null`), nil, 1)
			case "bad_action":
				input = bytes.Replace(input, []byte(`"action_ids":null`), []byte(`"action_ids":1`), 1)
			case "other_null":
				input = bytes.Replace(input, []byte(`"slot":1`), []byte(`"slot":null`), 1)
			case "unknown":
				input = append(input[:len(input)-1], []byte(`,"extra":1}`)...)
			case "duplicate":
				input = append(input[:len(input)-1], []byte(`,"action_ids":[]}`)...)
			}
			path := filepath.Join(t.TempDir(), "original.json")
			if mode != "missing_file" {
				if _, err := q.PublishBytes(context.Background(), path, input); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "symlink" {
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			ctx := context.Background()
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			original, got, err := pg17ReadTerminalPhysical(ctx, path)
			if mode != "nil_original" && mode != "empty_array" {
				if err == nil {
					t.Fatal("invalid original proof accepted")
				}
				return
			}
			if err != nil || !bytes.Equal(original, input) || capacity.BusinessCreationSHA256(original) != capacity.BusinessCreationSHA256(input) || got.ResourceID != proof.ResourceID {
				t.Fatal("original proof or wire changed")
			}
			if mode == "nil_original" && (got.ActionIDs != nil || capacity.GuestRetirementSHA(got) != capacity.GuestRetirementSHA(proof)) {
				t.Fatal("original nil slice or typed hash changed")
			}
			if mode == "empty_array" && got.ActionIDs == nil {
				t.Fatal("original empty slice changed")
			}
		})
	}
}
