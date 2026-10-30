//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The original qualification producer serializes a nil action_ids slice as
// null. Validate a copy with that single representation normalized; decode the
// original bytes afterward so the original nil slice and its hash stay intact.
func decodePG17TerminalPhysical(wire []byte, out *model.CapacityMutationProof) error {
	if out == nil {
		return errOriginalGuestStep
	}
	fields := make(map[string]bool)
	var actionsType reflect.Type
	for _, field := range reflect.VisibleFields(reflect.TypeOf(model.CapacityMutationProof{})) {
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || fields[name] {
			return errOriginalGuestStep
		}
		fields[name] = true
		if name == "action_ids" {
			actionsType = field.Type
		}
	}
	if actionsType != reflect.TypeOf([]string{}) {
		return errOriginalGuestStep
	}
	members, err := capacity.NativeCanonicalObject(wire, fields)
	if err != nil {
		return errOriginalGuestStep
	}
	if action, ok := members["action_ids"]; ok && bytes.Equal(bytes.TrimSpace(action), []byte("null")) {
		members["action_ids"] = json.RawMessage(`[]`)
		wireCopy, err := json.Marshal(members)
		if err != nil {
			return errOriginalGuestStep
		}
		var checked model.CapacityMutationProof
		if capacity.DecodeGuestLifecycle(wireCopy, &checked) != nil || json.Unmarshal(wire, out) != nil {
			return errOriginalGuestStep
		}
		return nil
	}
	if capacity.DecodeGuestLifecycle(wire, out) != nil {
		return errOriginalGuestStep
	}
	return nil
}

func pg17ReadTerminalPhysical(ctx context.Context, path string) ([]byte, model.CapacityMutationProof, error) {
	var wire json.RawMessage
	raw, err := q.ReadPrivate(ctx, path, &wire)
	var physical model.CapacityMutationProof
	if err != nil {
		return nil, physical, err
	}
	if err = decodePG17TerminalPhysical(wire, &physical); err != nil {
		return nil, physical, err
	}
	return raw, physical, nil
}
