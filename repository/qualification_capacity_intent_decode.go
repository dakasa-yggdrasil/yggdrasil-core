//go:build linux && nativequalification

package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The omitempty members of model.CapacityIntent. They may be absent; when
// present they are never null. qualificationClosedFields refuses this
// declaration unless it is exactly the type's omitempty member set.
var qualificationCapacityIntentOptional = map[string]bool{
	"failed_installed_disposal": true,
	"installed_guest_reconcile": true,
	"lease_owner":               true,
	"lease_executor_id":         true,
	"lease_expires_at":          true,
	"floor_degraded":            true,
	"original_notify_window":    true,
}

// native_pod_baseline is a non-omitempty []string, so a nil baseline is
// stored as JSON null. It is the only member whose null is accepted.
const qualificationCapacityIntentNullableBaseline = "native_pod_baseline"

// DecodeQualificationCapacityIntent is the qualification-only closed decoder
// for a raw public.capacity_intents.intent row. The shared Guest lifecycle
// decoder refuses every null, and so refuses every intent stored with a nil
// native pod baseline; it stays unchanged.
//
// The top-level member set is closed; each non-omitempty member is required
// exactly once and an omitempty member may be absent. Only
// native_pod_baseline may be null; a non-null baseline must be an array of
// strings. Every other present member is validated, closed and non-null, by
// the shared Guest lifecycle decoder against its field type. Duplicate
// members and trailing data are refused. The output is the json.Unmarshal of
// the original wire (so a null baseline stays nil and [] stays empty), and it
// is written only on success.
func DecodeQualificationCapacityIntent(wire []byte, out *model.CapacityIntent) error {
	refused := fmt.Errorf("closed qualification capacity intent required")
	if out == nil || len(wire) == 0 || len(wire) > capacity.GuestBootstrapLimit {
		return refused
	}
	fields, ok := qualificationClosedFields(reflect.TypeOf(model.CapacityIntent{}), nil, qualificationCapacityIntentOptional)
	if !ok {
		return refused
	}
	if baseline, declared := fields[qualificationCapacityIntentNullableBaseline]; !declared || baseline != reflect.TypeOf([]string{}) || qualificationCapacityIntentOptional[qualificationCapacityIntentNullableBaseline] {
		return refused
	}
	allowed := make(map[string]bool, len(fields))
	for name := range fields {
		allowed[name] = true
	}
	// Unknown and duplicate top-level members, and trailing data, are refused.
	members, err := capacity.NativeCanonicalObject(wire, allowed)
	if err != nil {
		return refused
	}
	for name, t := range fields {
		raw, present := members[name]
		if !present {
			if qualificationCapacityIntentOptional[name] {
				continue
			}
			return refused
		}
		value := bytes.TrimSpace(raw)
		if len(value) == 0 {
			return refused
		}
		if bytes.Equal(value, []byte("null")) {
			if name == qualificationCapacityIntentNullableBaseline {
				continue
			}
			return refused
		}
		if name == qualificationCapacityIntentNullableBaseline {
			if value[0] != '[' {
				return refused
			}
			var elements []json.RawMessage
			if json.Unmarshal(value, &elements) != nil {
				return refused
			}
			for _, element := range elements {
				var text string
				element = bytes.TrimSpace(element)
				if len(element) == 0 || element[0] != '"' || json.Unmarshal(element, &text) != nil {
					return refused
				}
			}
		}
		if capacity.DecodeGuestLifecycle(value, reflect.New(t).Interface()) != nil {
			return refused
		}
	}
	var decoded model.CapacityIntent
	if json.Unmarshal(wire, &decoded) != nil {
		return refused
	}
	*out = decoded
	return nil
}
