package capacity

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These are original model storage roundtrips, not a native lifetime or
// permission certificate. The owning Kind gate supplies the real SQL/SDK rows.
func TestNativeCapacityOriginalStorageRoundtrip(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw := func(value any) json.RawMessage {
		t.Helper()
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	challenge := raw(map[string]any{"schema_version": 2, "pod_uid": "original", "lanes": []string{"requests", "workers"}})
	witness := raw(map[string]any{"operation": ObserveNativePodTermination, "status": "observed", "observation": map[string]any{"state": "terminated", "restart_count": 0}})
	policy := raw(map[string]any{"floor": 2, "ceiling": 4, "source": json.Number("9007199254740993")})
	checkpoint := model.CapacityNativePodCheckpoint{
		Namespace: "original", PodName: "pod", PodUID: "original", PolicyID: uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		ContainerStartedAt: at, ConfirmedAt: &at, IntentGeneration: 1, State: "released",
		Challenge: challenge, OriginChallengeBytes: []byte{0, 1, 255}, NativeTerminationReceipt: witness,
		ProjectionAcknowledgement: raw(map[string]any{"state": "projection_observed"}),
		RootAcknowledgement:       raw(map[string]any{"state": "roots_open"}), OriginPolicy: policy,
	}
	encoded := raw(checkpoint)
	var decoded model.CapacityNativePodCheckpoint
	if err := DecodeNativeCapacity(encoded, &decoded); err != nil || !reflect.DeepEqual(checkpoint, decoded) {
		t.Fatal("original checkpoint raw objects/base64 storage changed", err)
	}
	command := model.CapacityNativeCommand{CommandID: checkpoint.PolicyID, CreatedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Minute), Request: challenge, NativeReadback: witness, OriginPolicy: policy}
	var decodedCommand model.CapacityNativeCommand
	if err := DecodeNativeCapacity(raw(command), &decodedCommand); err != nil || !reflect.DeepEqual(command, decodedCommand) {
		t.Fatal("original command raw request/readback storage changed", err)
	}
	command.NativeReadback = nil // Original refused, never-redeemed storage.
	if err := DecodeNativeCapacity(raw(command), &decodedCommand); err != nil || decodedCommand.NativeReadback == nil || !bytes.Equal(decodedCommand.NativeReadback, []byte("null")) {
		t.Fatal("original null raw readback refused or promoted", err)
	}
	var absentWitness model.AdapterCapacityPodTerminationResponse
	if DecodeNativeCapacity(decodedCommand.NativeReadback, &absentWitness) == nil {
		t.Fatal("original null readback became a typed termination witness")
	}
	var optional struct {
		Raw   json.RawMessage `json:"raw"`
		Bytes []byte          `json:"bytes"`
	}
	for index, value := range []json.RawMessage{json.RawMessage(`{"raw":null,"bytes":null}`), json.RawMessage(`{"raw":[1,{"n":9007199254740993}],"bytes":""}`)} {
		if err := DecodeNativeCapacity(value, &optional); err != nil {
			t.Fatal("original raw JSON/null/empty byte encoding refused", err)
		}
		if index == 0 && (optional.Bytes != nil || !bytes.Equal(optional.Raw, []byte("null"))) {
			t.Fatal("original optional null encoding changed")
		}
	}
	if !bytes.Contains(optional.Raw, []byte("9007199254740993")) {
		t.Fatal("raw numeric precision changed")
	}
}

func TestNativeCapacityStorageClosedRefusals(t *testing.T) {
	type record struct {
		Raw   json.RawMessage `json:"raw"`
		Bytes []byte          `json:"bytes"`
		Count int32           `json:"count"`
		Child struct {
			Name string `json:"name"`
		} `json:"child"`
	}
	for name, value := range map[string]string{
		"unknown":            `{"foreign":1}`,
		"field_alias":        `{"Raw":{}}`,
		"typed_nested_alias": `{"child":{"Name":"x"}}`,
		"typed_nested_extra": `{"child":{"name":"x","foreign":1}}`,
		"duplicate_root":     `{"raw":{},"raw":null}`,
		"duplicate_raw":      `{"raw":{"x":1,"x":2}}`,
		"duplicate_in_array": `{"raw":[{"x":1,"x":2}]}`,
		"malformed_raw":      `{"raw":{"x":}}`,
		"scalar_record":      `1`,
		"typed_scalar":       `{"child":1}`,
		"bytes_array":        `{"bytes":[65]}`,
		"bytes_number":       `{"bytes":1}`,
		"bytes_invalid":      `{"bytes":"not-base64"}`,
		"bytes_pad_bits":     `{"bytes":"QR=="}`,
		"numeric_range":      `{"count":2147483648}`,
		"numeric_fraction":   `{"count":1.5}`,
		"nonfinite":          `{"count":NaN}`,
		"trailing":           `{"raw":{}} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out record
			if DecodeNativeCapacity(json.RawMessage(value), &out) == nil {
				t.Fatal("malformed/noncanonical original storage accepted")
			}
		})
	}
	t.Run("original_cap", func(t *testing.T) {
		var out record
		if DecodeNativeCapacity(json.RawMessage(`{"raw":"`+strings.Repeat("x", (2<<20)-10)+`"}`), &out) != nil {
			t.Fatal("original exact two MiB cap was narrowed")
		}
		if DecodeNativeCapacity(json.RawMessage(`{"raw":"`+strings.Repeat("x", 2<<20)+`"}`), &out) == nil {
			t.Fatal("original two MiB cap changed")
		}
	})
	t.Run("raw_application_keys_remain_case_sensitive", func(t *testing.T) {
		var out record
		original := json.RawMessage(`{"raw":{"CaseKey":"one","casekey":"two"}}`)
		if DecodeNativeCapacity(original, &out) != nil || !bytes.Equal(out.Raw, []byte(`{"CaseKey":"one","casekey":"two"}`)) {
			t.Fatal("original raw application keys were normalized")
		}
	})
	t.Run("raw_is_not_typed_authority", func(t *testing.T) {
		for _, value := range []json.RawMessage{json.RawMessage(`{"Name":"x"}`), json.RawMessage(`{"name":"x","foreign":1}`), json.RawMessage(`1`)} {
			var child struct {
				Name string `json:"name"`
			}
			if DecodeNativeCapacity(value, &child) == nil {
				t.Fatal("raw value bypassed its original typed owner")
			}
		}
	})
	t.Run("output_shape", func(t *testing.T) {
		var absent *record
		if DecodeNativeCapacity(json.RawMessage(`{}`), nil) == nil || DecodeNativeCapacity(json.RawMessage(`{}`), absent) == nil || DecodeNativeCapacity(json.RawMessage(`{}`), record{}) == nil {
			t.Fatal("invalid original output target accepted")
		}
	})
}
