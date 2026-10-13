//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

// Structural parser inputs only: no process, QMP socket, provider call, source
// override or original lifecycle is supplied by these Go tests. The zero native
// lifetime deliberately cannot pass CheckCreator after its wire is decoded.
func originalClosedCreatorWire(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(CreatorReturn{OriginalIO: []OriginalIO{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func originalClosedIndependentWire(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(IndependentReturn{Original: CreatorReturn{OriginalIO: []OriginalIO{}}, IO: []OriginalIO{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOriginalNativeQEMUClosedSourceBytes(t *testing.T) {
	creator := originalClosedCreatorWire(t)
	t.Run("complete_struct_requires_explicit_false", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON(creator, &decoded) != nil || decoded.NativeStatusReadback.SingleStep || decoded.OriginalClosesReturned || decoded.OriginalIO == nil {
			t.Fatal("explicit false/empty native structural facts lost")
		}
	})
	t.Run("typed_wire_is_not_original_native_proof", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON(creator, &decoded) != nil {
			t.Fatal("closed structural input unexpectedly refused")
		}
		at := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
		if CheckCreator(decoded, 2, "", "", "", "", at, at.Add(time.Second), at.Add(2*time.Second)) == nil {
			t.Fatal("typed metadata became an original QEMU create proof")
		}
	})
	for _, name := range []string{"omitted_singlestep", "null_singlestep", "singlestep_alias", "singlestep_fold_duplicate", "singlestep_duplicate", "unknown_nested_status", "unknown_nested_lifetime", "unknown_nested_peer", "omitted_original_close", "null_original_io", "omitted_original_io", "uuid_case_alias", "trailing_record", "root_array", "root_null", "wire_oversize"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), creator...)
			switch name {
			case "omitted_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false,`), nil, 1)
			case "null_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":null`), 1)
			case "singlestep_alias":
				raw = bytes.Replace(raw, []byte(`"singlestep":`), []byte(`"SingleStep":`), 1)
			case "singlestep_fold_duplicate":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":false,"SingleStep":false`), 1)
			case "singlestep_duplicate":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":false,"singlestep":false`), 1)
			case "unknown_nested_status":
				raw = bytes.Replace(raw, []byte(`"native_status_readback":{`), []byte(`"native_status_readback":{"caller_complete":true,`), 1)
			case "unknown_nested_lifetime":
				raw = bytes.Replace(raw, []byte(`"qemu":{`), []byte(`"qemu":{"native_verified":true,`), 1)
			case "unknown_nested_peer":
				raw = bytes.Replace(raw, []byte(`"qmp_original_peer":{`), []byte(`"qmp_original_peer":{"same_owner":true,`), 1)
			case "omitted_original_close":
				raw = bytes.Replace(raw, []byte(`"original_closes_returned":false,`), nil, 1)
			case "null_original_io":
				raw = bytes.Replace(raw, []byte(`"original_io":[]`), []byte(`"original_io":null`), 1)
			case "omitted_original_io":
				raw = bytes.Replace(raw, []byte(`"original_io":[],`), nil, 1)
			case "uuid_case_alias":
				raw = bytes.Replace(raw, []byte(`"UUID":`), []byte(`"uuid":`), 1)
			case "trailing_record":
				raw = append(raw, []byte(`{}`)...)
			case "root_array":
				raw = []byte(`[]`)
			case "root_null":
				raw = []byte(`null`)
			case "wire_oversize":
				raw = append(raw, []byte(strings.Repeat(" ", capacity.GuestBootstrapLimit))...)
			}
			var decoded CreatorReturn
			if closedJSON(raw, &decoded) == nil {
				t.Fatal("omitted/aliased/duplicate native source fact accepted")
			}
		})
	}
	for _, name := range []string{"independent_omitted_nested_singlestep", "independent_unknown_nested", "independent_alias_native_tuple"} {
		t.Run(name, func(t *testing.T) {
			raw := originalClosedIndependentWire(t)
			switch name {
			case "independent_omitted_nested_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false,`), nil, 1)
			case "independent_unknown_nested":
				raw = bytes.Replace(raw, []byte(`"before":{`), []byte(`"before":{"kernel_complete":true,`), 1)
			case "independent_alias_native_tuple":
				raw = bytes.Replace(raw, []byte(`"resource_id":`), []byte(`"ResourceID":`), 1)
			}
			var decoded IndependentReturn
			if closedJSON(raw, &decoded) == nil {
				t.Fatal("independent read accepted a foreign nested source shape")
			}
		})
	}
}

func TestOriginalNativeQEMUMetadataDecoderSeparate(t *testing.T) {
	t.Run("unknown_qmp_metadata_is_read_only_shape", func(t *testing.T) {
		var metadata map[string]json.RawMessage
		if closedJSON([]byte(`{"QMP":{"version":{"qemu":{"major":10}},"capabilities":[]}}`), &metadata) != nil || metadata["QMP"] == nil {
			t.Fatal("QMP transport metadata grammar was confused with a privileged source DTO")
		}
	})
	for _, test := range []struct{ name, raw string }{
		{"map_duplicate_key", `{"QMP":{},"QMP":{}}`},
		{"map_fold_duplicate_key", `{"QMP":{},"qmp":{}}`},
		{"map_nested_fold_duplicate", `{"QMP":{"version":{},"Version":{}}}`},
		{"map_trailing_record", `{"QMP":{}} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var metadata map[string]json.RawMessage
			if closedJSON([]byte(test.raw), &metadata) == nil {
				t.Fatal("ambiguous metadata object accepted")
			}
		})
	}
	t.Run("same_metadata_cannot_decode_privileged_source", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON([]byte(`{"QMP":{"version":{},"capabilities":[]}}`), &decoded) == nil {
			t.Fatal("QMP metadata supplied privileged original create fields")
		}
	})
}
