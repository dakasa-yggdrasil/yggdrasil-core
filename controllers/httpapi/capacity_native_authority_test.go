package httpapi

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapacityNativeAuthorityLiteralClosedJSON(t *testing.T) {
	valid := `{"authority_token":"opaque","integration_instance_id":"instance","integration_type_id":"type","capability":"ensure_capacity_pod_drain","request_sha256":"digest"}`
	const pair = `,"release_protocol":"native_release_result_v1","adapter_source_commit":"source"}`
	for _, mode := range []string{"exact", "case_alias", "unicode_alias", "duplicate", "missing", "unknown", "release_pair", "release_protocol_only", "release_source_only", "release_pair_null"} {
		t.Run(mode, func(t *testing.T) {
			raw := valid
			switch mode {
			case "case_alias":
				raw = strings.Replace(raw, "authority_token", "AUTHORITY_TOKEN", 1)
			case "unicode_alias":
				raw = strings.Replace(raw, "request_sha256", "requeſt_sha256", 1)
			case "duplicate":
				raw = strings.Replace(raw, `"authority_token":"opaque"`, `"authority_token":"opaque","authority_token":"opaque"`, 1)
			case "missing":
				raw = strings.Replace(raw, `"authority_token":"opaque",`, "", 1)
			case "unknown":
				raw = strings.Replace(raw, "{", `{"receipt":true,`, 1)
			case "release_pair":
				raw = strings.TrimSuffix(raw, "}") + pair
			case "release_protocol_only":
				raw = strings.TrimSuffix(raw, "}") + `,"release_protocol":"native_release_result_v1"}`
			case "release_source_only":
				raw = strings.TrimSuffix(raw, "}") + `,"adapter_source_commit":"source"}`
			case "release_pair_null":
				raw = strings.TrimSuffix(raw, "}") + `,"release_protocol":null,"adapter_source_commit":"source"}`
			}
			var out model.CapacityNativeAuthorityRedeemRequest
			err := decodeCapacityNativeAuthorityJSON(httptest.NewRecorder(), httptest.NewRequest("POST", capacityMutationBasePath+"/native/redeem", strings.NewReader(raw)), &out)
			if (mode == "exact" || mode == "release_pair") != (err == nil) {
				t.Fatal("native authority schema mismatch", mode, err)
			}
			// The optional pair is one all-or-none binding, never one alone or a
			// default value supplied by the decoder.
			if mode == "exact" && (out.ReleaseProtocol != "" || out.AdapterSourceCommit != "") {
				t.Fatal("unbound native authority acquired a release binding")
			}
			if mode == "release_pair" && (out.ReleaseProtocol != "native_release_result_v1" || out.AdapterSourceCommit != "source" || out.AuthorityToken != "opaque") {
				t.Fatal("release-bound native authority lost its exact pair")
			}
		})
	}
}
