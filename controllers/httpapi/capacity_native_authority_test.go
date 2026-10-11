package httpapi

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapacityNativeAuthorityLiteralClosedJSON(t *testing.T) {
	valid := `{"authority_token":"opaque","integration_instance_id":"instance","integration_type_id":"type","capability":"ensure_capacity_pod_drain","request_sha256":"digest"}`
	for _, mode := range []string{"exact", "case_alias", "unicode_alias", "duplicate", "missing", "unknown"} {
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
			}
			var out model.CapacityNativeAuthorityRedeemRequest
			err := decodeCapacityNativeAuthorityJSON(httptest.NewRecorder(), httptest.NewRequest("POST", capacityMutationBasePath+"/native/redeem", strings.NewReader(raw)), &out)
			if (mode == "exact") != (err == nil) {
				t.Fatal("native authority schema mismatch", mode, err)
			}
		})
	}
}
