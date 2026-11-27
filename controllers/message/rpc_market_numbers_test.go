package message

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestProtectedMarketRPCPreservesIntegerQuantities(t *testing.T) {
	const original = `{"operation":"observe_compute_offer","capability":"observe_compute_offer","status":"observed","output":{"price_micros":9007199254740993,"byte_seconds":4611686018427387903}}`
	for _, body := range []string{original, `{"ok":true,"data":` + original + `}`} {
		var reply model.AdapterExecuteIntegrationResponse
		policy := adapterCallPolicy{detailFreeErrors: true, exactJSONNumbers: true}
		if err := decodeRPCBodyWithPolicy([]byte(body), &reply, policy); err != nil {
			t.Fatal(err)
		}
		values, ok := reply.Output.(map[string]any)
		if !ok {
			t.Fatal("execute output is not an object")
		}
		if number, ok := values["price_micros"].(json.Number); !ok || number.String() != "9007199254740993" {
			t.Fatal("protected RPC rounded the original price before semantic validation")
		}
		var typed struct {
			PriceMicros int64 `json:"price_micros"`
			ByteSeconds int64 `json:"byte_seconds"`
		}
		if err := capacity.DecodeNativeCapacity(reply.Output, &typed); err != nil {
			t.Fatal(err)
		}
		if typed.PriceMicros != 9007199254740993 || typed.ByteSeconds != 4611686018427387903 {
			t.Fatal("protected RPC did not preserve the original integer billing quantities")
		}
	}
}

func TestProtectedMarketRPCRejectsOriginalDuplicateMembers(t *testing.T) {
	for _, output := range []string{
		`{"price_micros":1,"price_micros":2}`,
		`{"price_micros":1,"PRICE_MICROS":2}`,
	} {
		original := `{"status":"observed","output":` + output + `}`
		for _, body := range []string{original, `{"ok":true,"data":` + original + `}`} {
			var reply model.AdapterExecuteIntegrationResponse
			if err := decodeRPCBodyWithPolicy([]byte(body), &reply, adapterCallPolicy{detailFreeErrors: true, exactJSONNumbers: true}); err == nil {
				t.Fatal("generic RPC map erased duplicate billing members before validation")
			}
		}
	}
}

func TestLegacyRPCNumericRepresentationRemainsUnchanged(t *testing.T) {
	var reply model.AdapterExecuteIntegrationResponse
	if err := decodeRPCBodyWithPolicy([]byte(`{"status":"succeeded","output":{"value":42}}`), &reply, adapterCallPolicy{detailFreeErrors: true}); err != nil {
		t.Fatal(err)
	}
	values, ok := reply.Output.(map[string]any)
	if !ok {
		t.Fatal("legacy output is not an object")
	}
	if number, ok := values["value"].(float64); !ok || number != 42 {
		t.Fatal("protected market opt-in changed legacy numeric representation")
	}
}
