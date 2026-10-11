package httpapi

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeAuthorityOpenAPIMirrorsClosedActualWire(t *testing.T) {
	other, err := os.ReadFile("../../docs/api-reference/openapi.json")
	if err != nil || !bytes.Equal(other, openapiBundle) {
		t.Fatal("served and documented native authority contracts differ")
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required             []string                   `json:"required"`
				Properties           map[string]json.RawMessage `json:"properties"`
				AdditionalProperties bool                       `json:"additionalProperties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(openapiBundle, &spec) != nil {
		t.Fatal("bundled OpenAPI unavailable")
	}
	for name, value := range map[string]any{"CapacityNativeAuthorityRedeemRequest": model.CapacityNativeAuthorityRedeemRequest{}, "CapacityNativeAuthorityPermit": model.CapacityNativeAuthorityPermit{}} {
		schema, ok := spec.Components.Schemas[name]
		typ := reflect.TypeOf(value)
		if !ok || schema.AdditionalProperties || len(schema.Required) != typ.NumField() || len(schema.Properties) != typ.NumField() {
			t.Fatal("native closed schema field count differs", name)
		}
		for i := 0; i < typ.NumField(); i++ {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if schema.Properties[tag] == nil {
				t.Fatal("actual native wire field missing", tag)
			}
			found := false
			for _, required := range schema.Required {
				found = found || required == tag
			}
			if !found {
				t.Fatal("actual native wire field optional", tag)
			}
		}
	}
	responses := spec.Paths[capacityMutationBasePath+"/native/redeem"]["post"].Responses
	for _, status := range []string{"200", "400", "401", "403", "409", "503"} {
		if responses[status] == nil {
			t.Fatal("native authority status undocumented", status)
		}
	}
}
