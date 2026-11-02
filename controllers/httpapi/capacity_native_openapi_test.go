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
	type requiredMembers struct {
		Required []string `json:"required"`
	}
	var spec struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required             []string                   `json:"required"`
				Properties           map[string]json.RawMessage `json:"properties"`
				AdditionalProperties bool                       `json:"additionalProperties"`
				AnyOf                []struct {
					Required []string `json:"required"`
					Not      *struct {
						AnyOf []requiredMembers `json:"anyOf"`
					} `json:"not"`
				} `json:"anyOf"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(openapiBundle, &spec) != nil {
		t.Fatal("bundled OpenAPI unavailable")
	}
	sameMembers := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		left := map[string]int{}
		for _, name := range want {
			left[name]++
		}
		for _, name := range got {
			if left[name] == 0 {
				return false
			}
			left[name]--
		}
		return true
	}
	// Every member without omitempty is required. omitempty members are one
	// all-or-none group on the actual wire: documented, never required alone
	// and never splittable (the release binding pair and its bound permit).
	for name, value := range map[string]any{"CapacityNativeAuthorityRedeemRequest": model.CapacityNativeAuthorityRedeemRequest{}, "CapacityNativeAuthorityPermit": model.CapacityNativeAuthorityPermit{}, "CapacityNativeReleaseResult": model.CapacityNativeReleaseResult{}} {
		schema, ok := spec.Components.Schemas[name]
		typ := reflect.TypeOf(value)
		mandatory, optional := []string{}, []string{}
		for i := 0; i < typ.NumField(); i++ {
			parts := strings.Split(typ.Field(i).Tag.Get("json"), ",")
			omitted := false
			for _, option := range parts[1:] {
				omitted = omitted || option == "omitempty"
			}
			if omitted {
				optional = append(optional, parts[0])
			} else {
				mandatory = append(mandatory, parts[0])
			}
		}
		if !ok || schema.AdditionalProperties || len(schema.Properties) != typ.NumField() || !sameMembers(schema.Required, mandatory) {
			t.Fatal("native closed schema field count differs", name)
		}
		for _, tag := range append(append([]string{}, mandatory...), optional...) {
			if schema.Properties[tag] == nil {
				t.Fatal("actual native wire field missing", tag)
			}
		}
		if len(optional) == 0 {
			if len(schema.AnyOf) != 0 {
				t.Fatal("closed native schema invents an optional group", name)
			}
			continue
		}
		if len(schema.AnyOf) != 2 || schema.AnyOf[0].Not == nil || len(schema.AnyOf[0].Required) != 0 || schema.AnyOf[1].Not != nil || !sameMembers(schema.AnyOf[1].Required, optional) || len(schema.AnyOf[0].Not.AnyOf) != len(optional) {
			t.Fatal("optional native members are not one all-or-none group", name)
		}
		single := []string{}
		for _, branch := range schema.AnyOf[0].Not.AnyOf {
			if len(branch.Required) != 1 {
				t.Fatal("optional native member absence is not member-exact", name)
			}
			single = append(single, branch.Required[0])
		}
		if !sameMembers(single, optional) {
			t.Fatal("optional native member absence differs from actual wire", name)
		}
	}
	for path, route := range map[string]string{
		capacityMutationBasePath + "/native/redeem": "CapacityNativeAuthorityRedeemRequest",
		capacityMutationBasePath + "/native/result": "CapacityNativeReleaseResult",
	} {
		post := spec.Paths[path]["post"]
		if post.RequestBody.Content["application/json"].Schema.Ref != "#/components/schemas/"+route {
			t.Fatal("native route request is not its closed actual wire", path)
		}
		for _, status := range []string{"200", "400", "401", "403", "409", "503"} {
			if post.Responses[status] == nil {
				t.Fatal("native authority status undocumented", path, status)
			}
		}
	}
}
