//go:build nativequalification

package contracts

import "testing"

func TestNativeQualificationMutationEventVersion(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				version string
				valid   bool
			}{
				{"empty_defaults_v1", "", true},
				{"v2_denied", "v2", false},
				{"unknown_denied", "bogus", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					err := ValidateEventPayload("native-qemu.server."+verb, tc.version, nativeQualificationEventPayload(verb))
					if (err == nil) != tc.valid {
						t.Fatalf("version=%q, valid=%v, validation error=%v", tc.version, tc.valid, err)
					}
				})
			}
		})
	}
}

func TestNativeQualificationMutationEventPayload(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			eventType := "native-qemu.server." + verb
			if !IsNativeQualificationMutationEvent(eventType) {
				t.Fatal("fixed qualification event missing from classifier")
			}
			otherVerb := "ensured"
			if verb == otherVerb {
				otherVerb = "destroyed"
			}
			cases := []struct {
				name   string
				change func(map[string]interface{})
				valid  bool
			}{
				{"valid", func(map[string]interface{}) {}, true},
				{"provider_mismatch", func(p map[string]interface{}) { p["provider"] = "native_qemu" }, false},
				{"resource_mismatch", func(p map[string]interface{}) { p["resource"] = "volume" }, false},
				{"verb_mismatch", func(p map[string]interface{}) { p["verb"] = otherVerb }, false},
				{"missing_provider", func(p map[string]interface{}) { delete(p, "provider") }, false},
				{"missing_resource", func(p map[string]interface{}) { delete(p, "resource") }, false},
				{"missing_verb", func(p map[string]interface{}) { delete(p, "verb") }, false},
				{"missing_resource_id", func(p map[string]interface{}) { delete(p, "resource_id") }, false},
				{"missing_instance_id", func(p map[string]interface{}) { delete(p, "instance_id") }, false},
				{"empty_resource_id", func(p map[string]interface{}) { p["resource_id"] = "" }, false},
				{"empty_instance_id", func(p map[string]interface{}) { p["instance_id"] = "" }, false},
				{"unknown_field", func(p map[string]interface{}) { p["unknown"] = true }, false},
				{"observed_not_object", func(p map[string]interface{}) { p["observed"] = "invalid" }, false},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					payload := nativeQualificationEventPayload(verb)
					tc.change(payload)
					err := ValidateEventPayload(eventType, "v1", payload)
					if (err == nil) != tc.valid {
						t.Fatalf("valid=%v, validation error=%v", tc.valid, err)
					}
				})
			}
		})
	}
}
