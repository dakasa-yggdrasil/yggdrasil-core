//go:build !nativequalification

package contracts

import "testing"

func TestNativeQualificationMutationEventDefaultDenied(t *testing.T) {
	for _, verb := range []string{"ensured", "destroyed"} {
		t.Run(verb, func(t *testing.T) {
			eventType := "native-qemu.server." + verb
			if IsNativeQualificationMutationEvent(eventType) {
				t.Fatal("default build classified a qualification event")
			}
			if err := ValidateEventPayload(eventType, "v1", nativeQualificationEventPayload(verb)); err == nil {
				t.Fatal("default build accepted a qualification event")
			}
			if _, err := readEventSchemaFile("events/v1/native_qualification/server_" + verb + ".json"); err == nil {
				t.Fatal("default build embedded a qualification schema")
			}
		})
	}
}
