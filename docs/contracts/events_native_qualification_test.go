package contracts

import "testing"

// These payloads test the event contract only; they carry no native proof.
func nativeQualificationEventPayload(verb string) map[string]interface{} {
	return map[string]interface{}{
		"provider":    "native-qemu",
		"resource":    "server",
		"verb":        verb,
		"resource_id": "qualification-server",
		"instance_id": "qualification-instance",
		"observed":    map[string]interface{}{"receipt_ref": "contract-only"},
		"emitted_at":  "2026-10-20T00:30:17Z",
	}
}

func TestNativeQualificationMutationEventRejectsVariants(t *testing.T) {
	for _, eventType := range []string{
		"native-qemu.server.created",
		"native-qemu.volume.ensured",
		"native-qemu.volume.destroyed",
		"native-qemu2.server.ensured",
		"other-qemu.server.ensured",
		"Native-qemu.server.ensured",
		"native-qemu.Server.ensured",
		"native-qemu.server.Ensured",
		"native-qemu.server.ensure",
		"native-qemu.server.ensured.extra",
		"native-qemu.server.destroyed.extra",
	} {
		t.Run(eventType, func(t *testing.T) {
			if IsNativeQualificationMutationEvent(eventType) {
				t.Fatal("variant classified as a fixed qualification event")
			}
			if err := ValidateEventPayload(eventType, "v1", nativeQualificationEventPayload("ensured")); err == nil {
				t.Fatal("variant event type accepted")
			}
		})
	}
}

func TestNativeQualificationMutationEventGenericContractPreserved(t *testing.T) {
	t.Run("generic_valid", func(t *testing.T) {
		payload := nativeQualificationEventPayload("ensured")
		payload["provider"], payload["resource"] = "stripe", "customer"
		if IsNativeQualificationMutationEvent("stripe.customer.ensured") {
			t.Fatal("generic event classified as qualification vocabulary")
		}
		if err := ValidateEventPayload("stripe.customer.ensured", "v1", payload); err != nil {
			t.Fatalf("generic contract changed: %v", err)
		}
	})
	t.Run("generic_hyphen_payload_denied", func(t *testing.T) {
		if err := ValidateEventPayload("stripe.server.ensured", "v1", nativeQualificationEventPayload("ensured")); err == nil {
			t.Fatal("generic schema admitted the hyphenated qualification provider")
		}
	})
}
