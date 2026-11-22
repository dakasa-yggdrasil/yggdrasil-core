package message

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCapacityNativeAbortUnredeemedRecoveryPrivateWire(t *testing.T) {
	t.Run("complete_history_and_issued_credential_only", func(t *testing.T) {
		issued, forged := strings.Repeat("a", 64), strings.Repeat("b", 64)
		no := false
		request := model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest{AuthorityToken: forged, ExpectedPodUID: "fixture-only", ExpectedPodResourceVersion: "10", DryRun: &no, Proof: model.CapacityNativeAbortRecoveryProof{Schema: capacity.NativePreRegistrationAbortRecoverySchema, History: model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, ArchivedCommands: 1}}}
		fields, err := nativeAbortPrivateInput(capacity.DestroyNativeUnregisteredProtection, request, issued)
		if err != nil || fields["authority_token"] != issued {
			t.Fatal("fresh issued permission did not cross the recovery boundary")
		}
		defer delete(fields, "authority_token")
		proof := fields["proof"].(map[string]any)
		if _, legacy := proof["zero_history"]; legacy || proof["history"].(map[string]any)["command_identities"] != float64(1) || proof["history"].(map[string]any)["archived_commands"] != float64(1) {
			t.Fatal("recovery history was concealed at the private wire")
		}
		if receipt, present := proof["observation"].(map[string]any)["receipt"]; !present || receipt != nil {
			t.Fatal("absent SDK receipt was omitted or fabricated")
		}
		raw, err := json.Marshal(fields)
		if err != nil || strings.Contains(string(raw), forged) {
			t.Fatal("caller credential entered the private wire")
		}
		request.AuthorityToken = ""
		canonical, err := json.Marshal(request)
		if err != nil || strings.Contains(string(canonical), issued) || strings.Contains(string(canonical), forged) || strings.Contains(string(canonical), "authority_token") {
			t.Fatal("private permission entered the retained recovery request")
		}
	})
	t.Run("closed_public_input", func(t *testing.T) {
		var in capacityNativeAbortRecoveryStepInput
		if capacity.DecodeNativeCapacity(map[string]any{"binding": map[string]any{}, "confirmation": "fixed", "authority_token": strings.Repeat("c", 64)}, &in) == nil {
			t.Fatal("public input supplied a private recovery permission")
		}
	})
}
