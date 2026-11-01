package repository

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFallbackReadNewWireHoldsMutatingDecoder(t *testing.T) {
	old := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", RetirementMode: failedInstalledV2Mode, ActualCoreSource: strings.Repeat("a", 40), BusinessEffectsPreserved: true}
	current := FailedInstalledDisposalRead{ReplacementMode: "original_canary_core_bound_v1", OriginalFailedIssuerCoreSource: strings.Repeat("b", 40), ReplacementCoreSource: old.ActualCoreSource, FailedInstalledGuestDisposal: old}
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFailedInstalledDisposalRead(raw)
	if err != nil || got.ReplacementMode != current.ReplacementMode || got.ReplacementCoreSource != old.ActualCoreSource {
		t.Fatal("compatible read", err)
	}
	var mutation FailedInstalledGuestDisposal
	if decodeFailedInstalledDisposal(raw, &mutation) == nil {
		t.Fatal("new wire allowed on old mutating decoder")
	}
	legacy, _ := json.Marshal(old)
	if _, err := decodeFailedInstalledDisposalRead(legacy); err != nil {
		t.Fatal("legacy read", err)
	}
	for name, bad := range map[string]string{
		"unknown":           strings.Replace(string(raw), `"replacement_mode":`, `"unknown":1,"replacement_mode":`, 1),
		"duplicate":         strings.Replace(string(raw), `"replacement_mode":`, `"replacement_mode":"original_canary_core_bound_v1","replacement_mode":`, 1),
		"wrong_mode":        strings.Replace(string(raw), "original_canary_core_bound_v1", "unsupported", 1),
		"same_source":       strings.Replace(string(raw), strings.Repeat("b", 40), strings.Repeat("a", 40), 1),
		"wrong_replacement": strings.Replace(string(raw), `"replacement_core_source":"`+strings.Repeat("a", 40), `"replacement_core_source":"`+strings.Repeat("c", 40), 1),
		"trailing":          string(raw) + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFailedInstalledDisposalRead([]byte(bad)); err == nil {
				t.Fatal("accepted malformed wire")
			}
		})
	}
}
