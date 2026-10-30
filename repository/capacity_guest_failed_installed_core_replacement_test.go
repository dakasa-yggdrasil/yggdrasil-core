package repository

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
)

func coreReplacementStorageMarker() FailedInstalledGuestDisposal {
	return FailedInstalledGuestDisposal{RetirementMode: failedInstalledV2Mode,
		ReplacementMode:                FailedInstalledCoreReplacementMode,
		OriginalFailedIssuerCoreSource: strings.Repeat("a", 40),
		ReplacementCoreSource:          strings.Repeat("b", 40), ActualCoreSource: strings.Repeat("b", 40),
		BlockedGuestSource: strings.Repeat("c", 40), BlockedProfileSHA256: strings.Repeat("d", 64)}
}

// Pure structural eligibility only. The production caller ALSO requires the
// compiled complete-contract approval, actual requested+terminal ledger and V2.
func TestFailedInstalledCoreReplacementIsExplicitAndBuildBound(t *testing.T) {
	r := coreReplacementStorageMarker()
	b := &model.CapacityGuestRetirementBinding{GuestSourceCommit: r.BlockedGuestSource, ProfileManifestSHA256: r.BlockedProfileSHA256,
		ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: "notify-hetzner-elastic"}}
	if !failedInstalledReplacementPermitted(b, r, r.ReplacementCoreSource) {
		t.Fatal("explicit same-profile exact-Core predicate")
	}
	for _, name := range []string{"legacy_empty", "partial", "unknown_mode", "same_Core", "foreign_current_Core", "different_recorded_request_Core", "legacy_retirement", "changed_only_Guest", "changed_only_profile", "wrong_provider"} {
		t.Run(name, func(t *testing.T) {
			x, y, current := r, *b, r.ReplacementCoreSource
			switch name {
			case "legacy_empty":
				x.ReplacementMode = ""
				x.OriginalFailedIssuerCoreSource = ""
				x.ReplacementCoreSource = ""
			case "partial":
				x.OriginalFailedIssuerCoreSource = ""
			case "unknown_mode":
				x.ReplacementMode = "any_new_Core"
			case "same_Core":
				x.OriginalFailedIssuerCoreSource = x.ReplacementCoreSource
			case "foreign_current_Core":
				current = strings.Repeat("e", 40)
			case "different_recorded_request_Core":
				x.ActualCoreSource = strings.Repeat("e", 40)
			case "legacy_retirement":
				x.RetirementMode = failedInstalledLegacyV1Mode
			case "changed_only_Guest":
				y.GuestSourceCommit = strings.Repeat("e", 40)
			case "changed_only_profile":
				y.ProfileManifestSHA256 = strings.Repeat("e", 64)
			case "wrong_provider":
				y.ProfileManifest.Profile = "notify-aws-elastic"
			}
			if failedInstalledReplacementPermitted(&y, x, current) {
				t.Fatal("unbounded or legacy same-profile replacement")
			}
		})
	}
	old := r
	old.ReplacementMode = ""
	old.OriginalFailedIssuerCoreSource = ""
	old.ReplacementCoreSource = ""
	both := *b
	both.GuestSourceCommit = strings.Repeat("e", 40)
	both.ProfileManifestSHA256 = strings.Repeat("f", 64)
	if !failedInstalledReplacementPermitted(&both, old, strings.Repeat("e", 40)) {
		t.Fatal("old both-changed route lost")
	}
	raw, _ := json.Marshal(old)
	if strings.Contains(string(raw), "replacement_mode") || strings.Contains(string(raw), "original_failed_issuer_core_source") || strings.Contains(string(raw), "replacement_core_source") {
		t.Fatal("old wire retrofilled")
	}
	var decoded FailedInstalledGuestDisposal
	if decodeFailedInstalledDisposal(raw, &decoded) != nil {
		t.Fatal("old canonical wire changed")
	}
}

func TestFailedInstalledCoreReplacementRequiresOriginalCanaryFailure(t *testing.T) {
	good := []byte(`{"steps":[{"id":"complete-original-provision","status":"failed","metadata":{"original_guest_reconcile_refusal_stage":"fresh_original_canary"}}]}`)
	if !failedInstalledOriginalCanaryFailure(good) {
		t.Fatal("closed original stage")
	}
	for _, raw := range []string{`{}`, `null`, string(good) + `{}`, strings.Replace(string(good), "fresh_original_canary", "installed_resume_claim", 1), strings.Replace(string(good), "failed", "succeeded", 1)} {
		if failedInstalledOriginalCanaryFailure([]byte(raw)) {
			t.Fatal("foreign or malformed stage")
		}
	}
}
