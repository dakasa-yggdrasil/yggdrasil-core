package message

import (
	"testing"
	"time"
)

func TestMFAEnrolledFromObservedState_GoogleWorkspaceTrue(t *testing.T) {
	got := mfaEnrolledFromObservedState("google-workspace", map[string]any{
		"isEnrolledIn2Sv": true,
		"primaryEmail":    "g@dakasa.me",
	})
	if !got {
		t.Fatal("expected true for google-workspace.isEnrolledIn2Sv=true")
	}
}

func TestMFAEnrolledFromObservedState_GoogleWorkspaceFalseOrMissing(t *testing.T) {
	cases := []struct {
		name string
		obs  map[string]any
	}{
		{"false", map[string]any{"isEnrolledIn2Sv": false}},
		{"missing", map[string]any{"primaryEmail": "g@dakasa.me"}},
		{"nil", nil},
		{"wrong type", map[string]any{"isEnrolledIn2Sv": "true"}}, // string, not bool
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if mfaEnrolledFromObservedState("google-workspace", tc.obs) {
				t.Fatalf("expected false, got true for %v", tc.obs)
			}
		})
	}
}

func TestMFAEnrolledFromObservedState_SlackHas2FA(t *testing.T) {
	if !mfaEnrolledFromObservedState("slack", map[string]any{"has_2fa": true}) {
		t.Fatal("expected true for slack.has_2fa=true")
	}
	if mfaEnrolledFromObservedState("slack", map[string]any{}) {
		t.Fatal("expected false when slack.has_2fa missing")
	}
}

func TestMFAEnrolledFromObservedState_UnknownProviderReturnsFalse(t *testing.T) {
	// Provider we have not mapped yet — must NOT guess. Returning false on
	// unknown providers is what protects "Sem registro" from becoming a
	// false-positive "Informada como ativa".
	if mfaEnrolledFromObservedState("github", map[string]any{"two_factor_authentication": true}) {
		t.Fatal("expected false for unknown provider, even when observed has plausible key")
	}
}

func TestTraitsMFAEnrolledAlreadySet_RecognizesNonEmptyValues(t *testing.T) {
	cases := []struct {
		name   string
		traits map[string]any
		want   bool
	}{
		{"nil traits", nil, false},
		{"empty map", map[string]any{}, false},
		{"missing key", map[string]any{"other": "value"}, false},
		{"empty string", map[string]any{"mfa_enrolled_at": ""}, false},
		{"whitespace string", map[string]any{"mfa_enrolled_at": "   "}, false},
		{"valid rfc3339", map[string]any{"mfa_enrolled_at": "2026-05-14T22:00:00Z"}, true},
		{"time.Time zero", map[string]any{"mfa_enrolled_at": time.Time{}}, false},
		{"time.Time non-zero", map[string]any{"mfa_enrolled_at": time.Now().UTC()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := traitsMFAEnrolledAlreadySet(tc.traits); got != tc.want {
				t.Fatalf("got %v want %v for %v", got, tc.want, tc.traits)
			}
		})
	}
}

func TestCloneTraitsWithMFA_PreservesExistingKeys(t *testing.T) {
	in := map[string]any{
		"tartaro_roles":  []string{"admin"},
		"provider_groups": []string{"diretoria@dakasa.me"},
	}
	when := time.Date(2026, 5, 14, 22, 35, 0, 0, time.UTC)
	out := cloneTraitsWithMFA(in, when)
	if out["mfa_enrolled_at"] != "2026-05-14T22:35:00Z" {
		t.Fatalf("mfa_enrolled_at = %v, want RFC3339 of when", out["mfa_enrolled_at"])
	}
	if _, ok := out["tartaro_roles"]; !ok {
		t.Fatal("tartaro_roles dropped during clone")
	}
	if _, ok := out["provider_groups"]; !ok {
		t.Fatal("provider_groups dropped during clone")
	}
	// Verify it's a new map — adding to input must not affect output.
	in["new_key"] = "new_value"
	if _, ok := out["new_key"]; ok {
		t.Fatal("output shares map with input — should be a separate map")
	}
}
