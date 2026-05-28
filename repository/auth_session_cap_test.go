package repository

import (
	"os"
	"testing"
)

// TestSessionCapForCollaborator_DefaultsTo20 confirms the default cap
// matches the documented value when YGGDRASIL_AUTH_SESSION_CAP is unset.
//
// Audit ref: C4 (42 active sessions per user in production; no cap).
func TestSessionCapForCollaborator_DefaultsTo20(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_SESSION_CAP", "")
	if got := sessionCapForCollaborator(); got != 20 {
		t.Fatalf("expected default cap=20, got %d", got)
	}
}

// TestSessionCapForCollaborator_HonorsEnvOverride verifies env override
// is parsed and applied. Negative / zero / non-numeric values fall back
// to the default so a misconfig doesn't disable the cap.
func TestSessionCapForCollaborator_HonorsEnvOverride(t *testing.T) {
	cases := []struct {
		env  string
		want int
	}{
		{"1", 1},
		{"50", 50},
		{"999", 999},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			t.Setenv("YGGDRASIL_AUTH_SESSION_CAP", c.env)
			if got := sessionCapForCollaborator(); got != c.want {
				t.Fatalf("env=%q expected %d, got %d", c.env, c.want, got)
			}
		})
	}
}

// TestSessionCapForCollaborator_InvalidEnvFallsBackToDefault verifies
// negative / zero / garbage env values fall back to the default.
func TestSessionCapForCollaborator_InvalidEnvFallsBackToDefault(t *testing.T) {
	for _, bad := range []string{"-5", "0", "abc", " "} {
		t.Run(bad, func(t *testing.T) {
			_ = os.Setenv("YGGDRASIL_AUTH_SESSION_CAP", bad)
			defer os.Unsetenv("YGGDRASIL_AUTH_SESSION_CAP")
			if got := sessionCapForCollaborator(); got != 20 {
				t.Fatalf("expected fallback to 20 on bad env %q, got %d", bad, got)
			}
		})
	}
}
