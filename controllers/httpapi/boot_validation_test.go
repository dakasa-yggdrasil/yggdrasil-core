package httpapi

import (
	"strings"
	"testing"
)

// Audit 2026-05-27 A12: production boots MUST fail loud when
// security-critical env vars are missing.  Non-production envs keep
// the dev fallbacks intact so local dev / CI works without ceremony.

func TestValidateBootSecrets_NonProductionSkipsCheck(t *testing.T) {
	// Default YGGDRASIL_ENV (unset / "dev" / "test") — fallbacks allowed.
	t.Setenv("YGGDRASIL_ENV", "")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("non-production with empty secrets: expected nil error, got %v", err)
	}
}

func TestValidateBootSecrets_DevExplicitSkipsCheck(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "dev")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("dev with empty secrets: expected nil error, got %v", err)
	}
}

func TestValidateBootSecrets_ProductionFailsOnMissingStateSecret(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "production")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "some-real-secret-32-bytes-here-ok")
	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with empty AUTH_THIRD_PARTY_STATE_SECRET: expected non-nil error")
	}
	if !strings.Contains(err.Error(), "AUTH_THIRD_PARTY_STATE_SECRET") {
		t.Fatalf("error must name the missing var, got: %v", err)
	}
}

func TestValidateBootSecrets_ProductionFailsOnMissingCSRFSecret(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "production")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "some-real-secret-32-bytes-here-ok")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "")
	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with empty YGGDRASIL_CSRF_HMAC_SECRET: expected non-nil error")
	}
	if !strings.Contains(err.Error(), "YGGDRASIL_CSRF_HMAC_SECRET") {
		t.Fatalf("error must name the missing var, got: %v", err)
	}
}

func TestValidateBootSecrets_ProductionListsAllMissing(t *testing.T) {
	// Operator should see EVERY missing var in one boot failure, not
	// have to fix one, redeploy, discover the next.
	t.Setenv("YGGDRASIL_ENV", "production")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "")
	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with both missing: expected non-nil error")
	}
	for _, name := range []string{"AUTH_THIRD_PARTY_STATE_SECRET", "YGGDRASIL_CSRF_HMAC_SECRET"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error must list %s in batch report, got: %v", name, err)
		}
	}
}

func TestValidateBootSecrets_ProductionPassesWithAllSet(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "production")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "real-state-secret-good-strong-len")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "real-csrf-secret-good-strong-len")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("production with both set: expected nil, got %v", err)
	}
}

func TestValidateBootSecrets_ProductionPassesProdAlias(t *testing.T) {
	// `prod` is an accepted alias of `production` to match common ops shorthand.
	t.Setenv("YGGDRASIL_ENV", "prod")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "real-state-secret-good-strong-len")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "real-csrf-secret-good-strong-len")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("prod alias with both set: expected nil, got %v", err)
	}
}
