package httpapi

import (
	"strings"
	"testing"
)

const testEventPublishToken = "dedicated-event-publish-token"

func setValidProductionBootEnvironment(t *testing.T, environment string) {
	t.Helper()
	t.Setenv("YGGDRASIL_ENV", environment)
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "real-state-secret-good-strong-len")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "real-csrf-secret-good-strong-len")
	t.Setenv("YGGDRASIL_EVENT_PUBLISH_TOKEN", testEventPublishToken)
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "legacy-workflow-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"scoped-workflow-token","subject":{"type":"service","id":"scoped-workflow-test"}}]`)
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "deploy-token")
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "auth-admin-token")
}

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
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "")
	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with empty AUTH_THIRD_PARTY_STATE_SECRET: expected non-nil error")
	}
	if !strings.Contains(err.Error(), "AUTH_THIRD_PARTY_STATE_SECRET") {
		t.Fatalf("error must name the missing var, got: %v", err)
	}
}

func TestValidateBootSecrets_ProductionFailsOnMissingCSRFSecret(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
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
	setValidProductionBootEnvironment(t, "production")
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
	setValidProductionBootEnvironment(t, "production")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("production with valid security configuration: expected nil, got %v", err)
	}
}

func TestValidateBootSecrets_ProductionPassesProdAlias(t *testing.T) {
	// `prod` is an accepted alias of `production` to match common ops shorthand.
	setValidProductionBootEnvironment(t, "prod")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("prod alias with valid security configuration: expected nil, got %v", err)
	}
}

func TestValidateBootSecrets_ProductionRequiresEventOrLegacyToken(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("YGGDRASIL_EVENT_PUBLISH_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with anonymous event publishing: expected non-nil error")
	}
	for _, name := range []string{"YGGDRASIL_EVENT_PUBLISH_TOKEN", "YGGDRASIL_WORKFLOW_RUN_TOKEN"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error must name %s, got: %v", name, err)
		}
	}
}

func TestValidateBootSecrets_ProductionKeepsLegacyEventTokenCompatibility(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("YGGDRASIL_EVENT_PUBLISH_TOKEN", "")

	if err := validateBootSecrets(); err != nil {
		t.Fatalf("production with only the legacy workflow token should remain compatible: %v", err)
	}
}

func TestValidateBootSecrets_ProductionAcceptsDedicatedEventTokenWithoutLegacy(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	if err := validateBootSecrets(); err != nil {
		t.Fatalf("production with a dedicated event token should pass: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsEventTokenCollisions(t *testing.T) {
	tests := []struct {
		name          string
		collidingEnv  string
		expectedIssue string
	}{
		{name: "legacy workflow", collidingEnv: "YGGDRASIL_WORKFLOW_RUN_TOKEN", expectedIssue: "YGGDRASIL_WORKFLOW_RUN_TOKEN"},
		{name: "deploy", collidingEnv: "YGGDRASIL_DEPLOY_TOKEN", expectedIssue: "YGGDRASIL_DEPLOY_TOKEN"},
		{name: "auth admin", collidingEnv: "YGGDRASIL_AUTH_ADMIN_TOKEN", expectedIssue: "YGGDRASIL_AUTH_ADMIN_TOKEN"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidProductionBootEnvironment(t, "production")
			t.Setenv(test.collidingEnv, testEventPublishToken)

			err := validateBootSecrets()
			if err == nil {
				t.Fatalf("event token collision with %s: expected non-nil error", test.collidingEnv)
			}
			if !strings.Contains(err.Error(), test.expectedIssue) {
				t.Fatalf("error must name colliding credential %s, got: %v", test.expectedIssue, err)
			}
			if strings.Contains(err.Error(), testEventPublishToken) {
				t.Fatalf("boot error leaked credential value: %v", err)
			}
		})
	}
}

func TestValidateBootSecrets_ProductionRejectsEventTokenCollisionWithScopedWorkflowToken(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"dedicated-event-publish-token","subject":{"type":"service","id":"colliding-workflow"}}]`)

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("event token collision with a scoped workflow token: expected non-nil error")
	}
	if !strings.Contains(err.Error(), "scoped workflow token") {
		t.Fatalf("error must identify the scoped workflow collision, got: %v", err)
	}
	if strings.Contains(err.Error(), testEventPublishToken) {
		t.Fatalf("boot error leaked credential value: %v", err)
	}
}

func TestValidateBootSecrets_ProductionFailsClosedOnMalformedScopedTokenConfig(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", "not-json")

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("malformed scoped token configuration: expected non-nil error")
	}
	if !strings.Contains(err.Error(), "YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON") {
		t.Fatalf("error must identify malformed scoped token configuration, got: %v", err)
	}
}
