package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testEventPublishToken = "dedicated-event-publish-token"

func setValidProductionBootEnvironment(t *testing.T, environment string) {
	t.Helper()
	t.Setenv("YGGDRASIL_ENV", environment)
	t.Setenv("AUTH_THIRD_PARTY_STATE_SECRET", "real-state-secret-good-strong-len")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "real-csrf-secret-good-strong-len")
	setTestLegacyEventPublishCredential(t, testEventPublishToken)
	t.Setenv(eventPublisherPrincipalsEnv, "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "scoped-workflow-token", "scoped-workflow-test",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))
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

func TestValidateBootSecrets_ProductionRequiresIndependentEventCredential(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")
	t.Setenv(eventPublisherPrincipalsEnv, "")

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production with anonymous event publishing: expected non-nil error")
	}
	for _, name := range []string{"YGGDRASIL_EVENT_PUBLISH_TOKEN", eventPublisherPrincipalsEnv} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error must name %s, got: %v", name, err)
		}
	}
}

func TestValidateBootSecrets_ProductionRejectsWorkflowTokenAsEventCredential(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")
	t.Setenv(eventPublisherPrincipalsEnv, "")
	setTestLegacyWorkflowCredential(t, "legacy-workflow-token")

	if err := validateBootSecrets(); err == nil {
		t.Fatal("production accepted a workflow token as the event-publish credential")
	}
}

func TestValidateBootSecrets_ProductionAcceptsExplicitUnexpiredLegacyEventBridge(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")

	if err := validateBootSecrets(); err != nil {
		t.Fatalf("production with an explicit unexpired legacy event bridge should pass: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsImplicitOrExpiredLegacyEventBridge(t *testing.T) {
	for _, test := range []struct {
		name      string
		enabled   string
		expiresAt string
	}{
		{name: "not explicitly enabled", enabled: "", expiresAt: "2099-01-01T00:00:00Z"},
		{name: "expired", enabled: "true", expiresAt: "2020-01-01T00:00:00Z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setValidProductionBootEnvironment(t, "production")
			t.Setenv(legacyEventPublishEnabledEnv, test.enabled)
			t.Setenv(legacyEventPublishExpiryEnv, test.expiresAt)
			if err := validateBootSecrets(); err == nil {
				t.Fatal("invalid legacy event bridge satisfied production boot")
			}
		})
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
			if test.collidingEnv == "YGGDRASIL_WORKFLOW_RUN_TOKEN" {
				setTestLegacyWorkflowCredential(t, testEventPublishToken)
			} else {
				t.Setenv(test.collidingEnv, testEventPublishToken)
			}

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

func TestValidateBootSecrets_ProductionRejectsEventTokenCollisionWithWorkflowMachinePrincipal(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, testEventPublishToken, "colliding-workflow",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("event token collision with a scoped workflow token: expected non-nil error")
	}
	if !strings.Contains(err.Error(), workflowMachinePrincipalsEnv) {
		t.Fatalf("error must identify the workflow machine-principal collision, got: %v", err)
	}
	if strings.Contains(err.Error(), testEventPublishToken) {
		t.Fatalf("boot error leaked credential value: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsLegacyEventBridgeCollisionWithHashedEventPrincipal(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    string
		expiresAt time.Time
	}{
		{name: "active", status: "active", expiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "revoked", status: "revoked", expiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "expired", status: "active", expiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(test.name, func(t *testing.T) {
			setValidProductionBootEnvironment(t, "production")
			raw, marshalErr := json.Marshal([]eventPublisherPrincipalConfig{{
				PrincipalID: "adapter-aws",
				Status:      test.status,
				ExpiresAt:   test.expiresAt,
				RotationID:  "test-rotation-event-collision",
				TokenSHA256: testTokenSHA256(testEventPublishToken),
				AllowedEvents: []eventPublisherEventRef{{
					Provider:   "aws",
					InstanceID: "aws-primary",
					EventType:  "aws.bucket.ensured",
				}},
			}})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			t.Setenv(eventPublisherPrincipalsEnv, string(raw))

			err := validateBootSecrets()
			if err == nil {
				t.Fatal("legacy event bridge reused by a hashed event principal was accepted")
			}
			for _, name := range []string{eventPublisherPrincipalsEnv, legacyEventPublishTokenEnv} {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("collision error must name %s, got: %v", name, err)
				}
			}
			if strings.Contains(err.Error(), testEventPublishToken) || strings.Contains(err.Error(), testTokenSHA256(testEventPublishToken)) {
				t.Fatalf("boot diagnostic leaked credential material: %v", err)
			}
		})
	}
}

func TestValidateBootSecrets_ProductionFailsClosedOnRawScopedTokenConfig(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(legacyScopedWorkflowTokensEnv, `[{"token":"raw-token"}]`)

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("raw scoped token configuration: expected non-nil error")
	}
	if !strings.Contains(err.Error(), legacyScopedWorkflowTokensEnv) {
		t.Fatalf("error must identify raw scoped token configuration, got: %v", err)
	}
}

func TestValidateBootSecrets_ProductionAcceptsOnlyHashedMachinePrincipals(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "event-machine-token", "adapter-aws"))

	if err := validateBootSecrets(); err != nil {
		t.Fatalf("independent hashed workflow and event principals should boot without global legacy tokens: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsCrossScopeMachineCredentialReuse(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "same-machine-token", "adapter-aws"))
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "same-machine-token", "ci-dakasa",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("cross-scope machine credential reuse was accepted")
	}
	for _, name := range []string{workflowMachinePrincipalsEnv, eventPublisherPrincipalsEnv} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("collision error must name %s, got: %v", name, err)
		}
	}
	if strings.Contains(err.Error(), "same-machine-token") || strings.Contains(err.Error(), testTokenSHA256("same-machine-token")) {
		t.Fatalf("boot diagnostic leaked credential material: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsInvalidMachinePrincipalConfig(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(workflowMachinePrincipalsEnv, `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"`+testTokenSHA256("workflow")+`","allowed_workflows":[{"namespace":"dakasa","name":"*"}]}]`)

	err := validateBootSecrets()
	if err == nil {
		t.Fatal("production boot accepted wildcard workflow allowlist")
	}
	if !strings.Contains(err.Error(), "wildcards") {
		t.Fatalf("boot error did not identify exact-allowlist violation: %v", err)
	}
}

func TestValidateBootSecrets_ProductionAcceptsExplicitUnexpiredLegacyWorkflowBridge(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	setTestLegacyWorkflowCredential(t, "legacy-workflow-test-token")

	if err := validateBootSecrets(); err != nil {
		t.Fatalf("explicit unexpired workflow migration bridge rejected: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsExpiredLegacyAsOnlyWorkflowCredential(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	setTestLegacyWorkflowCredential(t, "legacy-workflow-test-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "2020-01-01T00:00:00Z")

	if err := validateBootSecrets(); err == nil {
		t.Fatal("expired legacy workflow bridge satisfied production boot")
	}
}
