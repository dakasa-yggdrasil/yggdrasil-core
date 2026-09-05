package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func testTokenSHA256(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func testWorkflowMachinePrincipalsJSON(t *testing.T, token, principalID string, workflows ...machineWorkflowRef) string {
	t.Helper()
	raw, err := json.Marshal([]workflowMachinePrincipalConfig{{
		PrincipalID:      principalID,
		Status:           "active",
		ExpiresAt:        time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		RotationID:       "test-rotation-workflow-1",
		RotatedAt:        time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
		TokenSHA256:      testTokenSHA256(token),
		AllowedWorkflows: workflows,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testEventPublisherPrincipalsJSON(t *testing.T, token, principalID string, events ...eventPublisherEventRef) string {
	t.Helper()
	if len(events) == 0 {
		events = []eventPublisherEventRef{{
			Provider:   "aws",
			InstanceID: "aws-primary",
			EventType:  "aws.bucket.ensured",
		}}
	}
	raw, err := json.Marshal([]eventPublisherPrincipalConfig{{
		PrincipalID:   principalID,
		Status:        "active",
		ExpiresAt:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		RotationID:    "test-rotation-event-1",
		RotatedAt:     time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
		TokenSHA256:   testTokenSHA256(token),
		AllowedEvents: events,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func setTestLegacyEventPublishCredential(t *testing.T, token string) {
	t.Helper()
	t.Setenv(legacyEventPublishTokenEnv, token)
	t.Setenv(legacyEventPublishEnabledEnv, "true")
	t.Setenv(legacyEventPublishExpiryEnv, "2099-01-01T00:00:00Z")
}

func setTestLegacyWorkflowCredential(t *testing.T, token string) {
	t.Helper()
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", token)
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "true")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "2099-01-01T00:00:00Z")
}

func TestWorkflowMachinePrincipalConfigStoresOnlyHashAndExactAllowlist(t *testing.T) {
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "unit-test-workflow-token", "ci-dakasa",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	principals, err := workflowMachinePrincipalsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 1 || principals[0].PrincipalID != "ci-dakasa" {
		t.Fatalf("principals = %+v", principals)
	}
	if !machineCredentialMatches("unit-test-workflow-token", principals[0].TokenSHA256) {
		t.Fatal("valid bearer did not match its configured SHA-256 digest")
	}
	if machineCredentialMatches("wrong-token", principals[0].TokenSHA256) {
		t.Fatal("wrong bearer matched configured SHA-256 digest")
	}
	if !workflowMachinePrincipalAllows(&principals[0], "dakasa", "deploy-validation") {
		t.Fatal("exact allowlist item did not match")
	}
	if workflowMachinePrincipalAllows(&principals[0], "dakasa", "deploy-validation-extra") {
		t.Fatal("allowlist performed a non-exact match")
	}
}

func TestMachinePrincipalConfigAcceptsRotationIDWithoutHistoricalTimestamp(t *testing.T) {
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","token_sha256":"`+testTokenSHA256("x")+`","allowed_workflows":[{"namespace":"dakasa","name":"deploy"}]}]`)
	if _, err := workflowMachinePrincipalsFromEnv(); err != nil {
		t.Fatalf("rotation_id-only workflow principal rejected: %v", err)
	}

	t.Setenv(eventPublisherPrincipalsEnv, `[{"principal_id":"adapter","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","token_sha256":"`+testTokenSHA256("event")+`","allowed_events":[{"provider":"aws","instance_id":"aws-primary","event_type":"aws.bucket.ensured"}]}]`)
	if _, err := eventPublisherPrincipalsFromEnv(); err != nil {
		t.Fatalf("rotation_id-only event principal rejected: %v", err)
	}
}

func TestWorkflowMachinePrincipalConfigRejectsRawTokensAndWildcards(t *testing.T) {
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	tests := []struct {
		name   string
		config string
	}{
		{
			name:   "raw token field",
			config: `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token":"raw-must-never-be-configured","token_sha256":"` + testTokenSHA256("x") + `","allowed_workflows":[{"namespace":"dakasa","name":"deploy"}]}]`,
		},
		{
			name:   "wildcard namespace",
			config: `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"` + testTokenSHA256("x") + `","allowed_workflows":[{"namespace":"*","name":"deploy"}]}]`,
		},
		{
			name:   "wildcard name",
			config: `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"` + testTokenSHA256("x") + `","allowed_workflows":[{"namespace":"dakasa","name":"deploy-*"}]}]`,
		},
		{
			name:   "non SHA-256 digest",
			config: `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"short","allowed_workflows":[{"namespace":"dakasa","name":"deploy"}]}]`,
		},
		{
			name:   "missing rotation metadata",
			config: `[{"principal_id":"ci","status":"active","expires_at":"2099-01-01T00:00:00Z","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"` + testTokenSHA256("x") + `","allowed_workflows":[{"namespace":"dakasa","name":"deploy"}]}]`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(workflowMachinePrincipalsEnv, test.config)
			if _, err := workflowMachinePrincipalsFromEnv(); err == nil {
				t.Fatal("invalid machine principal configuration was accepted")
			}
		})
	}
}

func TestMachinePrincipalLifecycleFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	digest, _ := hex.DecodeString(testTokenSHA256("lifecycle-token"))
	var tokenDigest [sha256.Size]byte
	copy(tokenDigest[:], digest)

	for _, test := range []struct {
		name      string
		status    string
		expiresAt time.Time
		wantMatch bool
	}{
		{name: "active", status: "active", expiresAt: now.Add(time.Hour), wantMatch: true},
		{name: "expired", status: "active", expiresAt: now.Add(-time.Second)},
		{name: "disabled", status: "disabled", expiresAt: now.Add(time.Hour)},
		{name: "revoked", status: "revoked", expiresAt: now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			principals := []workflowMachinePrincipal{{
				PrincipalID: "ci",
				Status:      test.status,
				ExpiresAt:   test.expiresAt,
				TokenSHA256: tokenDigest,
			}}
			matched := activeWorkflowMachinePrincipal("lifecycle-token", principals, now) != nil
			if matched != test.wantMatch {
				t.Fatalf("matched=%v, want %v", matched, test.wantMatch)
			}
		})
	}
}

func TestEventPublisherPrincipalLifecycleFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	digest, _ := hex.DecodeString(testTokenSHA256("event-lifecycle-token"))
	var tokenDigest [sha256.Size]byte
	copy(tokenDigest[:], digest)

	for _, test := range []struct {
		name      string
		status    string
		expiresAt time.Time
		wantMatch bool
	}{
		{name: "active", status: "active", expiresAt: now.Add(time.Hour), wantMatch: true},
		{name: "expired", status: "active", expiresAt: now.Add(-time.Second)},
		{name: "disabled", status: "disabled", expiresAt: now.Add(time.Hour)},
		{name: "revoked", status: "revoked", expiresAt: now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			principals := []eventPublisherPrincipal{{
				PrincipalID: "adapter",
				Status:      test.status,
				ExpiresAt:   test.expiresAt,
				TokenSHA256: tokenDigest,
			}}
			matched := activeEventPublisherPrincipal("event-lifecycle-token", principals, now) != nil
			if matched != test.wantMatch {
				t.Fatalf("matched=%v, want %v", matched, test.wantMatch)
			}
		})
	}
}

func TestEventPublisherConfigCannotCarryWorkflowScope(t *testing.T) {
	t.Setenv(eventPublisherPrincipalsEnv, `[{"principal_id":"adapter","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","rotated_at":"2026-09-05T00:00:00Z","token_sha256":"`+testTokenSHA256("event-token")+`","allowed_events":[{"provider":"aws","instance_id":"aws-primary","event_type":"aws.bucket.ensured"}],"allowed_workflows":[{"namespace":"dakasa","name":"deploy"}]}]`)
	if _, err := eventPublisherPrincipalsFromEnv(); err == nil {
		t.Fatal("event publisher configuration accepted workflow scope")
	}
}

func TestEventPublisherConfigRequiresExactValidEventScope(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
	}{
		{name: "missing", config: `"allowed_events":[]`},
		{name: "wildcard instance", config: `"allowed_events":[{"provider":"aws","instance_id":"aws-*","event_type":"aws.bucket.ensured"}]`},
		{name: "generic event", config: `"allowed_events":[{"provider":"aws","instance_id":"aws-primary","event_type":"deployment.completed"}]`},
		{name: "provider mismatch", config: `"allowed_events":[{"provider":"gcp","instance_id":"aws-primary","event_type":"aws.bucket.ensured"}]`},
		{name: "raw token field", config: `"token":"raw-must-never-be-configured","allowed_events":[{"provider":"aws","instance_id":"aws-primary","event_type":"aws.bucket.ensured"}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(eventPublisherPrincipalsEnv, `[{"principal_id":"adapter","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r1","token_sha256":"`+testTokenSHA256("event")+`",`+test.config+`}]`)
			if _, err := eventPublisherPrincipalsFromEnv(); err == nil {
				t.Fatal("invalid event-publisher scope was accepted")
			}
		})
	}
}
