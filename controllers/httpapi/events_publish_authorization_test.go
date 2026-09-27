package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventPublisherAuthorizationProvesEffectiveGrantWithoutPublishingOrExposingCredential(t *testing.T) {
	const token = "adapter-efi-event-token"
	configs := []eventPublisherPrincipalConfig{{
		PrincipalID: "integration-efi",
		Status:      "active",
		ExpiresAt:   time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		RotationID:  "efi-r1",
		TokenSHA256: testTokenSHA256(token),
		AllowedEvents: []eventPublisherEventRef{
			{Provider: "efi", InstanceID: "efi-dakasa-validation", EventType: "efi.charge.ensured"},
			{Provider: "efi", InstanceID: "efi-dakasa-production", EventType: "efi.automatic_webhook.ensured"},
		},
	}}
	raw, err := json.Marshal(configs)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(eventPublisherPrincipalsEnv, string(raw))
	t.Setenv(legacyEventPublishTokenEnv, "")
	t.Setenv(legacyEventPublishEnabledEnv, "")
	t.Setenv(legacyEventPublishExpiryEnv, "")

	server := eventPublishServerFromEnv(t)
	request := httptest.NewRequest(http.MethodPost, eventPublisherAuthorizationPath, strings.NewReader(
		`{"provider":"efi","instance_id":"efi-dakasa-production","event_type":"efi.automatic_webhook.ensured"}`,
	))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.handleEventPublisherAuthorization(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response eventPublisherAuthorizationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Allowed || response.PrincipalID != "integration-efi" || response.GrantForm != eventGrantFormExact || response.GrantCount != 2 || len(response.GrantSetSHA256) != 64 {
		t.Fatalf("response=%+v", response)
	}
	if strings.Contains(recorder.Body.String(), token) || strings.Contains(recorder.Body.String(), testTokenSHA256(token)) {
		t.Fatalf("response exposed credential material: %s", recorder.Body.String())
	}
}

func TestEventPublisherAuthorizationFingerprintIsOrderIndependentAndGrantSensitive(t *testing.T) {
	grantA := eventPublisherEventRef{Provider: "efi", InstanceID: "efi-production", EventType: "efi.charge.ensured"}
	grantB := eventPublisherEventRef{Provider: "efi", InstanceID: "efi-production", EventType: "efi.automatic_webhook.ensured"}
	principal := func(grants ...eventPublisherEventRef) *eventPublisherPrincipal {
		set := make(map[eventPublisherEventRef]struct{}, len(grants))
		for _, grant := range grants {
			set[grant] = struct{}{}
		}
		return &eventPublisherPrincipal{AllowedEvents: set, LogicalEvents: map[eventPublisherLogicalRef]struct{}{}}
	}
	countAB, hashAB := eventPublisherGrantSetFingerprint(principal(grantA, grantB))
	countBA, hashBA := eventPublisherGrantSetFingerprint(principal(grantB, grantA))
	_, hashA := eventPublisherGrantSetFingerprint(principal(grantA))
	if countAB != 2 || countBA != 2 || hashAB == "" || hashAB != hashBA || hashAB == hashA {
		t.Fatalf("fingerprints AB=%s BA=%s A=%s", hashAB, hashBA, hashA)
	}
}

func TestEventPublisherAuthorizationRejectsLegacyBridgeAndUngrant(t *testing.T) {
	setEventPublishAuthEnvironment(t, "legacy-event-token", "")
	legacy := httptest.NewRequest(http.MethodPost, eventPublisherAuthorizationPath, strings.NewReader(
		`{"provider":"efi","instance_id":"efi-production","event_type":"efi.automatic_webhook.ensured"}`,
	))
	legacy.Header.Set("Authorization", "Bearer legacy-event-token")
	recorder := httptest.NewRecorder()
	eventPublishServerFromEnv(t).handleEventPublisherAuthorization(recorder, legacy)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("legacy status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "adapter-event-token", "adapter-efi"))
	unsetEnvForTest(t, legacyEventPublishTokenEnv)
	unsetEnvForTest(t, legacyEventPublishEnabledEnv)
	unsetEnvForTest(t, legacyEventPublishExpiryEnv)
	request := httptest.NewRequest(http.MethodPost, eventPublisherAuthorizationPath, strings.NewReader(
		`{"provider":"efi","instance_id":"other","event_type":"efi.automatic_webhook.ensured"}`,
	))
	request.Header.Set("Authorization", "Bearer adapter-event-token")
	recorder = httptest.NewRecorder()
	eventPublishServerFromEnv(t).handleEventPublisherAuthorization(recorder, request)
	if recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "other") {
		t.Fatalf("ungranted status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
