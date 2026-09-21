package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

const (
	testDirectoryToken       = "directory-read-token-for-tests"
	testDirectoryPrincipalID = "social-directory"
)

var testTartaroInstance = tartaroInstanceRef{Namespace: "dakasa", Name: "tartaro-dakasa-validation"}

func testDirectoryPrincipalConfig(token, principalID string, capabilities []string, instances ...tartaroInstanceRef) directoryMachinePrincipalConfig {
	return directoryMachinePrincipalConfig{
		PrincipalID:             principalID,
		Status:                  "active",
		ExpiresAt:               time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		RotationID:              "test-rotation-directory-1",
		RotatedAt:               time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
		TokenSHA256:             testTokenSHA256(token),
		Capabilities:            capabilities,
		AllowedTartaroInstances: instances,
	}
}

func allDirectoryCapabilities() []string {
	return []string{directoryCapabilityLookupEmail, directoryCapabilityRead, directoryCapabilityEffectiveActions}
}

func testDirectoryMachinePrincipalsJSON(t *testing.T, configs ...directoryMachinePrincipalConfig) string {
	t.Helper()
	raw, err := json.Marshal(configs)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDirectoryMachinePrincipalConfigLoadsExactScopes(t *testing.T) {
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
		testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, allDirectoryCapabilities(), testTartaroInstance)))

	principals, err := directoryMachinePrincipalsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 1 {
		t.Fatalf("principals=%d, want 1", len(principals))
	}
	principal := principals[0]
	if principal.PrincipalID != testDirectoryPrincipalID || principal.Status != "active" || principal.RotationID != "test-rotation-directory-1" {
		t.Fatalf("unexpected principal metadata: %+v", principal)
	}
	if len(principal.Capabilities) != 3 {
		t.Fatalf("capabilities=%v, want three exact capabilities", principal.Capabilities)
	}
	if !directoryMachinePrincipalAllowsTartaroInstance(&principal, "dakasa", "tartaro-dakasa-validation") {
		t.Fatal("allowed instance not honored")
	}
	if directoryMachinePrincipalAllowsTartaroInstance(&principal, "dakasa", "other-instance") {
		t.Fatal("unlisted instance was allowed")
	}
	if !machineCredentialMatches(testDirectoryToken, principal.TokenSHA256) {
		t.Fatal("configured digest does not match the raw bearer")
	}
	if machineCredentialMatches(testDirectoryToken+"x", principal.TokenSHA256) {
		t.Fatal("digest matched a different bearer")
	}
}

func TestDirectoryMachinePrincipalConfigAbsentIsNotAnError(t *testing.T) {
	t.Setenv(directoryMachinePrincipalsEnv, "")
	principals, err := directoryMachinePrincipalsFromEnv()
	if err != nil || principals != nil {
		t.Fatalf("principals=%v err=%v, want nil/nil", principals, err)
	}
}

func TestDirectoryMachinePrincipalConfigRejectsInvalidEntries(t *testing.T) {
	valid := testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, allDirectoryCapabilities(), testTartaroInstance)
	readOnly := testDirectoryPrincipalConfig("other-token", "other-id", []string{directoryCapabilityRead})

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty array", raw: "[]", want: "at least one principal"},
		{name: "object instead of array", raw: "{}", want: "parse"},
		{name: "trailing json", raw: testDirectoryMachinePrincipalsJSON(t, valid) + "[]", want: "trailing JSON"},
		{name: "raw token field", raw: `[{"principal_id":"x","token":"raw"}]`, want: "unknown field"},
		{name: "missing capabilities", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.Capabilities = nil
			c.AllowedTartaroInstances = nil
			return c
		}()), want: "requires at least one capability"},
		{name: "unknown capability", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.Capabilities = []string{"directory.write"}
			return c
		}()), want: "must be one of"},
		{name: "wildcard capability", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.Capabilities = []string{"directory.*"}
			return c
		}()), want: "must be one of"},
		{name: "duplicate capability", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.Capabilities = []string{directoryCapabilityRead, directoryCapabilityRead}
			return c
		}()), want: "duplicates a capabilities item"},
		{name: "effective actions without instances", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.AllowedTartaroInstances = nil
			return c
		}()), want: "requires at least one exact allowed_tartaro_instances"},
		{name: "instances without effective actions", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.AllowedTartaroInstances = []tartaroInstanceRef{testTartaroInstance}
			return c
		}()), want: "allowed_tartaro_instances requires the directory.effective_actions capability"},
		{name: "wildcard instance", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.AllowedTartaroInstances = []tartaroInstanceRef{{Namespace: "dakasa", Name: "tartaro-*"}}
			return c
		}()), want: "cannot contain wildcards"},
		{name: "blank instance", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.AllowedTartaroInstances = []tartaroInstanceRef{{Namespace: "dakasa", Name: " "}}
			return c
		}()), want: "requires namespace and name"},
		{name: "duplicate instance", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.AllowedTartaroInstances = []tartaroInstanceRef{testTartaroInstance, testTartaroInstance}
			return c
		}()), want: "duplicates an allowed_tartaro_instances item"},
		{name: "duplicate principal id", raw: testDirectoryMachinePrincipalsJSON(t, valid, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.PrincipalID = valid.PrincipalID
			return c
		}()), want: "duplicates principal_id"},
		{name: "duplicate digest", raw: testDirectoryMachinePrincipalsJSON(t, valid, func() directoryMachinePrincipalConfig {
			c := readOnly
			c.TokenSHA256 = valid.TokenSHA256
			return c
		}()), want: "duplicates a credential digest"},
		{name: "missing expiry", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.ExpiresAt = time.Time{}
			return c
		}()), want: "requires expires_at"},
		{name: "missing rotation id", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.RotationID = ""
			return c
		}()), want: "requires rotation_id"},
		{name: "invalid status", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.Status = "enabled"
			return c
		}()), want: "status must be active, disabled, or revoked"},
		{name: "uppercase digest", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.TokenSHA256 = strings.ToUpper(c.TokenSHA256)
			return c
		}()), want: "64 lowercase hexadecimal"},
		{name: "all zero digest", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.TokenSHA256 = strings.Repeat("0", 64)
			return c
		}()), want: "all-zero digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(directoryMachinePrincipalsEnv, tc.raw)
			principals, err := directoryMachinePrincipalsFromEnv()
			if err == nil {
				t.Fatalf("accepted invalid inventory: %+v", principals)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%q, want substring %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), testDirectoryToken) || strings.Contains(err.Error(), testTokenSHA256(testDirectoryToken)) {
				t.Fatalf("error leaks credential material: %q", err.Error())
			}
		})
	}
}

func TestDirectoryMachinePrincipalLifecycleGate(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	base := testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead})

	cases := []struct {
		name   string
		mutate func(*directoryMachinePrincipalConfig)
		usable bool
		reason string
	}{
		{name: "active", mutate: func(*directoryMachinePrincipalConfig) {}, usable: true},
		{name: "expired", mutate: func(c *directoryMachinePrincipalConfig) {
			c.ExpiresAt = now.Add(-time.Minute)
		}, reason: "expired"},
		{name: "expires exactly now", mutate: func(c *directoryMachinePrincipalConfig) {
			c.ExpiresAt = now
		}, reason: "expired"},
		{name: "revoked", mutate: func(c *directoryMachinePrincipalConfig) { c.Status = "revoked" }, reason: "status_revoked"},
		{name: "disabled", mutate: func(c *directoryMachinePrincipalConfig) { c.Status = "disabled" }, reason: "status_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			tc.mutate(&config)
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, config))
			principals, err := directoryMachinePrincipalsFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			matched := directoryMachinePrincipalByCredential(testDirectoryToken, principals)
			if matched == nil {
				t.Fatal("digest match must succeed in every lifecycle state so the gate can refuse it explicitly")
			}
			usable, reason := directoryMachinePrincipalUsable(matched, now)
			if usable != tc.usable || reason != tc.reason {
				t.Fatalf("usable=%v reason=%q, want %v %q", usable, reason, tc.usable, tc.reason)
			}
			if directoryMachinePrincipalByCredential("wrong-"+testDirectoryToken, principals) != nil {
				t.Fatal("wrong bearer matched a principal")
			}
			if directoryMachinePrincipalByCredential("", principals) != nil {
				t.Fatal("empty bearer matched a principal")
			}
		})
	}
	if usable, reason := directoryMachinePrincipalUsable(nil, now); usable || reason != "credential_unknown" {
		t.Fatalf("nil principal usable=%v reason=%q", usable, reason)
	}
}

func TestValidateBootSecrets_ProductionAcceptsDistinctDirectoryPrincipal(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
		testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, allDirectoryCapabilities(), testTartaroInstance)))
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("distinct directory principal rejected: %v", err)
	}
}

func TestValidateBootSecrets_ProductionWithoutDirectoryPrincipalsStillBoots(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(directoryMachinePrincipalsEnv, "")
	if err := validateBootSecrets(); err != nil {
		t.Fatalf("absent directory inventory must be optional: %v", err)
	}
}

func TestValidateBootSecrets_ProductionRejectsDirectoryCredentialReuse(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{name: "workflow principal", token: "scoped-workflow-token", want: workflowMachinePrincipalsEnv + " entry 0"},
		{name: "event bridge", token: testEventPublishToken, want: legacyEventPublishTokenEnv},
		{name: "deploy token", token: "deploy-token", want: "YGGDRASIL_DEPLOY_TOKEN"},
		{name: "auth admin token", token: "auth-admin-token", want: "YGGDRASIL_AUTH_ADMIN_TOKEN"},
		{name: "event principal", token: "event-principal-token", want: eventPublisherPrincipalsEnv + " entry 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidProductionBootEnvironment(t, "production")
			t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "event-principal-token", "event-principal"))
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
				testDirectoryPrincipalConfig(tc.token, testDirectoryPrincipalID, []string{directoryCapabilityRead})))
			err := validateBootSecrets()
			if err == nil {
				t.Fatal("directory credential reuse across scopes was accepted")
			}
			if !strings.Contains(err.Error(), directoryMachinePrincipalsEnv+" entry 0 credential must differ from "+tc.want) {
				t.Fatalf("error=%q, want directory reuse issue naming %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), tc.token) || strings.Contains(err.Error(), testTokenSHA256(tc.token)) {
				t.Fatalf("error leaks credential material: %q", err.Error())
			}
		})
	}
}

func TestValidateBootSecrets_ProductionReportsMalformedDirectoryInventory(t *testing.T) {
	setValidProductionBootEnvironment(t, "production")
	t.Setenv(directoryMachinePrincipalsEnv, `[{"principal_id":"broken"}]`)
	err := validateBootSecrets()
	if err == nil || !strings.Contains(err.Error(), directoryMachinePrincipalsEnv) {
		t.Fatalf("malformed directory inventory not reported: %v", err)
	}
}

func TestNewFailsClosedOnMalformedDirectoryInventoryInEveryEnvironment(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "")
	t.Setenv(directoryMachinePrincipalsEnv, `[{"principal_id":"broken"}]`)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := New("yggdrasil-core-test", db, nil, zap.NewNop()); err == nil || !strings.Contains(err.Error(), directoryMachinePrincipalsEnv) {
		t.Fatalf("New accepted a malformed directory inventory: %v", err)
	}
}
