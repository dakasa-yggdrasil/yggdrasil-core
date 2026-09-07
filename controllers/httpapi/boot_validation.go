package httpapi

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"
)

// Boot-time validation of security-critical env vars. Called once by
// Server.New() before the mux is wired.  Misconfigurations that would
// silently weaken security in production (e.g. an empty
// AUTH_THIRD_PARTY_STATE_SECRET that falls back to a known-public
// dev string) MUST halt the boot — silent fallbacks let a deploy roll
// to production looking healthy while the security envelope is open.
//
// Audit refs:
//   - A12 (AUTH_THIRD_PARTY_STATE_SECRET fallback "yggdrasil-dev-…" in prod)
//   - A12-bis (YGGDRASIL_CSRF_HMAC_SECRET fallback "yggdrasil-dev-…" in prod)
//
// Production detection is environment-driven via `YGGDRASIL_ENV`
// (canonical values: "production", "prod"). The variable is set by the
// Kubernetes Deployment in `dakasa-yggdrasil/yggdrasil`. Any other value
// or absence keeps the dev fallbacks intact so local dev / CI keeps
// working with `go run .` and no env wiring.

// devEnvAllowsFallback returns true when the runtime is non-production
// and the dev fallbacks are permitted. We treat anything other than the
// explicit production markers as dev/test to avoid breaking local setups.
func devEnvAllowsFallback() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_ENV")))
	switch env {
	case "production", "prod":
		return false
	default:
		return true
	}
}

// validateBootSecrets returns a non-nil error if a security-critical env var
// is missing or conflicts with another credential in production. Callers MUST
// treat the error as fatal (panic via main.go's `panic(err)` path).
//
// Every issue produces one line in the returned error so the operator sees the
// full list in one boot failure instead of fixing one var, rolling, and
// discovering the next.
func validateBootSecrets() error {
	if devEnvAllowsFallback() {
		// Non-production: dev fallbacks are intentional. Skip the gate
		// so `go run .` / `vitest` / CI test harness keep working.
		return nil
	}

	var issues []string
	now := time.Now().UTC()
	workflowPrincipals, workflowPrincipalsErr := workflowMachinePrincipalsFromEnv()
	if workflowPrincipalsErr != nil {
		issues = append(issues, workflowPrincipalsErr.Error())
	}
	eventPrincipals, eventPrincipalsErr := eventPublisherPrincipalsFromEnv()
	if eventPrincipalsErr != nil {
		issues = append(issues, eventPrincipalsErr.Error())
	}
	legacyWorkflow, legacyWorkflowErr := legacyWorkflowCredentialFromEnv(now)
	if legacyWorkflowErr != nil {
		issues = append(issues, legacyWorkflowErr.Error())
	}
	legacyEvent, legacyEventErr := legacyEventPublishCredentialFromEnv(now)
	if legacyEventErr != nil {
		issues = append(issues, legacyEventErr.Error())
	}

	// A12 — third-party OAuth state secret. Falls back to the constant
	// "yggdrasil-dev-third-party-state-secret" in auth.go if empty,
	// which is a public string in this repo.
	if strings.TrimSpace(os.Getenv("AUTH_THIRD_PARTY_STATE_SECRET")) == "" {
		issues = append(issues,
			"AUTH_THIRD_PARTY_STATE_SECRET (third-party OAuth state HMAC; production fallback is a public dev string)")
	}

	// A12-bis — CSRF token HMAC secret. Falls back to
	// "yggdrasil-dev-csrf-hmac-secret" in csrf.go if empty. With CSRF in
	// enforce mode that fallback would let any caller compute valid
	// tokens from the known secret.
	if strings.TrimSpace(os.Getenv("YGGDRASIL_CSRF_HMAC_SECRET")) == "" {
		issues = append(issues,
			"YGGDRASIL_CSRF_HMAC_SECRET (CSRF token HMAC; production fallback is a public dev string)")
	}

	// Production needs independent workflow-dispatch and event-publish
	// credentials. The global workflow token is accepted only as an explicit,
	// time-bounded workflow-route migration bridge; it never satisfies event
	// publishing. Hashed machine principals are the durable path.
	eventToken := strings.TrimSpace(os.Getenv(legacyEventPublishTokenEnv))
	legacyWorkflowToken := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN"))
	if workflowPrincipalsErr == nil && legacyWorkflowErr == nil &&
		usableWorkflowMachinePrincipalCount(workflowPrincipals, now) == 0 && !legacyWorkflow.Active {
		issues = append(issues,
			"YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON needs an active, unexpired principal or the explicit legacy workflow migration credential must be active")
	}
	if eventPrincipalsErr == nil && legacyEventErr == nil &&
		usableEventPublisherPrincipalCount(eventPrincipals, now) == 0 && !legacyEvent.Active {
		issues = append(issues, fmt.Sprintf(
			"%s needs an active, unexpired principal or %s must be explicitly enabled with %s=true and an active %s",
			eventPublisherPrincipalsEnv,
			legacyEventPublishTokenEnv,
			legacyEventPublishEnabledEnv,
			legacyEventPublishExpiryEnv,
		))
	}

	// Hash both plaintext bridges only inside the process and compare every
	// scope in constant time. Diagnostics name configuration locations but never
	// include credentials or digests.
	plaintextScopes := []struct {
		name  string
		value string
	}{
		{name: "YGGDRASIL_WORKFLOW_RUN_TOKEN", value: legacyWorkflowToken},
		{name: legacyEventPublishTokenEnv, value: eventToken},
		{name: "YGGDRASIL_DEPLOY_TOKEN", value: strings.TrimSpace(os.Getenv("YGGDRASIL_DEPLOY_TOKEN"))},
		{name: "YGGDRASIL_AUTH_ADMIN_TOKEN", value: strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_ADMIN_TOKEN"))},
	}
	for left := range plaintextScopes {
		for right := left + 1; right < len(plaintextScopes); right++ {
			if plaintextScopes[left].value != "" && plaintextScopes[right].value != "" &&
				constantTimeTokenEqual(plaintextScopes[left].value, plaintextScopes[right].value) {
				issues = append(issues, fmt.Sprintf("%s must differ from %s", plaintextScopes[left].name, plaintextScopes[right].name))
			}
		}
	}

	if workflowPrincipalsErr == nil {
		for index, principal := range workflowPrincipals {
			for _, other := range plaintextScopes {
				if digestMatchesPlaintext(principal.TokenSHA256, other.value) {
					issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s", workflowMachinePrincipalsEnv, index, other.name))
				}
			}
		}
	}
	if eventPrincipalsErr == nil {
		for index, principal := range eventPrincipals {
			for _, other := range plaintextScopes {
				// Even the event bridge must use a distinct bearer. Reuse would create
				// a downgrade: once the hashed principal expires or is revoked, the
				// same bearer could fall through to the broader migration bridge.
				if digestMatchesPlaintext(principal.TokenSHA256, other.value) {
					issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s", eventPublisherPrincipalsEnv, index, other.name))
				}
			}
		}
	}
	if workflowPrincipalsErr == nil && eventPrincipalsErr == nil {
		for workflowIndex, workflowPrincipal := range workflowPrincipals {
			for eventIndex, eventPrincipal := range eventPrincipals {
				if machineCredentialDigestsCollide(workflowPrincipal.TokenSHA256, eventPrincipal.TokenSHA256) {
					issues = append(issues, fmt.Sprintf("%s entry %d credential must differ from %s entry %d", workflowMachinePrincipalsEnv, workflowIndex, eventPublisherPrincipalsEnv, eventIndex))
				}
			}
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return fmt.Errorf(
		"production boot-validation failed (YGGDRASIL_ENV=%s): security configuration issues:\n  - %s",
		os.Getenv("YGGDRASIL_ENV"),
		strings.Join(issues, "\n  - "),
	)
}

func digestMatchesPlaintext(digest [sha256.Size]byte, plaintext string) bool {
	configuredDigest, ok := digestForConfiguredToken(plaintext)
	return ok && machineCredentialDigestsCollide(digest, configuredDigest)
}
