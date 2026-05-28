package httpapi

import (
	"fmt"
	"os"
	"strings"
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

// validateBootSecrets returns a non-nil error if a security-critical
// env var is missing in production. Callers MUST treat the error as
// fatal (panic via main.go's `panic(err)` path).
//
// The checks are all "AND" — every missing secret produces one line in
// the returned error so the operator sees the full list in one boot
// failure instead of fixing one var, rolling, and discovering the next.
func validateBootSecrets() error {
	if devEnvAllowsFallback() {
		// Non-production: dev fallbacks are intentional. Skip the gate
		// so `go run .` / `vitest` / CI test harness keep working.
		return nil
	}

	var missing []string

	// A12 — third-party OAuth state secret. Falls back to the constant
	// "yggdrasil-dev-third-party-state-secret" in auth.go if empty,
	// which is a public string in this repo.
	if strings.TrimSpace(os.Getenv("AUTH_THIRD_PARTY_STATE_SECRET")) == "" {
		missing = append(missing,
			"AUTH_THIRD_PARTY_STATE_SECRET (third-party OAuth state HMAC; production fallback is a public dev string)")
	}

	// A12-bis — CSRF token HMAC secret. Falls back to
	// "yggdrasil-dev-csrf-hmac-secret" in csrf.go if empty. With CSRF in
	// enforce mode that fallback would let any caller compute valid
	// tokens from the known secret.
	if strings.TrimSpace(os.Getenv("YGGDRASIL_CSRF_HMAC_SECRET")) == "" {
		missing = append(missing,
			"YGGDRASIL_CSRF_HMAC_SECRET (CSRF token HMAC; production fallback is a public dev string)")
	}

	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"production boot-validation failed (YGGDRASIL_ENV=%s): missing required secrets:\n  - %s",
		os.Getenv("YGGDRASIL_ENV"),
		strings.Join(missing, "\n  - "),
	)
}
