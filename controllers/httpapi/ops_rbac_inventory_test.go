package httpapi

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestConsoleRoutesAreFullyMapped is the drift-prevention safety net for
// Phase 5 RBAC wiring. It scans server.go for every
// `mux.HandleFunc("METHOD /api/v1/console/...`, expects each line to be
// wrapped in `requireOpsPermissionFunc(perm<X>, …)`, and fails when a
// new console route lands without a permission wrapper.
//
// Why a regex over the source: ServeMux exposes registered patterns
// reflectively in Go 1.23+, but compiled-in handler chains are opaque
// (the http.Handler interface erases the wrapping). The simplest
// load-bearing assertion is that the source registers each route
// behind the wrapper — easy to verify, hard to bypass accidentally.
//
// Stop conditions (per task): if a future cycle adds a wildcard
// default-deny middleware OR moves all routes to a Handle() pattern,
// rewrite this test to match the new convention.
func TestConsoleRoutesAreFullyMapped(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	f, err := os.Open(serverPath)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Matches `mux.HandleFunc("<METHOD> /api/v1/console/...`
	routeRe := regexp.MustCompile(`mux\.HandleFunc\("[A-Z]+ /api/v1/console/[^"]*"`)
	// Confirms the line carries the wrapper. Two valid forms:
	//   server.requireOpsPermissionFunc(permX, server.handleY)
	//   server.requireOpsPermissionFunc(permX, requireDeployToken(server.handleY))
	wrapperRe := regexp.MustCompile(`server\.requireOpsPermissionFunc\(perm[A-Za-z]+,`)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var routeCount int
	var missing []string
	for scanner.Scan() {
		line := scanner.Text()
		if !routeRe.MatchString(line) {
			continue
		}
		routeCount++
		if !wrapperRe.MatchString(line) {
			missing = append(missing, strings.TrimSpace(line))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if routeCount == 0 {
		t.Fatalf("regex did not match any console routes — server.go shape changed; update TestConsoleRoutesAreFullyMapped")
	}
	if len(missing) > 0 {
		t.Errorf("%d /api/v1/console/* route(s) lack requireOpsPermissionFunc wrapping (audit §3.1 + INTEGRATION_CONTRACT §12):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	// Sanity check: the audit found 89 console routes pre-Phase-5. If
	// the count drifts radically (someone deletes a whole subtree, or
	// the regex stops matching) the test should surface that. Allow a
	// reasonable band [80, 120] — narrower would be brittle, wider
	// defeats the purpose.
	if routeCount < 80 || routeCount > 120 {
		t.Errorf("console route count = %d, expected ~89 — investigate before merging", routeCount)
	}
}

// TestOpsRoutesAreFullyMapped is the Phase 5B drift-prevention mirror of
// TestConsoleRoutesAreFullyMapped. It scans server.go for every
// `mux.HandleFunc("METHOD /api/v1/ops/...`, expects each line to be
// wrapped in `requireOpsPermissionFunc(perm<X>, …)`, and fails when a
// new ops route lands without a permission wrapper.
//
// Why two tests instead of one: the /api/v1/ops/* namespace is the
// older console-style surface (~22 routes); /api/v1/console/* is the
// newer canonical namespace (~89 routes). Keeping the assertions split
// makes regressions on either group surface in the failing-test name
// without ambiguity.
func TestOpsRoutesAreFullyMapped(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	f, err := os.Open(serverPath)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Matches `mux.HandleFunc("<METHOD> /api/v1/ops/...`
	routeRe := regexp.MustCompile(`mux\.HandleFunc\("[A-Z]+ /api/v1/ops/[^"]*"`)
	wrapperRe := regexp.MustCompile(`server\.requireOpsPermissionFunc\(perm[A-Za-z]+,`)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var routeCount int
	var missing []string
	for scanner.Scan() {
		line := scanner.Text()
		if !routeRe.MatchString(line) {
			continue
		}
		routeCount++
		if !wrapperRe.MatchString(line) {
			missing = append(missing, strings.TrimSpace(line))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if routeCount == 0 {
		t.Fatalf("regex did not match any ops routes — server.go shape changed; update TestOpsRoutesAreFullyMapped")
	}
	if len(missing) > 0 {
		t.Errorf("%d /api/v1/ops/* route(s) lack requireOpsPermissionFunc wrapping (audit §3.1 + INTEGRATION_CONTRACT §12 — Phase 5B):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	// Phase 5B inventory found 22 ops routes. Allow a band [18, 40] — narrower
	// would be brittle (each PR that adds an ops route would have to bump),
	// wider defeats the purpose of catching subtree deletions.
	if routeCount < 18 || routeCount > 40 {
		t.Errorf("ops route count = %d, expected ~22 — investigate before merging", routeCount)
	}
}

// TestOpsRoutesUseCanonicalPermissions is the Phase 5B mirror for the
// /api/v1/ops/* namespace. Catches the same class of drift on the
// older namespace (a route wrapped with a perm constant not declared
// in ops_rbac_catalog.go).
func TestOpsRoutesUseCanonicalPermissions(t *testing.T) {
	canonical := map[string]struct{}{
		"permViewPeople":            {},
		"permCreateCollaborator":    {},
		"permEditCollaborator":      {},
		"permOffboardCollaborator":  {},
		"permIssueSetupToken":       {},
		"permViewTeams":             {},
		"permCreateTeam":            {},
		"permEditTeam":              {},
		"permManageTeamPermissions": {},
		"permViewIntegrations":      {},
		"permManageIntegrations":    {},
		"permManageSecrets":         {},
		"permViewAudit":             {},
		"permManageAuthProviders":   {},
		"permViewOps":               {},
		"permManageWorkflows":       {},
		"permManageOrganization":    {},
		"permViewOverview":          {},
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	f, err := os.Open(serverPath)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}
	defer func() { _ = f.Close() }()

	permRe := regexp.MustCompile(`requireOpsPermissionFunc\((perm[A-Za-z]+),`)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// Restrict to ops route registrations only; comments in server.go
		// also contain the /api/v1/ops/ literal as prose and should not match.
		if !strings.Contains(line, `mux.HandleFunc("`) || !strings.Contains(line, "/api/v1/ops/") {
			continue
		}
		matches := permRe.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		perm := matches[1]
		if _, ok := canonical[perm]; !ok {
			t.Errorf("non-canonical permission %q used in ops route — add to ops_rbac_catalog.go or fix the wiring:\n  %s",
				perm, strings.TrimSpace(line))
		}
	}
}

// TestManageSecretsIsDistinctFromManageIntegrations locks the Phase 5B
// permission split — the two constants must not collapse to the same
// value (a tempting bug if someone refactors the catalog).
func TestManageSecretsIsDistinctFromManageIntegrations(t *testing.T) {
	if permManageSecrets == permManageIntegrations {
		t.Fatalf("permission split regression: permManageSecrets == permManageIntegrations (both = %q). Secret custody has HIGHER blast radius than integration provisioning; keep them separate.", permManageSecrets)
	}
	if permManageSecrets == "" {
		t.Fatalf("permManageSecrets is empty — Phase 5B split must define a non-empty constant")
	}
	want := "yggdrasil:manage_secrets"
	if permManageSecrets != want {
		t.Fatalf("permManageSecrets = %q, want %q (must match surface-console's PERMS.ManageSecrets and integration-yggdrasil-self action_catalog)", permManageSecrets, want)
	}
}

// TestConsoleRoutesUseCanonicalPermissions verifies each route uses
// only the 17 canonical permissions defined in ops_rbac_catalog.go
// (16 from Phase 5 + manage_secrets from Phase 5B).
// Catches drift where someone defines a new perm constant without
// adding it to the catalog (which would then drift from surface-console's
// PERMS).
func TestConsoleRoutesUseCanonicalPermissions(t *testing.T) {
	canonical := map[string]struct{}{
		"permViewPeople":            {},
		"permCreateCollaborator":    {},
		"permEditCollaborator":      {},
		"permOffboardCollaborator":  {},
		"permIssueSetupToken":       {},
		"permViewTeams":             {},
		"permCreateTeam":            {},
		"permEditTeam":              {},
		"permManageTeamPermissions": {},
		"permViewIntegrations":      {},
		"permManageIntegrations":    {},
		"permManageSecrets":         {},
		"permViewAudit":             {},
		"permManageAuthProviders":   {},
		"permViewOps":               {},
		"permManageWorkflows":       {},
		"permManageOrganization":    {},
		"permViewOverview":          {},
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	f, err := os.Open(serverPath)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}
	defer func() { _ = f.Close() }()

	permRe := regexp.MustCompile(`requireOpsPermissionFunc\((perm[A-Za-z]+),`)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var seen = map[string]int{}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "/api/v1/console/") {
			continue
		}
		matches := permRe.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		perm := matches[1]
		if _, ok := canonical[perm]; !ok {
			t.Errorf("non-canonical permission %q used in console route — add to ops_rbac_catalog.go or fix the wiring:\n  %s",
				perm, strings.TrimSpace(line))
		}
		seen[perm]++
	}

	// Surface which permissions are mapped and which are unused. Unused
	// permissions in the catalog aren't a hard error — surface-console
	// references them for UX hints — but the report helps reviewers
	// notice when a permission becomes orphaned.
	for perm := range canonical {
		if seen[perm] == 0 {
			t.Logf("info: permission %s declared in catalog but not used by any console route (might be FE-only)", perm)
		}
	}
}

// TestNoUngatedMutatingRoutes is the durable guardrail for RBAC sweep #2
// (2026-05-28). It scans server.go for every mutating route registration
// (POST/PATCH/PUT/DELETE on /api/v1/* OR /scim/* OR /saml/*) and validates
// each carries ONE of:
//
//   - requireOpsPermissionFunc(perm…  → canonical RBAC gate
//   - requireDeployToken(…             → deploy-token / machine-only path
//   - Membership in the documented allowlist below
//
// INTEGRATION_CONTRACT §12: backend is the authorization authority. Any
// new mutating route that lands without a gate must explicitly justify
// itself by joining the allowlist, with a comment explaining WHY the
// route is workflow-token-only / self-scoped / webhook / admin-token.
//
// Stop conditions: if a future cycle adopts a default-deny middleware
// (the whole mux returns 403 unless the route opts in), this test
// becomes vacuous — keep it anyway because the allowlist is still the
// canonical inventory of the exemptions that need to exist.
func TestNoUngatedMutatingRoutes(t *testing.T) {
	// Allowlist: routes that intentionally do NOT use requireOpsPermissionFunc.
	// Each entry MUST have a justification comment.
	allowlist := map[string]string{
		// Manifest CRUD — console session through the outer auth gate plus the
		// in-handler manifest-write check; workflow credentials are rejected.
		`POST /api/v1/manifests`:        "console session plus in-handler manifest-write authorization",
		`DELETE /api/v1/manifests/{id}`: "console session plus in-handler manifest-write authorization",

		// Event publishing — exact-scope hashed publisher or the explicit,
		// expiring event-only migration bridge.
		`POST /api/v1/events`: "scoped event publisher or explicit expiring legacy event bridge",

		// Webhook receivers — external callers (no claims), HMAC-validated in-handler.
		`POST /api/v1/github/webhook`:                       "external GitHub webhook, HMAC-validated",
		`POST /api/v1/integrations/{instance_id}/webhook`:   "external provider webhook, per-instance HMAC",
		`POST /api/v1/integration-surfaces/{name}/sync`:     "workflow-token, manifest-sync addon",
		`POST /api/v1/integrations/{instance_id}/surface-query`: "workflow-token, manifest-sync addon",

		// Integration type sync — admin-token via in-handler check.
		`POST /api/v1/integration-types/{id}/sync`: "admin-token via in-handler authorizeAuthAdminRequest",

		// Authentication flow endpoints (login/password/MFA) — pre-session.
		`POST /api/v1/auth/passwords`:                              "admin-token via in-handler check",
		`POST /api/v1/auth/passwords/setup-tokens`:                 "admin-token via in-handler check",
		`POST /api/v1/auth/passwords/setup`:                        "pre-session setup-token flow",
		`POST /api/v1/auth/passwords/change`:                       "self password change",
		`POST /api/v1/auth/passwords/forgot`:                       "pre-session, rate-limited",
		`POST /api/v1/auth/passwords/reset`:                        "reset-token flow, pre-session",
		`POST /api/v1/auth/login`:                                  "pre-session, rate-limited",
		`POST /api/v1/auth/third-party/login`:                      "pre-session third-party",
		`POST /api/v1/auth/logout`:                                 "self logout",
		`POST /api/v1/auth/mfa/enroll/request`:                     "pre-session enroll",
		`POST /api/v1/auth/mfa/factors/totp/begin`:                 "self MFA enroll",
		`POST /api/v1/auth/mfa/factors/totp/finish`:                "self MFA enroll",
		`POST /api/v1/auth/mfa/factors/webauthn/begin`:             "self MFA enroll",
		`POST /api/v1/auth/mfa/factors/webauthn/finish`:            "self MFA enroll",
		// WebAuthn login flow — pre-session, BLOCKED password re-verify inside
		// the handler before assertion verification. Same authority shape as
		// POST /api/v1/auth/login (password+totp); cannot be RBAC-gated
		// because the caller is anonymous until the assertion finishes.
		`POST /api/v1/auth/mfa/webauthn/login/begin`:               "pre-session passkey challenge, password re-verified in handler",
		`POST /api/v1/auth/mfa/webauthn/login/finish`:              "pre-session passkey verify, password re-verified in handler",
		// Authenticated passkey rename/remove — self-only via guard()
		// (session required + requireSessionCollaborator pins the row).
		`PATCH /api/v1/auth/mfa/factors/webauthn/{credential_id}`:  "self via guard() — rename own passkey",
		`DELETE /api/v1/auth/mfa/factors/webauthn/{credential_id}`: "self via guard() — remove own passkey",
		`POST /api/v1/auth/mfa/recovery-codes`:                     "self MFA recovery, guard()",

		// SAML protocol endpoints — RFC 7522/8417 protocol callers, signature-validated.
		`POST /saml/sso`: "SAML protocol callback, IdP-signed",
		`POST /saml/slo`: "SAML protocol callback, IdP-signed",

		// Self-scoped routes — caller acts on their own session/preferences.
		`PATCH /api/v1/me/preferences`:    "self",
		`DELETE /api/v1/me/sessions/{id}`: "self via guard()",

		// Admin-token / OIDC protocol endpoints.
		`POST /api/v1/oidc/introspect`:                            "RFC 7662, bearer-or-manifest-token",
		`POST /api/v1/admin/collaborators/{id}/revoke-sessions`:   "admin-token only",
		`PATCH /api/v1/admin/oidc-clients/{id}`:                   "admin-token only",
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	serverPath := filepath.Join(filepath.Dir(thisFile), "server.go")
	f, err := os.Open(serverPath)
	if err != nil {
		t.Fatalf("open server.go: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Pattern that matches a mutating route registration. Captures
	// METHOD and PATH separately. Also accepts mux.Handle( for the
	// loginRateLimit wrapper.
	routeRe := regexp.MustCompile(`mux\.(?:HandleFunc|Handle)\("(POST|PATCH|PUT|DELETE) (/[^"]+)"`)
	wrapperRe := regexp.MustCompile(`requireOpsPermissionFunc\(perm[A-Za-z]+,`)
	deployTokenRe := regexp.MustCompile(`requireDeployToken\(`)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	type ungated struct {
		key  string
		line string
	}
	var (
		mutatingCount int
		gatedCount    int
		exemptCount   int
		ungatedFound  []ungated
	)

	for scanner.Scan() {
		line := scanner.Text()
		m := routeRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		method, path := m[1], m[2]
		// Skip /console/ routes: covered by TestConsoleRoutesAreFullyMapped.
		if strings.HasPrefix(path, "/api/v1/console/") {
			gatedCount++
			mutatingCount++
			continue
		}
		// Skip /ops/ routes: covered by TestOpsRoutesAreFullyMapped.
		if strings.HasPrefix(path, "/api/v1/ops/") {
			gatedCount++
			mutatingCount++
			continue
		}
		mutatingCount++
		key := method + " " + path
		if wrapperRe.MatchString(line) {
			gatedCount++
			continue
		}
		if deployTokenRe.MatchString(line) {
			gatedCount++
			continue
		}
		if _, ok := allowlist[key]; ok {
			exemptCount++
			continue
		}
		ungatedFound = append(ungatedFound, ungated{key: key, line: strings.TrimSpace(line)})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if mutatingCount == 0 {
		t.Fatalf("regex matched zero mutating routes — server.go shape changed; update TestNoUngatedMutatingRoutes")
	}

	if len(ungatedFound) > 0 {
		var lines []string
		for _, u := range ungatedFound {
			lines = append(lines, "  "+u.key+"\n    "+u.line)
		}
		t.Errorf("%d mutating /api/v1/* route(s) lack RBAC gate (INTEGRATION_CONTRACT §12) — wrap in requireOpsPermissionFunc(perm…) or add to the documented allowlist with justification:\n%s",
			len(ungatedFound), strings.Join(lines, "\n"))
	}

	t.Logf("mutating routes scanned=%d gated=%d allowlist-exempt=%d ungated=%d",
		mutatingCount, gatedCount, exemptCount, len(ungatedFound))
}
