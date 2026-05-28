// Hardening tests for redirect_uri validation — audit 2026-05-27 A9.
//
// The zitadel/oidc/v3 library validates redirect_uri via exact slice
// membership (`slices.Contains(client.RedirectURIs(), uri)` —
// vendor/github.com/zitadel/oidc/v3/pkg/op/auth_request.go::checkURIAgainstRedirects).
// Our clientView does NOT implement HasRedirectGlobs, so the glob path
// is never exercised — exact match is the only acceptance.
//
// These tests pin the behavior so a future change (e.g. someone adding
// glob support, or a clientView refactor that broadens the URI set)
// breaks the test before it breaks production. The threat model is the
// open-redirect class: an attacker who knows a real client_id steers
// the OP into emitting a code with an attacker-controlled redirect_uri,
// then exfiltrates the code via that redirect.
//
// Coverage:
//   - Canonical registered URI → allowed.
//   - Attacker URI not in the allowlist → rejected.
//   - Prefix attack (`https://tartaro.dakasa.me/cb.attacker.com`) →
//     rejected because exact equality fails. Documents the property
//     that allowlist must NEVER be relaxed to startswith.
//   - Path-injection / query-string fuzz → rejected (exact equality
//     is character-for-character).
//   - PostLogoutRedirectURI follows the same exact-equality contract
//     via op.ValidateEndSessionPostLogoutRedirectURI.

package oidc

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// fakeClient is a deterministic op.Client built from a model.OIDCClient
// without touching the DB. We use clientView's exposed methods directly
// (the redirect_uri validator only consults RedirectURIs() /
// ApplicationType() / response type — no DB hits).
func fakeClient(redirects, postLogout []string) op.Client {
	return newClientView(model.OIDCClient{
		ClientID:               "test-client",
		ClientSecretHash:       "$2a$10$irrelevant",
		RedirectURIs:           redirects,
		PostLogoutRedirectURIs: postLogout,
		Scopes:                 []string{"openid", "email", "profile"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCERequired:           true,
	}, "https://yggdrasil.test")
}

// TestRedirectURI_ExactMatch_Canonical: the canonical registered URI is
// accepted. Sanity baseline for the rest of the table.
func TestRedirectURI_ExactMatch_Canonical(t *testing.T) {
	client := fakeClient([]string{"https://tartaro.dakasa.me/auth/oidc/callback"}, nil)
	err := op.ValidateAuthReqRedirectURI(client, "https://tartaro.dakasa.me/auth/oidc/callback", oidc.ResponseTypeCode)
	if err != nil {
		t.Fatalf("canonical redirect_uri should be accepted, got: %v", err)
	}
}

// TestRedirectURI_ExactMatch_RejectsAttacker: a redirect_uri the client
// did NOT register is rejected, even if the attacker is on the same TLD.
// Without this guard the attacker can exfiltrate the authorization code.
func TestRedirectURI_ExactMatch_RejectsAttacker(t *testing.T) {
	client := fakeClient([]string{"https://tartaro.dakasa.me/auth/oidc/callback"}, nil)

	for _, attacker := range []string{
		"https://attacker.com/cb",
		"http://tartaro.dakasa.me/auth/oidc/callback",        // scheme downgrade
		"https://tartaro.dakasa.me/auth/oidc/callback/evil",  // path append
		"https://tartaro.dakasa.me/auth/oidc/callback?evil=1", // query append
		"https://tartaro.dakasa.me.attacker.com/auth/oidc/callback", // host suffix attack
		"https://tartaro.dakasa.me/auth/oidc/callback.attacker.com", // path-as-domain confusion
		"https://tartaro.dakasa.me//attacker.com/cb",         // double-slash hijack
		"//attacker.com/cb",                                   // protocol-relative
		"javascript:alert(1)",                                 // pseudo-scheme
	} {
		err := op.ValidateAuthReqRedirectURI(client, attacker, oidc.ResponseTypeCode)
		if err == nil {
			t.Errorf("attacker redirect_uri %q should be rejected, but was accepted", attacker)
		}
	}
}

// TestRedirectURI_ExactMatch_PrefixAttack: documents the security
// property — the allowlist must NEVER be relaxed to startswith. This
// test is what breaks if someone changes checkURIAgainstRedirects (or
// our clientView wraps it) to a HasPrefix check.
func TestRedirectURI_ExactMatch_PrefixAttack(t *testing.T) {
	client := fakeClient([]string{"https://tartaro.dakasa.me/cb"}, nil)

	// Canonical accepted — sanity.
	if err := op.ValidateAuthReqRedirectURI(client, "https://tartaro.dakasa.me/cb", oidc.ResponseTypeCode); err != nil {
		t.Fatalf("canonical should pass: %v", err)
	}
	// Prefix attacks rejected.
	for _, attacker := range []string{
		"https://tartaro.dakasa.me/cb.attacker.com",
		"https://tartaro.dakasa.me/cb/attacker.com",
		"https://tartaro.dakasa.me/cb?q=attacker.com",
		"https://tartaro.dakasa.me/cb#attacker.com",
	} {
		if err := op.ValidateAuthReqRedirectURI(client, attacker, oidc.ResponseTypeCode); err == nil {
			t.Errorf("prefix attack %q should be rejected", attacker)
		}
	}
}

// TestRedirectURI_ExactMatch_MultiRegisteredAllowed: clients registering
// multiple redirect URIs (e.g. one for dev, one for prod) get all of
// them accepted via exact match — but NOT an attacker URI that's "close"
// to either.
func TestRedirectURI_ExactMatch_MultiRegisteredAllowed(t *testing.T) {
	registered := []string{
		"https://tartaro.dakasa.me/auth/oidc/callback",
		"http://localhost:3000/auth/oidc/callback",
	}
	client := fakeClient(registered, nil)

	for _, uri := range registered {
		if err := op.ValidateAuthReqRedirectURI(client, uri, oidc.ResponseTypeCode); err != nil {
			t.Errorf("registered URI %q should be accepted, got: %v", uri, err)
		}
	}

	for _, attacker := range []string{
		"http://localhost:3001/auth/oidc/callback", // adjacent port
		"https://localhost:3000/auth/oidc/callback", // scheme upgrade
		"https://tartaro.dakasa.me/auth/oidc",      // path truncation
	} {
		if err := op.ValidateAuthReqRedirectURI(client, attacker, oidc.ResponseTypeCode); err == nil {
			t.Errorf("attacker URI %q should be rejected even with multi-register, got accept", attacker)
		}
	}
}

// TestRedirectURI_ExactMatch_EmptyAllowlist: a client with no registered
// redirect URIs has nothing to allow → every URI is rejected. Defends
// against a misconfigured client that would otherwise accept any URI.
func TestRedirectURI_ExactMatch_EmptyAllowlist(t *testing.T) {
	client := fakeClient([]string{}, nil)
	for _, uri := range []string{
		"https://tartaro.dakasa.me/cb",
		"https://anything.example/cb",
	} {
		if err := op.ValidateAuthReqRedirectURI(client, uri, oidc.ResponseTypeCode); err == nil {
			t.Errorf("URI %q with empty allowlist should be rejected, got accept", uri)
		}
	}
}

// TestPostLogoutRedirectURI_ExactMatch follows the same exact-equality
// contract on the end-session endpoint. The OP rejects with
// "post_logout_redirect_uri invalid" (vendor/.../op/session.go:144).
func TestPostLogoutRedirectURI_ExactMatch(t *testing.T) {
	client := fakeClient(nil, []string{"https://tartaro.dakasa.me/auth/oidc/post-logout"})

	if err := op.ValidateEndSessionPostLogoutRedirectURI("https://tartaro.dakasa.me/auth/oidc/post-logout", client); err != nil {
		t.Fatalf("canonical post_logout_redirect_uri should be accepted, got: %v", err)
	}
	for _, attacker := range []string{
		"https://attacker.com/cb",
		"https://tartaro.dakasa.me/auth/oidc/post-logout/evil",
		"https://tartaro.dakasa.me/auth/oidc/post-logout?evil=1",
		"https://tartaro.dakasa.me.attacker.com/auth/oidc/post-logout",
		"javascript:alert(1)",
	} {
		if err := op.ValidateEndSessionPostLogoutRedirectURI(attacker, client); err == nil {
			t.Errorf("post_logout attacker URI %q should be rejected", attacker)
		}
	}
}

// TestClientView_DoesNotImplementHasRedirectGlobs locks down the
// invariant that clientView is NOT a HasRedirectGlobs — the glob path
// in checkURIAgainstRedirects (vendor/.../op/auth_request.go:305) never
// fires for our clients. If someone later adds glob support to clientView
// they MUST also revisit this audit (A9): glob matching CAN open
// open-redirect holes when the pattern is sloppy
// (`https://*.dakasa.me/*` would accept the attacker host
// `evil.dakasa.me`).
func TestClientView_DoesNotImplementHasRedirectGlobs(t *testing.T) {
	client := fakeClient([]string{"https://tartaro.dakasa.me/cb"}, nil)
	if _, ok := client.(op.HasRedirectGlobs); ok {
		t.Fatalf("clientView must NOT implement HasRedirectGlobs — glob matching opens open-redirect holes; audit 2026-05-27 A9")
	}
}
