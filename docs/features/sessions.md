# Sessions and OAuth/OIDC

How humans and bots authenticate to Yggdrasil and stay authenticated.
Two paths into a session — password and third-party identity (OAuth /
OIDC). Both produce the same kind of bearer token + cookie; downstream
authorization is identical.

## Sessions

A session is a row in `auth_session`. It's bound to one collaborator,
has a server-side TTL (default 720h = 30 days, env-tunable), and holds
arbitrary `metadata` populated at login (`source`, IP, user-agent,
device id).

```json
{
  "id":              "01935...",
  "collaborator_id": "01935...",
  "status":          "active",
  "metadata":        { "source": "web", "ip": "..." },
  "last_seen_at":    "2026-04-23T...",
  "expires_at":      "2026-05-23T...",
  "revoked_at":      null,
  "created_at":      "...",
  "updated_at":      "..."
}
```

Logout revokes immediately (`revoked_at` set, `status = revoked`).
Expired sessions are filtered at resolution time and lazily reaped by
a background job.

## Password login

```http
POST /api/v1/auth/login
{ "identifier": "ana", "password": "..." }
```

Verifies the password credential first. If MFA has not been enrolled,
the API returns `428` with `code: "mfa_not_enrolled"` and an
`enroll_url`; no session is issued. If MFA is enrolled but the request
does not include a supported second factor, the API returns `202` with
`code: "mfa_required"`:

```json
{
  "code": "mfa_required",
  "factors": ["totp", "recovery_code"]
}
```

The client completes login by repeating the same request with
`totp_code` or a single-use `recovery_code`:

```http
POST /api/v1/auth/login
{ "identifier": "ana", "password": "...", "totp_code": "123456" }
```

```http
POST /api/v1/auth/login
{ "identifier": "ana", "password": "...", "recovery_code": "ABCD-EFGH-IJKL-MNOP" }
```

Only after the MFA factor validates does the API open a session and
return the bearer + Set-Cookie. Recovery codes are consumed on success
and cannot be reused.

The first admin's password credential is created by the bootstrap
addon — see [getting-started.md](../getting-started.md). Subsequent
collaborators get credentials via `POST /api/v1/auth/passwords`.

## Third-party identity (OAuth / OIDC)

The infrastructure is a generic OAuth 2.0 / OIDC client backed by
provider configuration stored as `third_party_auth_provider`
manifests:

- GitHub
- Google
- Custom OIDC

Configure via the CLI:

```sh
yggdrasil auth provider apply -f docs/auth-providers/github.example.yaml
```

The provider manifest stores: `authorize_url`, `token_url`,
`userinfo_url`, `scopes`, `client_id`, `client_secret_ref` (managed
secret), and field mappings (`subject_field`, `email_field`, etc.) so
the same code path handles GitHub, Google, and arbitrary OIDC servers.

### Browser flow

```
GET  /api/v1/auth/third-party/start/{provider}
     → 302 redirect to provider's authorize URL with signed state cookie
GET  /api/v1/auth/third-party/callback/{provider}?code=...&state=...
     → core verifies state, exchanges code for token,
       fetches userinfo, links/creates collaborator,
       opens session, sets cookie
```

State signing prevents CSRF. The signing key is config (
`AUTH_THIRD_PARTY_STATE_SECRET`); rotate per the
[security guide](../security.md).

### Auto-link by email

When `auto_link_by_email: true` on the provider, a successful
third-party login matches the userinfo email against existing
collaborators. If a single match exists, the third-party identity is
linked to that collaborator. Otherwise a new collaborator is created.

This is the right default for most teams (engineers' GitHub email
already matches their work email). Disable it when you want admin
review for every cross-IdP link.

### Identities

A `third_party_identity` row holds the (provider, subject) → collaborator
mapping. One collaborator can hold many identities (GitHub + Google +
custom OIDC). Identities can be unlinked via
`DELETE /api/v1/auth/third-party-identities/{provider}/{subject}`.

## Token transport

The bearer issued at login can travel as:

- A `Authorization: Bearer <token>` header (the CLI's default).
- A cookie (the browser default — name configurable via
  `AUTH_SESSION_COOKIE_NAME`, defaults `yggdrasil_session`).
- A header for workflow-run callbacks: `X-Yggdrasil-Workflow-Token`.

All three resolve through the same session lookup.

## Wire shape — session resolution

```http
GET /api/v1/auth/session
Authorization: Bearer <token>
```

```json
{
  "authenticated": true,
  "session": { "id": "...", "expires_at": "...", "metadata": { ... } },
  "collaborator": { "id": "...", "slug": "ana", "primary_email": "..." }
}
```

The CLI uses this implicitly during `yggdrasil status`; surfaces (e.g.
the console) hit it on every page load to render the user widget.

## Operate it

**Monitor:**

- Login success/failure rate. Repeated failures from one IP are
  brute-force candidates; surface them via your IDS.
- Active session count. Sudden growth often means an automation
  forgot to logout — track per `metadata.source`.
- Third-party callback errors (`state mismatch`, `code exchange
  failed`). These point at provider config drift.

**Back up:**

`auth_session`, `password_credential`, `third_party_identity`, and
`third_party_auth_provider` are all in the standard Postgres backup.
Note: revoking and re-issuing tokens on restore is a one-time
disruption; communicate it.

**Tune:**

- `AUTH_SESSION_TTL_HOURS`. 720 (30 days) is the default; tighten for
  human surfaces, loosen for bot tokens issued out-of-band.
- `AUTH_SESSION_COOKIE_SECURE`. Default `false` for compose-on-laptop.
  Always `true` in production behind TLS.
- `AUTH_SESSION_COOKIE_DOMAIN`. Set to your apex when surfaces share
  the cookie (`yggdrasil.example.com` and `console.example.com`).

## Pitfalls

- **Long-lived tokens for bots.** A 30-day token shared with CI is a
  liability. Issue scoped, short-lived tokens via a CI-specific
  collaborator, rotate on a schedule.
- **Email-based auto-link with shared inboxes.** Two collaborators
  sharing an alias merge into one when auto-link is on. Disable
  auto-link OR ensure unique primary emails.
- **Provider client secrets in `spec`.** Always set `client_secret_ref:
  managed-secret-name`; the inline `client_secret` field exists for
  the upsert request but is materialized into a managed secret on
  write — never inspect-able after.
- **Token in URL query strings.** Some integrations want a token in
  a callback URL. Don't. URLs leak via referrer headers and proxy
  logs. Use POST + Authorization header.
