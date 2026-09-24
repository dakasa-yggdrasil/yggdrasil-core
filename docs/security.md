# Security

How Yggdrasil handles authentication, authorization, secrets, and
network boundaries in a self-hosted deployment.

## Authentication

Two paths, both converging on a session row + bearer token after MFA:

1. **Password** — `/api/v1/auth/login`. Credentials checked against
   `password_credential` table. A valid password returns
   `mfa_required` until the caller supplies a valid `totp_code` or
   single-use `recovery_code`; a session is not issued from password
   alone.
2. **OAuth/OIDC** — `/api/v1/auth/third-party/start/<provider>` →
   redirect to the provider → `/api/v1/auth/third-party/callback/
   <provider>` → session issued. Provider config lives in
   `third_party_auth_provider` table (see
   [docs/auth-providers/](./auth-providers/)).

MFA enrollment is mandatory. If a collaborator has no MFA enrollment,
auth paths return `mfa_not_enrolled` and the console guides the user
through TOTP enrollment before any session can be created.

Sessions carry a server-side expiry (`AUTH_SESSION_TTL_HOURS`, 720
default = 30 days). Revocation is immediate via
`/api/v1/auth/logout`.

The first admin on a fresh install is provisioned by the
`first_run_bootstrap` addon. Once the DB has any collaborator, the
addon becomes a no-op — it cannot be coerced into overwriting.

### Access links and account recovery

No link ever stands in for the second factor. A link proves possession
of a URL, and URLs travel through chat and email.

| Situation | Path | What the link can do |
|---|---|---|
| First access | Admin issues a setup link (`POST /auth/passwords/setup-tokens`) | Sets the password, then answers `428 mfa_not_enrolled` with an enroll link; the session only exists after enrollment |
| Lost password, has the second factor | Self-service: `POST /auth/passwords/forgot` emails a reset link; `POST /auth/passwords/reset` takes the new password plus a TOTP or recovery code | Opens a session only after the factor is proven; revokes every older session |
| Lost password, self-service unavailable | Admin issues a setup link for the existing account | Sets the password and revokes older sessions, then answers `200 {next: "login"}` with no cookie: the person signs in with the new password and their factor |
| Lost second factor (with or without the password) | Admin issues a setup link with `reset_mfa: true` | Wipes TOTP, passkeys, recovery codes **and the password** in the same transaction that issues the link, so the old password stops working at once (otherwise a leaked password could enroll its own authenticator before the owner opens the link); then behaves as a first access. Audited as `credential.mfa_reset` and `auth.mfa.reset` with the acting admin (or `service:auth-admin-token`) |

Link rules:

- Setup and reset links are single-use and replace any earlier link of
  the same purpose. A rejected password (`422`, with `reason` in
  `too_short`, `contains_identity`, `too_common`) never consumes the link.
- Every path that replaces a credential through a link (setup re-access,
  reset, `reset_mfa`) runs the §13 fan-out: console sessions and OIDC
  refresh tokens are revoked, a `session_revocation` row is written,
  `collaborator.session.terminated` is emitted and back-channel logout
  fires. A first access has nothing to revoke and emits nothing.
- A setup link clears the login lockout (`failed_attempts`,
  `locked_until`): the next step for an enrolled account is the login.
- `/auth/passwords/forgot` and `/auth/passwords/reset` follow the login's
  status rule (only `active` signs in): other statuses, including
  `pending_start`, get no link and a `403` on the reset and its preflight.
  The setup commit keeps admitting `pending_start` because it opens no
  session.
- `/auth/passwords/reset` sits behind the per-IP login rate limit and
  reserves one of five second-factor attempts atomically before checking
  the code, so concurrent requests cannot exceed the cap. A request with
  no TOTP or recovery code (or only a passkey assertion, `501`) is
  answered before any attempt is spent. A wrong code keeps the link
  alive (`attempts_remaining` in the `401`); the fifth failure burns it.
- `GET /auth/passwords/setup/preflight` and
  `GET /auth/passwords/reset/preflight` validate a link without
  consuming it and report the account posture and the password policy,
  so the console can pick the right journey before asking for anything.
  The setup preflight's `account.recovery` marks an account whose existing
  password or factor a full recovery wiped (the issuance records
  `replaced_credential`; the wipe itself leaves nothing to tell a returning
  person from a new hire) while it has no password and no factor yet, even
  when a later plain access link replaced the recovery one; the
  reset preflight's `has_passkey` tells a passkey-only account (needs a
  plain access link) from one with no factor left.
- Link issuance takes a per-collaborator transaction lock, so two
  concurrent issuances (two admins, a double submit) run one after the
  other and the newer link always replaces the older one.
- `auth_credential_tokens.created_by` records the issuing admin and is set
  to NULL if that admin is deleted.
- `GET /auth/passwords/forgot/options` reports whether self-service
  reset can deliver email; when it cannot, the console sends people to
  an administrator instead of a form that goes nowhere.

Reset email delivery goes through an integration instance that exposes
`send_email` (`integration-aws` SES or `integration-google-workspace`),
never a provider SDK in the core:

| Variable | Meaning |
|---|---|
| `AUTH_EMAIL_INTEGRATION` | `<namespace>/<name>` of the `send_email` instance. Unset: self-service reset is reported unavailable |
| `AUTH_EMAIL_FROM` | Sender address. Optional; the adapter falls back to its instance config |
| `YGGDRASIL_CONSOLE_URL` / `YGGDRASIL_PUBLIC_BASE_URL` | Origin of the link in the email. Required: the core never builds an emailed link from the request `Host` or `X-Forwarded-Host`, which would let an anonymous `/forgot` call mail a real token to an attacker's domain |
| `AUTH_PASSWORD_RESET_TOKEN_TTL` | Reset link lifetime (default `24h`) |
| `AUTH_PASSWORD_SETUP_TOKEN_TTL` | Setup link lifetime (default `48h`) |

### Non-human principals

Workflow automation is configured through
`YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON`. Each principal has
`principal_id`, lifecycle `status`, `expires_at`, `rotation_id`, an optional
`rotated_at`, a 64-character lowercase `token_sha256`, and a non-empty
`allowed_workflows` list of exact `{namespace,name}` pairs. Raw bearer values
must stay in the caller's secret store; they are never placed in this JSON.
The core hashes the presented bearer and compares digests in constant time.

The allowlist is mandatory, and a selected workflow without
`spec.authorization` is denied to machine principals. The declared RBAC and
optional policy decision are an additional mandatory restriction. Machine
callers must select the current active manifest by namespace/name;
`manifest_id` and explicit `version` selectors are denied. A machine principal
may call only
`POST /api/v1/workflow-runs` and poll its own run through
`GET /api/v1/workflow-runs/{run_id}`. Its authenticated `principal_id` is
written by the server into async run metadata; client attempts to choose that
reserved field are discarded. Hashed machine dispatch is always async even if
the caller asks for `async=false` or a `sync` header. The async worker uses the
panic-safe goroutine wrapper; a panic records only a generic failed-run error
before being recovered and counted. Foreign and absent runs both return 404.

Event writers use a separate
`YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON` inventory with the same hash and
lifecycle fields, no workflow allowlist, and a non-empty `allowed_events` list
of exact `{provider,instance_id,event_type}` mutation triples. Machine event
principals are accepted only on `POST /api/v1/events`, cannot publish the
generic event shape, and have their actor identity bound by the server;
human console sessions are rejected because this machine route has no event
publish RBAC wrapper. The plaintext event bridge is also mutation-only and is
bound to the reserved `legacy-event-publish-bridge` service actor. Workflow and
event credentials are mutually isolated. Workflow credentials never authorize
manifests, secrets (including
`include_values=true`), `/console`, generic `/ops`, deploy, tenant, or
auth-admin routes.

Directory readers use a third, isolated inventory,
`YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON` (ADR-0019), with the same hash,
lifecycle, and rotation fields plus a non-empty `capabilities` list drawn from
`directory.lookup_email`, `directory.read`, and `directory.effective_actions`,
and, only with the last one, a non-empty `allowed_tartaro_instances` list of
exact `{namespace,name}` references. The credential travels in
`X-Yggdrasil-Directory-Token` or as a bearer and is accepted only on
`GET /api/v1/collaborators?q=<one exact email>&status=active[&limit=1..100]`,
`GET /api/v1/collaborators/{canonical uuid}`, and
`GET /api/v1/collaborators/{canonical uuid}/effective-tartaro-actions`, each
gated by its own capability and, for effective actions, by the configured
Tartaro instance being allowlisted. The outer gate decides the directory
claim first, on every request, before its public pass-through and before any
other credential family, so a request that names itself as a directory
attempt is served by the directory branch alone on any path: it never reaches
a handler, the mux, console session or JWT resolution, never receives
collaborator claims, and answers 401 for missing, unknown, expired, disabled,
or revoked credentials and 403 for any other method, path spelling, route
family, missing capability, or unlisted instance. That includes public routes
(`/healthz`, `/api/v1/tenant/brand`, `/api/v1/auth/session`,
`/api/v1/auth/verify`, discovery documents, SCIM), non-canonical spellings
the mux would otherwise redirect to a clean path, and canonical spellings that
match no route: none serves its body, its redirect, or a 404 to a directory
attempt. Callers that do not name themselves as directory attempts keep every
route's existing behavior. Responses carry only `id`, `primary_email`,
`display_name`, and `status`, or `collaborator_id` and
`computed_tartaro_actions`; inactive collaborators read as absent. The
effective actions are computed only from memberships the RBAC projection
honors now (membership active, team active, inside the `starts_at`/`ends_at`
window, one shared predicate), so the machine answer is never wider than what
Yggdrasil would authorize. Any database failure answers a fixed 500
`internal.error` (`directory is unavailable`) without the driver text. Each
attributable outcome writes a `directory.machine_read` audit row before it is
answered; the write is synchronous and fail-closed, so when the row cannot be
stored the outcome is withheld and the request answers 500 `internal.error`
(`directory audit is unavailable`) instead. Each withheld outcome is counted
once in the Prometheus counter `yggdrasil_directory_audit_failures_total`
on `/metrics`, labeled `reason` with `store_unconfigured` (the server has no
audit writer), `insert_timeout` (the synchronous write deadline fired), or
`insert_failed` (the store rejected the row), so an audit store outage on the
read path is visible without reading logs. The row never carries the
credential, the query string, or any email; its trace reference comes only
from a well-formed W3C `traceparent`, and a directory `principal_id` is
bounded to 247 characters so the audit actor fits its column. The inventory
is loaded and validated once at boot and held by the server; the request
path matches credentials against that copy and never reads the environment
again, so a malformed inventory can only refuse the boot, never a request,
and a rotation written to the environment of a running process takes effect
only at the next boot. Boot fails on a malformed directory inventory in every
environment, and production boot rejects a directory digest shared with any
other credential scope.

`YGGDRASIL_AUTH_ADMIN_TOKEN` remains a purpose-built credential for the exact
provider, SCIM, and SAML administration mutations that support machine
bootstrap. Only that static credential may use the outer route bypass, and the
destination handler revalidates it. Human administrator sessions still pass
through the normal MFA, CSRF, claims, and RBAC pipeline.

The old plaintext `YGGDRASIL_WORKFLOW_RUN_TOKEN` is accepted only when
`YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED=true` and
`YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT` is a future RFC3339 timestamp. It
remains workflow dispatch/poll-only. `YGGDRASIL_EVENT_PUBLISH_TOKEN` is the
separate plaintext event-only migration bridge and requires
`YGGDRASIL_EVENT_PUBLISH_LEGACY_ENABLED=true` plus a future RFC3339
`YGGDRASIL_EVENT_PUBLISH_LEGACY_EXPIRES_AT`. Production boot requires an
active, unexpired workflow credential and an independent event credential and
rejects malformed, wildcarded, duplicate, expired-only, or cross-scope
configuration. A plaintext bridge bearer must also differ from hashed
principals in the same scope, preventing expiry or revocation from downgrading
the bearer to bridge authority. The raw-token
`YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON` format is rejected.

## Authorization

For workflow machine dispatch, `spec.authorization` is mandatory and two
evaluation phases happen in order after the machine allowlist check:

1. **RBAC** — `rbac` manifests define (subject, action, resource)
   tuples. `/api/v1/authorization/evaluate` returns whether the
   caller's session has the needed grant.
2. **Policy** — `policy` manifests layer guardrails on top (rate
   limits, data residency, blast-radius caps, approval gates). A
   request denied by a policy is rejected with a structured error
   that names the policy.

Both phases record a `authorization.evaluated` event — the audit
trail is complete.

## Audit trail

Every audited outcome of the HTTP API is one row in `audit_events`
(migration 00017). Four writers in `controllers/httpapi` produce them: the
handler audit (`recordAudit`: manifest create and delete, warnings
persistence, workflow template instantiation), the auth audit
(`recordAuthAuditSync`: the closed `auth.*` action set for login, MFA,
session, and password outcomes), the directory machine-read audit described
above, and the ops permission gate (`recordOpsAuditDenied`: one
`ops.permission.denied` row per call `requireOpsPermission` refuses in
enforce mode, through the ops row shape of migration 00031). The
OIDC provider writes its `resource_kind=oidc` rows from `controllers/oidc`.
All of them are fire-and-forget (an insert failure is logged and never gates
the request) except the directory writer, which is synchronous and
fail-closed.

Two request headers reach the fixed-width columns of a row, and neither
reaches them raw (ADR-0020). A row's `trace_id` and `span_id` come only from
a well-formed W3C `traceparent` header, through the one parser
`recordAudit`, `recordAuthAuditSync`, and the directory writer share
(`internal/tracecontext`). The optional `X-Yggdrasil-Actor` header, which
lets a caller declare the actor a `recordAudit` row is attributed to, is
stored only when it is `user:<id>` or `service:<name>` (ASCII) and at most
255 characters, the width of `actor`; otherwise the row is attributed to
the credential (`service:bearer-token` or `anonymous`). Any other value,
including an oversized one, is dropped rather than truncated or stored, so
a caller cannot pick a header the `VARCHAR(64)`, `VARCHAR(32)`, or
`VARCHAR(255)` columns reject and thereby erase the audit line of its own
login, MFA attempt, or manifest write. The declared actor is bounded, not
verified: the server does not check it against the credential.

The ops audit middleware `withOpsAudit`, which would store `X-Correlation-ID`
in `correlation_id`, is not attached to any route, and the live ops writer
reads no request header. `correlation_id` is `TEXT`, but its btree index
(`audit_events_correlation_idx`, migration 00031) rejects values of about
2.7 KB or more while the server accepts headers up to the 1 MiB default, so
that header needs the same bounding before the middleware is ever attached.

## Secrets

Never embedded in manifests directly. Three supported referencing
modes:

1. **Managed secrets** — `client_secret_ref: my-oauth-secret`
   resolves to a row in `managed_secret`. Secrets are encrypted at
   rest with a key bound to the deployment.
2. **External secret** — `password_ref: secret://…` (and the
   equivalent `*_ref` fields) on a `control_plane` manifest resolve to
   a Kubernetes Secret the cluster owns; the rendered Deployment mounts
   it via `secretKeyRef`.
3. **Environment variables** — the `control_plane`-rendered Deployment
   injects config as env; sensitive values come from referenced
   Secrets, never inline. `yggdrasil init` (compose mode) stores
   secrets in the local `.env` file (0600).

Adapters in `integration-*` repos consume credentials at RPC call
time from `integration_instance.credentials`, which itself uses the
same reference mechanism.

## Network

`yggdrasil-core` only needs outbound to:

- Postgres (internal) — the only always-required dependency.
- RabbitMQ (internal) — only when an integration declares the
  `rabbitmq` transport (opt-in; HTTP-only otherwise).
- HTTP integration adapters (internal) — when integrations use the
  default `http_json` transport.
- OAuth/OIDC provider token endpoints (when OIDC is configured).
- GitHub API (when `yggdrasil install` is triggered against a
  private repo).

Integration adapters need outbound to whatever the integration
targets (your Kubernetes cluster, your Grafana, your AWS account).
They never share network boundaries with each other unless you
deploy them in the same namespace.

Inbound is HTTP only. In production, front with a TLS-terminating
ingress or gateway. The session cookie is `Secure` by default;
cookie name and domain are configurable
(`AUTH_SESSION_COOKIE_NAME`, `AUTH_SESSION_COOKIE_DOMAIN`).

## Container security

The `yggdrasil-core` image runs as non-root (uid 65532, enforced by
the `podSecurityContext` on the `control_plane`-rendered Deployment).
Capabilities are dropped; privilege escalation is denied. No shell is
shipped in the image — only the binary.

## Responsible disclosure

Security issues: email security@dakasa.me with a reproduction and
your proposed severity. Do NOT open a public GitHub issue.

We aim to acknowledge within 2 business days and ship a fix within
30 days for high/critical severity.
