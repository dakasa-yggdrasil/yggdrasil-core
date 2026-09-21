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
(`directory audit is unavailable`) instead. The row never carries the
credential, the query string, or any email; its trace reference comes only
from a well-formed W3C `traceparent`, and a directory `principal_id` is
bounded to 247 characters so the audit actor fits its column. Boot fails on a
malformed directory inventory in every environment, and production boot
rejects a directory digest shared with any other credential scope.

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
(migration 00017), written by one of three writers: the handler audit
(`recordAudit`: manifest create and delete, warnings persistence, workflow
template instantiation), the auth audit (`recordAuthAuditSync`: the closed
`auth.*` action set for login, MFA, session, and password outcomes), and the
directory machine-read audit described above. The first two are
fire-and-forget (an insert failure is logged and never gates the request);
the directory writer is synchronous and fail-closed.

A row's `trace_id` and `span_id` come only from a well-formed W3C
`traceparent` header, through the one parser every writer shares
(`internal/tracecontext`, ADR-0020). Any other value, including an oversized
one, is dropped rather than truncated or stored, so a caller cannot pick a
header the `VARCHAR(64)` and `VARCHAR(32)` columns reject and thereby erase
the audit line of its own login or MFA attempt. The ops routes also store
`X-Correlation-ID` in `correlation_id` through their own middleware; that
value never reaches the trace columns.

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
