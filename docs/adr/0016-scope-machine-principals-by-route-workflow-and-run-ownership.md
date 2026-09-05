# ADR-0016: Scope machine principals by route, workflow, and run ownership

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / non-human HTTP authentication and workflow dispatch
- **Supersedes:** ADR-0013
- **Superseded by:** —

## Context

CI jobs and integration adapters historically shared one plaintext workflow
token. That credential could dispatch every workflow and was also accepted by
event publishing, manifest mutation, deploy, and generic operator routes. A
leak therefore crossed unrelated trust boundaries. Async polling and global
idempotency also returned durable run identifiers without binding them to the
machine identity that created the run.

The replacement must support independent rotation without storing raw bearer
values in configuration. An exact machine allowlist limits which workflow is
selected, but it does not constrain dangerous inputs or express the explicit
RBAC grant required to leave quarantine. Machine dispatch must therefore depend
on a manifest authorization block as well as the principal allowlist.

## Decision

Configure workflow machine principals in
`YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON`. Each entry contains only a
64-character lowercase `token_sha256` digest plus `principal_id`, `status`,
`expires_at`, `rotation_id`, an optional `rotated_at`, and a non-empty
`allowed_workflows` list. Every workflow reference contains an exact
`namespace` and `name`; wildcard syntax is invalid. The core hashes a presented
bearer with SHA-256 and compares digests in constant time.

Authorize a workflow machine principal only on exact workflow dispatch and
polling routes. Resolve the workflow manifest first, enforce the principal's
exact allowlist, and deny machine dispatch if `spec.authorization` is absent.
Machine callers must select by namespace/name and always resolve the current
active manifest; `manifest_id` and explicit `version` selectors are denied so a
caller cannot choose a historical or inactive contract under an allowed logical
name. The declared RBAC and optional policy are additional mandatory
restrictions. A workflow credential never authorizes events, manifests, deploy,
auth administration, tenant administration, secrets, catalogs, or generic
operator APIs. Always route hashed machine dispatch through durable asynchronous
execution, even if the request asks for `async=false` or `sync`; synchronous
execution does not establish run ownership or principal-scoped idempotency and
would return the complete workflow response directly. Launch the background
worker through `internal/goroutine.SafeGo` with the stable
`workflow_run_async` label. If execution panics, record a generic failed state
on the durable run before re-panicking into `SafeGo`; the panic value is never
written to the run result.

Keep the dedicated plaintext auth-admin credential compatible only on the
registered provider, SCIM, and SAML mutation route shapes. Its outer-gate
bypass recognizes the static credential itself; a human administrator session
continues through normal session resolution, MFA, CSRF, claims, and RBAC. Each
destination handler revalidates auth-admin authorization.

Configure event publishers independently in
`YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON`. Event entries carry the same hash,
lifecycle, and rotation fields, cannot contain a workflow allowlist, and require
a non-empty `allowed_events` list of exact
`{provider,instance_id,event_type}` integration-mutation triples. They are
accepted only for `POST /api/v1/events`; generic event payloads and mutations
outside the authenticated principal's exact triples are denied. The server
overwrites client actor and reserved publisher metadata with the authenticated
principal. Human console sessions are not authorized on this unwrapped machine
route. Cross-scope credential digest reuse is a production boot error.

For asynchronous workflow runs, overwrite any client-supplied creator field and
persist the authenticated `principal_id` under reserved metadata key
`yggdrasil.io/creator_machine_principal_id`. Machine polling adds that ownership
predicate to the database query and returns the same 404 for foreign and absent
runs. Persist a SHA-256 digest of `(principal_id, client idempotency key)` in the
existing `metadata.idempotency_key` slot. This keeps retries stable for one
principal without changing the SQL schema or allowing the global unique index to
return another principal's run. Restore the caller's original key only in the
in-memory execution copy.

Keep `YGGDRASIL_WORKFLOW_RUN_TOKEN` solely as an explicit migration bridge. It
is accepted only when `YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED=true` and
`YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT` is a future RFC3339 timestamp, and
only on workflow dispatch and polling routes. It never publishes events or
performs administrative writes. Keep plaintext
`YGGDRASIL_EVENT_PUBLISH_TOKEN` temporarily as an event-route-only bridge for
existing adapters, accepted only with
`YGGDRASIL_EVENT_PUBLISH_LEGACY_ENABLED=true` and a future RFC3339
`YGGDRASIL_EVENT_PUBLISH_LEGACY_EXPIRES_AT`. The bridge accepts only integration
mutation payloads, never generic events, and the server replaces any client
actor with the reserved `legacy-event-publish-bridge` service identity.
Production boot requires a usable workflow credential and a separate usable
event credential, while allowing both plaintext bridges to be absent when
hashed workflow and event principals exist.

Remove the repository-generic, default-on deploy emitter from core. Its target
accepted caller-selected repository, workflow, ref, and environment inputs and
therefore was not a safe consumer of workflow machine credentials. Automatic
emission may return only with a purpose-bound caller and a typed workflow whose
authorization and input policy freeze the permitted target. The historical
generic bootstrap manifest is not allowlisted or authorized for a hashed
machine principal and remains quarantined from automatic invocation.

Reject the former `YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON` configuration
because it stores raw scoped bearer tokens. Invalid, empty, duplicate,
expired-only, wildcarded, or credential-reusing production configuration fails
boot without printing token values or digests. In particular, a hashed event
principal cannot reuse the plaintext event bridge bearer: otherwise expiry or
revocation of that principal would downgrade the same credential to the
broader bridge.

## Consequences

- A leaked CI credential reaches only workflows in its exact allowlist that
  also explicitly grant its machine subject through manifest authorization,
  only through the current active namespace/name contract, and only its own
  forced-async runs.
- Adapter event publishers cannot dispatch workflows, publish generic events,
  or impersonate another configured provider/instance/event scope; workflow
  callers cannot publish events.
- Rotation can overlap by adding a new principal entry or changing lifecycle
  status without storing raw credentials in the core configuration.
- Machine idempotency metadata contains an internal scoped digest rather than
  the caller's raw idempotency key. Workflow execution still sees the original
  value in memory.
- A panic in forced-async execution is recovered at the process boundary, and
  core attempts to finalize the durable run with only a generic failure
  message before recording the panic metric.
- Existing async rows without creator metadata remain visible to human console
  sessions and the time-bounded legacy workflow bridge, but not to hashed
  machine principals.
- Operators must migrate CD callers and adapters before removing the two
  explicitly expiring plaintext bridges. Each bridge must use a value distinct
  from every hashed or plaintext credential, including principals in the same
  event scope.
- No push-to-main workflow in core automatically submits the generic
  repository-commit workflow request.

## Related

- ADR-0013 (superseded event credential bridge)
- ADR-0015 (async input validation and redaction boundary)
