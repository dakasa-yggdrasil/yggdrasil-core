# ADR-0019: Scope directory machine principals to exact collaborator read routes

- **Status:** Accepted
- **Date:** 2026-09-20
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / non-human directory read authentication
- **Supersedes:** none
- **Superseded by:** none

## Context

A service that mediates human approvals (the first consumer is the Social
publishing gate) must resolve a verified email to one canonical collaborator,
confirm that the collaborator is active, and read the collaborator's effective
Tartaro actions before it treats a message as an approval. The three routes
that answer those questions (`GET /api/v1/collaborators`,
`GET /api/v1/collaborators/{id}`, and
`GET /api/v1/collaborators/{id}/effective-tartaro-actions`) sit behind the
console authentication boundary and were reachable only by a human session or
a console OIDC JWT.

No existing machine credential could be used. Workflow and event principals
(ADR-0017) are accepted only on workflow-run and event-publish routes; the
deploy and auth-admin credentials are bound to their own route classes; the
OIDC provider issues only `authorization_code` and `refresh_token` grants, so
there is no client-credentials service subject. Copying a human session or
widening an existing principal would cross trust boundaries: the default
collaborator view carries personal, employment, provider, and trait data, and
the plain GET routes carry no per-service read scope. The consumer also must
not be able to choose a different Tartaro instance or search broadly.

## Decision

Introduce a third, independent machine inventory,
`YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON`, with the same hashed-credential
lifecycle as ADR-0017: each entry carries `principal_id`, `status`,
`expires_at`, `rotation_id`, optional `rotated_at`, and a 64-character
lowercase `token_sha256`. Raw bearers never enter the configuration. Each
entry additionally declares a non-empty `capabilities` list drawn only from
`directory.lookup_email`, `directory.read`, and
`directory.effective_actions`, and, exactly when `directory.effective_actions`
is present, a non-empty `allowed_tartaro_instances` list of exact
`{namespace,name}` references. Wildcards, duplicates, unknown fields, and
inconsistent capability/instance pairs reject the whole inventory. Boot fails
in every environment on a malformed inventory, and production boot also
rejects a directory digest that equals any plaintext bridge, the deploy or
auth-admin credential, or any workflow or event principal.

Accept a directory principal only on the three exact routes above, with the
GET method, a canonical lowercase hyphenated UUID, and no other path spelling.
The credential travels in `X-Yggdrasil-Directory-Token` or as an
`Authorization: Bearer` value. A request that presents the dedicated header,
or a bearer whose digest matches a configured directory principal in any
lifecycle state, is a directory machine attempt. The outer gate decides that
claim first, on every request, before its public pass-through and before any
other credential family, and a claimed request is served entirely by the
directory branch: it never continues to console JWT or session resolution,
never receives collaborator claims, and never reaches any handler, the mux,
or their permission middleware, on any path. Missing, unknown, expired,
disabled, or revoked credentials answer 401; a valid credential on any other
method, path spelling, or route family, on a route whose capability the
principal lacks, or on effective actions when the server's configured Tartaro
instance is not in the principal's allowlist, answers 403.

"Any other route family" is literal. Public routes (`/healthz`,
`/api/v1/tenant/brand`, `/api/v1/auth/session`, `/api/v1/auth/verify`, the
discovery documents, SCIM, auth administration reads), non-canonical spellings
that `net/http`'s `ServeMux` would otherwise answer with a redirect to the
clean path (`/api/v1//collaborators`, `/api/v1/./collaborators/{id}`,
`//api/v1/collaborators`), and canonical spellings that match no registered
pattern (`/API/v1/collaborators`) all answer 401 or 403 from the directory
branch with the usual audit row when the request names itself as a directory
attempt; none of them serves its public body, its redirect, or a 404 to such a
request. Callers that do not name themselves as directory attempts
(anonymous, session, console JWT, bearers matching no directory digest) keep
every route's existing behavior, including the mux's cleaned-path redirect,
so human console behavior is unchanged. The claim check loads the inventory
only when a request carries the dedicated header or a bearer.

The email lookup requires exactly `q=<one exact email>` and `status=active`,
accepts an optional `limit` between 1 and 100, and rejects every other query
parameter, wildcard, substring, or malformed address with 400 before touching
the database. The server compares the address exactly and case-insensitively
against `primary_email` on active rows only; a second matching row (impossible
under the unique index, but checked) fails closed with 500. The identity read
and effective-actions routes accept no query string and treat a collaborator
that is not `active` as absent (404). Responses use purpose-built projections:
`id`, `primary_email`, `display_name`, and `status` for identity, and
`collaborator_id` plus `computed_tartaro_actions` for effective actions. No
personal, employment, provider, trait, metadata, per-team, or drift data is
returned.

The effective-actions route is an authorization oracle for a machine
consumer, so it walks only memberships that Yggdrasil's own RBAC projection
honors at the moment of the read: the membership is active, the team is
active, and the request time falls inside the membership's optional
`starts_at`/`ends_at` window. That predicate is a single definition shared
with the RBAC subject resolver (`repository.authorizationMembershipPredicate`),
so the two views of "who is authorized now" cannot drift. The grant walk over
those teams (grants on the configured instance, wildcards ignored, sorted
union) is the same code the console route uses. The console drift view keeps
the broader active-membership set that the tartaro reactor materializes into
the `tartaro_actions` trait, so it still compares like with like; the machine
answer is therefore never wider than what Yggdrasil would authorize and may be
narrower than the materialized trait for an expired, not-yet-started, or
deactivated-team membership.

Any repository or database failure on the machine path answers 500
`internal.error` with the fixed body `directory is unavailable`; the driver
text is logged and never sent, and it never selects the status.

Every attributable outcome (one whose credential matched a configured
principal) writes one `directory.machine_read` audit row with actor
`service:<principal_id>`, the capability, the target collaborator id, the
outcome, and a reason, and the write is synchronous and fail-closed: the row
is stored before the outcome is answered, and when it cannot be stored the
outcome, including a 200 with data, is withheld and the request answers 500
`internal.error` with the fixed body `directory audit is unavailable`. The
only directory response that ever leaves without its row is that 500, which
is logged at error level with the principal, capability, target, outcome, and
reason. The row never carries the credential, the query string, or an email
address; its `trace_id` and `span_id` come only from a well-formed W3C
`traceparent` header (anything else is dropped, never stored), and a
directory `principal_id` is bounded at boot to 247 characters so the actor
`service:<principal_id>` fits its column, because a row the database rejects
is a row that was never written. A credential that matches no principal has
nothing to attribute and writes no row. Rotation and revocation are operator
actions on the inventory (add a new digest with a fresh `rotation_id`, then
retire the old entry); there is no mint endpoint and no automatic renewal.

## Consequences

- A leaked directory credential can only read identity fields of active
  collaborators one exact email or id at a time and the action names of the
  configured Tartaro instance. It cannot dispatch, publish, deploy, mutate,
  list, or read any other route family, and cannot be downgraded into a human
  session.
- Reading an approver's effective actions never grants the service those
  actions; the consumer remains responsible for evaluating the live human
  actor on every decision. The answer honors the membership window and team
  status, so it can be narrower than the materialized `tartaro_actions`
  trait; the console drift view is not narrowed.
- The audit store is on the read path. An `audit_events` outage makes the
  directory read unavailable (500) instead of serving unaudited data;
  consumers already treat 5xx as retry-later, never as a verdict.
- The console routes keep their existing behavior for human sessions and
  console JWTs; the directory branch is additive and only short-circuits
  requests that name themselves as machine attempts.
- Consumers must implement the fail-closed contract: 401 means the credential
  is unusable and the operator must rotate it; no approval or publication may
  proceed on 401, 403, or 5xx.
- The audit trail gains one action for the whole machine path; operators
  filter by `metadata.capability` and `metadata.reason`.

## Related

- ADR-0017 (refines: reuses the hashed principal lifecycle and adds a third, isolated scope)
- ADR-0009 (depends-on: team-scoped Tartaro action grants are the source of computed actions)
