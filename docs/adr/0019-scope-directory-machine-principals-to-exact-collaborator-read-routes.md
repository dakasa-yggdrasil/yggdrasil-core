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
lifecycle state, is a directory machine attempt and is served entirely by the
directory branch of the outer gate: it never continues to console JWT or
session resolution, never receives collaborator claims, and never reaches the
console handlers or their permission middleware. Missing, unknown, expired,
disabled, or revoked credentials answer 401; a valid credential on any other
method, path variant, or route family, on a route whose capability the
principal lacks, or on effective actions when the server's configured Tartaro
instance is not in the principal's allowlist, answers 403.

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
returned. The effective-actions computation is the same code the console
route uses.

Every attributable outcome writes one `directory.machine_read` audit row with
actor `service:<principal_id>`, the capability, the target collaborator id,
the outcome, and a reason. The row never carries the credential, the query
string, or an email address. Rotation and revocation are operator actions on
the inventory (add a new digest with a fresh `rotation_id`, then retire the
old entry); there is no mint endpoint and no automatic renewal.

## Consequences

- A leaked directory credential can only read identity fields of active
  collaborators one exact email or id at a time and the action names of the
  configured Tartaro instance. It cannot dispatch, publish, deploy, mutate,
  list, or read any other route family, and cannot be downgraded into a human
  session.
- Reading an approver's effective actions never grants the service those
  actions; the consumer remains responsible for evaluating the live human
  actor on every decision.
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
