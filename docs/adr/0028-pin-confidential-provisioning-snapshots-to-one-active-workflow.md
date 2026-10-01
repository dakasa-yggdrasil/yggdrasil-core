# ADR-0028: Pin confidential provisioning snapshots to one active workflow

- **Status:** Proposed
- **Date:** 2026-10-01
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / identity provisioning workflow reads
- **Supersedes:** —
- **Superseded by:** —

## Context

The identity provider reconciliation workflow previously asked the
`integration-yggdrasil-self` adapter to list Core collaborators through
`GET /api/v1/collaborators`. That route requires authority the adapter must
not have. A shared Core token would expose unrelated Core operations, and a
normal workflow result would persist collaborator data in
`workflow_runs.result` and step metadata. ADR-0019's directory machine
principal is deliberately limited to exact active-email or ID lookups for a
different consumer; it cannot list collaborators.

The existing workflow is actorless on AMQP and its provider adapters can log
errors containing personal data. A full provider fanout therefore needs a
separate security review. The first safe increment is a Core-local, read-only
snapshot check with no per-person output or provider dispatch.

## Decision

Add the in-process `collaborator.provisioning_snapshot` step. It executes only
for the exact active `dakasa/reconcile-identity-providers` manifest ID named
by `YGGDRASIL_IDENTITY_PROVISIONING_WORKFLOW_MANIFEST_ID`. An unset, invalid,
inactive, historical, or different ID refuses execution. The operation also
requires `spec.authorization`, explicit manual trigger mode with
`enabled:false`, no runtime inputs, no run metadata, and no transitional
dispatch token. Its entire spec has one step, `list-collaborators`, with no
other integration or product operation; the producer condition may be absent
or literal `false` while its source is staged. ADR-0027 then rejects actorless
AMQP and repository-binding dispatch; a human console-session caller must pass
the workflow's RBAC/policy contract. Machine-principal async dispatch adds
server-authored run metadata, so this zero-metadata operation refuses that
channel. The HTTP handler binds both synchronous
and asynchronous execution to the exact manifest ID that passed this
authorization check. Async dispatch checks the snapshot constraints before
inserting `workflow_runs`.

At the read itself, start a transaction and lock the exact active workflow
manifest row with `SELECT ... FOR SHARE`. Read collaborators in the same
transaction. A concurrent replacement that commits first makes the exact-ID
check fail; one that begins later waits until the read finishes. Query at
most 1,001 rows and refuse a snapshot larger than 1,000 rather than silently
omitting a collaborator. Select only ID, canonical status, and primary email.
Reject unknown statuses, empty or
case-insensitively duplicated email addresses, and any database or scan
error. All failures return one fixed message without personal data.

The in-process step validates this narrow projection and returns only
`metadata.total_count`. Per-person fields never enter workflow template
context, the public response, `workflow_runs`, or a completion event. No
adapter token, `private://` collection, provider fanout, or provider mutation
is introduced by this decision. Canonical status is inspected but no provider
`active` value is inferred.

## Consequences

- An adapter cannot turn an integration credential into a broad Core
  collaborator-list credential.
- Replacing the active manifest requires a new explicit Core pin; the read
  rechecks the active row under a transaction lock after dispatch.
- The 1,000-person cap is a deliberate operational limit and must be reviewed
  before growth makes it insufficient.
- A later provider fanout requires a separate ADR and code changes proving
  that workflow results, transport errors, and adapter logs in Google
  Workspace, Slack, and GitHub cannot disclose personal data. This read-only
  operation does not authorize writes or activation of the workflow.
- CI must cover exact-manifest and actorless denial, concurrent-revocation
  behavior at the read boundary, narrow projection, invalid identity data,
  and absence of personal data in public workflow results. Local tests are
  not run on the owner's machine.

## Related

- ADR-0019 (separate exact-lookup directory machine authority)
- ADR-0027 (authenticated channels for workflows declaring authorization)
- DaKasa ADR-0284 (removed the self-adapter's broad Core bridge)
