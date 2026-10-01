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
not have. A shared Core token would expose unrelated Core operations and a
normal workflow result would persist full collaborator data in
`workflow_runs.result`, step metadata, and template context. ADR-0019's
directory machine principal is deliberately limited to exact active-email or
ID lookups for a different consumer; it cannot list collaborators.

The workflow still needs a bounded read of canonical identity fields for a
future, separately reviewed provider write path. The engine must keep the
read result confidential across multiple `for_each` steps and ensure an
adapter cannot echo personal data into durable workflow evidence.

## Decision

Add the in-process `collaborator.provisioning_snapshot` step, available only
to the exact active `dakasa/reconcile-identity-providers` workflow manifest ID
named by `YGGDRASIL_IDENTITY_PROVISIONING_WORKFLOW_MANIFEST_ID`. An unset,
invalid, inactive, historical, or different ID refuses execution before the
directory query; asynchronous dispatch refuses it before inserting a run.
The operator pins a manifest row, never just a mutable logical name or version.
The read uses Core's own database connection and no adapter credential.

Query at most 1,001 rows and refuse snapshots larger than 1,000 rather than
silently omitting a collaborator. Select only ID, canonical status, primary
email, display name, and given/family names. Refuse unknown statuses.
Project only these fields plus ID as `external_id` into an invocation-local
collection at `private://list-collaborators/collaborators`. The step's public
metadata contains only `total_count`. It never exposes the collection through
`WorkflowExecutionContext.Steps`, the public response, `workflow_runs`, or a
completion event.

Only a step with a direct dependency on the named producer can consume that
private URI. A private `for_each` iteration passes one projected item to its
step and immediately replaces the result with engine-owned status, attempts,
timestamps, and a fixed failure message. Adapter output, metadata, error
detail, and echoed input never enter the shared template context or durable
run evidence. The collection is discarded when the run ends. For this
workflow, caller inputs may contain booleans only, and run metadata is limited
to the scheduler's fixed non-personal fields; this applies before async
persistence as well as at execution.

This decision grants a read only. Provider writes, provider ownership,
admission rules, group management, Slack SCIM prerequisites, and activation of
the workflow require separate review and rollout. In particular, canonical
`status` is preserved; the Core does not infer provider `active` from it.

## Consequences

- An adapter cannot turn a credential intended for integration work into a
  broad Core collaborator-list credential.
- An active-version replacement requires an explicit Core pin change before
  it can read the snapshot. A stale scheduled selector fails closed.
- The 1,000-person cap is a deliberate operational limit and must be reviewed
  before growth makes it insufficient.
- Provider adapters will receive the selected fields only when a later
  manifest enables a reviewed private iteration. Their own transport and
  provider-side handling remain subject to that review.
- CI must cover exact-manifest denial, narrow projection, private source
  validation, and redaction of adapter-echoed personal data. Local tests are
  not run on the owner's machine.

## Related

- ADR-0016 (separate one-step leases for provider-generated secrets)
- ADR-0019 (separate exact-lookup directory machine authority)
- ADR-0027 (authenticated channels for workflows declaring authorization)
- DaKasa ADR-0284 (removed the self-adapter's broad Core bridge)
