# ADR-0032: Materialize explicit typed team leadership

- **Status:** Accepted
- **Date:** 2026-10-07
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / team writers and directory leadership
- **Supersedes:** 0031
- **Superseded by:** none

## Context

Historical team owners are administrative input. Core's owner writer preserves
existing free-form membership ranks and sources, so neither an owners JSON list
nor a membership role consistently proves effective formal leadership. Inferring
leadership from those records would grant demoted, inactive or expired people
an audience. Old full-form clients also echo owner input on unrelated updates.

## Decision

Preserve ADR0031's restricted snapshot, contact, audit, pagination, revision,
credential and completeness contracts. Replace only its owner-reference authority
with a required typed `team_memberships.is_lead` boolean. Migration54 defaults it
to false and performs no owner, role or title backfill. Free-form membership role,
source and RBAC semantics remain independent.

Canonical team creation with nonempty owners requires `assert_leadership:true`.
There is no prior version at creation. Updating an existing team with any owners
array, including empty or unchanged, requires that explicit intent and the exact
`expected_updated_at` reviewed by the caller. Compare before any mutation under
`FOR NO KEY UPDATE`. Omitted owners is an ordinary compatible patch; null is
invalid. Missing intent refuses with422; stale version refuses with409. HTTP,
AMQP and local-service writers share this boundary. Unrelated updates never
materialize historical input; declarative clients must opt into the same intent.

Resolve asserted owners to canonical identities and materialize/remove the typed
bit in the same team-write transaction. Preserve existing role, source and
membership windows. The Console editor receives the complete formal assignment
set, including inactive/future/expired typed leaders. An already typed selected
leader retains its current active state; adding a false-to-true assignment can
activate it deliberately. Effective public leaders remain a separate projection. Removing leadership keeps independent manual membership;
rows created only by owner sync retain their established deactivation behavior.
General membership activation never seeds a false bit from role. Root-admin
teams cannot gain formal leadership, including by later trait promotion.

Directory membership JSON always includes `is_lead`. Team `owner_ids` derives
only from that bit, active membership, active team and inclusive membership
windows at fixed first-page `observed_at`. Continuations load and derive at the
signed original time before comparing revision. A fresh observation can change
its derived leaders when a boundary passes. Raw owners input, rank, title and
primary-team hints provide no fallback. Collaborator lifecycle and incomplete
phone profile remain separate consumer audience/participation gates.

## Consequences

Existing leadership requires reviewed explicit assertions after schema/source
cutover. Cached full-update clients cannot incidentally rematerialize leadership;
operators reload/review after a refusal. Core and Console must be deployed
coherently before a directory consumer uses the new authority. No live repair or
permission grant is implied by this source migration.

## Related

- ADR0031 (restricted snapshot contracts retained)
- ADR0030 (declared contacts remain separate from leadership and consent)
