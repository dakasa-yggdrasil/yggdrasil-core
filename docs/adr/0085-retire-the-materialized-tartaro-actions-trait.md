# ADR-0085: Retire the materialized tartaro_actions trait

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / Tartaro effective actions; integration-tartaro-dakasa team reactors
- **Supersedes:** 0009
- **Superseded by:** none

## Context

ADR-0009 moved Tartaro authorization to team-scoped action grants and
materialized each collaborator's union into `traits.tartaro_actions`: the
`integration-tartaro-dakasa` adapter declared reactors on
`team_membership.added`, `team_membership.removed`, `team_grant.added` and
`team_grant.revoked`, recomputed the union and wrote it back through the
collaborator traits API. Core added two operator escape hatches around that
pipeline: the console `GET /api/v1/collaborators/{id}/effective-tartaro-actions`
answered the trait next to a live recomputation with a `drift` flag, and
`POST /api/v1/collaborators/{id}/sync-tartaro-actions` emitted a synthetic
`team_membership.added` event (zero team id) to make the reactor run again. A
one-shot script, `scripts/migrate_tartaro_roles_to_actions`, converted the
older `tartaro_roles` trait into teams and grants, and a build of it was
committed at the repository root.

The Tartaro panel services now authorize live (dakasa-tartaro-fe ADR-0015):
the OIDC token only authenticates, and actions come from the effective-actions
routes of Core on every decision, behind a short per-pod cache. No Tartaro
decision reads `traits.tartaro_actions` any more. The materialization had also
stopped working, for reasons that would each need a fix: the adapter computed
grants for default instance coordinates instead of the live instance, its Core
credential is no longer accepted on the routes it called, its Describe declared
event names in a form the dispatcher does not match, and the collaborator
update it used replaces the whole traits object. A reactor that worked would
therefore overwrite every other trait of the collaborator, including
`yggdrasil_admin`, which the Tartaro services read as god mode. Keeping a dead
writer with that property, plus a console field and a route that only exist to
observe and trigger it, is a liability with no remaining purpose.

## Decision

Live authorization is the only Tartaro authorization path. Retire the
materialized `traits.tartaro_actions` trait and everything that exists only to
produce or observe it:

- Core removes `POST /api/v1/collaborators/{id}/sync-tartaro-actions` and its
  handler. The route is not replaced.
- The console effective-actions response no longer carries
  `trait_tartaro_actions` or `drift`. Core never reads `traits.tartaro_actions`
  for any authorization answer; the computation reads only team memberships and
  team grants (its exact rules are ADR-0086).
- `scripts/migrate_tartaro_roles_to_actions` and the binary committed at the
  repository root are deleted. Their migration is complete and they wrote to
  the retired trait.
- `integration-tartaro-dakasa` removes its four team reactors and the client
  code that wrote the trait; its Describe declares only the reactors it still
  serves.
- Nothing in Core or the adapters writes collaborator traits wholesale on
  behalf of Tartaro authorization. Existing `tartaro_actions` values stay
  stored as inert data: removing them would need the same whole-object update
  this decision stops using, and nothing reads them.

ADR-0009's grant model stays in force: a grant is
`(team, integration instance, action_name)`, team grants and memberships are
written through the normal team APIs, the canonical `team_membership.*` and
`team_grant.*` events keep being emitted for the reactors that consume them,
and only grants on the configured Tartaro instance count toward Tartaro
actions. What this ADR supersedes is ADR-0009's materialization, its two
escape hatches, its trait-reading checks and, together with ADR-0086, its
decision to skip wildcard grants.

## Consequences

- A membership or grant change is visible to Tartaro on the next
  effective-actions read; there is no reactor lag, no backoff window and no
  manual resync. Consumers bound staleness with their own cache.
- The repository's API stability rule asks for a one-release fallback before
  a field or route is removed. It is not applied here: the removed fields and
  the route describe a mechanism that no longer runs, the known consumers read
  only `computed_tartaro_actions`, and keeping the route would keep a trigger
  for a writer that replaces whole trait objects. A call to the removed
  route no longer reaches any handler and emits no event; a client that
  decoded `trait_tartaro_actions` or `drift` reads them as absent.
- The stored trait can drift arbitrarily from the truth from now on. Any new
  reader of `traits.tartaro_actions` would be reading stale data and must use
  the effective-actions routes instead.
- A future feature that needs to persist a per-collaborator derivation must
  not reuse the whole-object traits update; it needs a merge-safe writer, a
  separate store or a live computation.

## Related

- ADR-0009 (superseded by this ADR; its team-scoped grant model is retained)
- ADR-0086 (defines the live computation both effective-actions variants answer)
- ADR-0019, ADR-0031, ADR-0032 (directory machine read routes and projections)
- dakasa-tartaro-fe ADR-0015 (Tartaro live authorization)
