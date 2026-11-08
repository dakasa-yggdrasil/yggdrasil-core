# ADR-0107: Count Tartaro action holders with the same predicate as the effective-actions read

- **Status:** Accepted
- **Date:** 2026-11-08
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / Tartaro action-holder roster (`GET /api/v1/tartaro/action-holders`)
- **Supersedes:** none
- **Superseded by:** none

## Context

Tartaro decides whether a ban is applied at once or goes to a collective vote
of the moderators who may suspend users (dakasa-system ADR-0057). It counted
those voters with `GET /api/v1/collaborators?role=risk` and read a `total`
field. Core ignores `role` and returns no `total`, so the count was always 0
and every ban took the solo path. Core had no read that answers "who holds
this Tartaro grant now". The only authoritative answer was the per-collaborator
effective-actions read (ADR-0086), and calling it once per collaborator does
not scale and still needs a list of candidates.

## Decision

Core serves `GET /api/v1/tartaro/action-holders?action=<grant action>`, the
roster of the collaborators who hold that grant right now on the configured
Tartaro instance (`YGGDRASIL_TARTARO_INSTANCE_NAMESPACE`/`_NAME`).

1. **Same predicate as the effective-actions read.** A holder has status
   exactly `active` and either (a) a membership satisfying
   `authorizationMembershipPredicate` (membership active, team active, inside
   `starts_at`/`ends_at`) in a team with a grant on the instance whose
   `action_name` is the action, or is `*` while the instance permission
   catalog (`ListIntegrationInstancePermissionActions`) lists the action
   (source `team_grant`), or (b) Tartaro god mode by the `tartaroGodMode`
   rule (source `god_mode`). Only direct memberships count, as in the grant
   walk. One SQL statement embeds `authorizationMembershipPredicate`
   verbatim and returns the candidates with their exact and wildcard grant
   flags, their raw `traits.yggdrasil_admin` and whether any `*` grant exists
   on the instance. Core then applies the catalog and `tartaroGodMode` in
   Go, so neither rule is restated in SQL.
2. **Fail toward "cannot count", never toward "count lower".** When any `*`
   grant exists on the instance and the catalog cannot be resolved (instance
   or type not resolvable, a read or decoding failure), the answer is 503
   with `{"error": ...}`. A roster read failure is a 5xx. No partial roster
   is ever answered. This differs on purpose from the effective-actions
   read, where an unresolvable catalog only narrows one collaborator's own
   answer.
3. **Wire contract.** The 200 body always carries `action`,
   `integration_instance` (`namespace`, `name`), `total` and `holders`.
   `holders` is sorted by `collaborator_id` ascending, unique and never null;
   `total` equals its length; each holder has `collaborator_id` and a
   non-empty sorted `sources` subset of `god_mode` and `team_grant`. A god
   with a team grant is listed once with both sources. The query takes only
   `action`, exactly once, non-empty, without surrounding whitespace, never
   `*`, at most 128 bytes; anything else is 400.
4. **Same authentication as the collaborator list.** Any authenticated
   console caller (session or forwarded OIDC JWT) passes, with no ops
   permission, because Tartaro moderators hold no Core ops permission. It is
   not a directory machine route. The answer carries collaborator ids only.

## Consequences

- Tartaro can count its eligible voters in one call and decode the roster
  strictly. The roster and the effective-actions read change together: a
  change to the membership predicate, the god-mode rule or the wildcard
  expansion reaches both.
- Any authenticated console caller can learn which collaborator ids hold a
  given Tartaro grant. The collaborator list already exposes every id and
  status to the same callers, so no new class of caller sees new identities.
- A catalog outage while a `*` grant exists makes the roster unavailable,
  and Tartaro then refuses to decide a ban rather than applying it alone.
- The god-mode candidate set is every active collaborator with a
  `yggdrasil_admin` trait key, filtered in Go; it stays small.
- `/api/v1/tartaro` is now a console-gated prefix.

## Related

- ADR-0086 (effective-actions predicate, god mode and wildcard expansion reused here)
- ADR-0085 (retired materialized trait)
- ADR-0019 (directory machine routes; this route is not one)
- dakasa-system ADR-0057 (collective voting for suspensions)
