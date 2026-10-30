# ADR-0086: Compute Tartaro effective actions with one predicate, a god-mode verdict and wildcard expansion

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / Tartaro effective actions (console and directory machine variants)
- **Supersedes:** none (amends the minimal directory effective-actions projection of ADR-0019, retained by ADR-0031 and ADR-0032)
- **Superseded by:** none

## Context

Tartaro services authorize live against Core (dakasa-tartaro-fe ADR-0015).
They read actions from one of two variants of
`GET /api/v1/collaborators/{id}/effective-tartaro-actions`: the console
variant, called with the human caller's token, and the directory machine
variant (ADR-0019), called by a service principal with
`directory.effective_actions`. Three gaps made those answers differ from what
the platform means:

- The console variant counted every membership with `active = true`, ignoring
  the team status and the optional `starts_at`/`ends_at` window. That set was
  chosen so the old drift view compared like with like against the
  materialized trait, which ADR-0085 retires. The directory variant already
  used `repository.authorizationMembershipPredicate`, so the two variants
  could answer different action sets for the same collaborator.
- Neither variant answered god mode. Tartaro services derived it from
  `traits.yggdrasil_admin` themselves, through a second Core read or from
  their token, so the authorization answer was split across sources.
- Both variants skipped grants whose `action_name` is `*` (ADR-0009 V1). The
  console grant editor offers "all actions" for an instance by writing a `*`
  grant, which therefore gave a team nothing in Tartaro, while the documented
  meaning of `*` on a team grant is "every action of that instance".

## Decision

Both variants run one computation (`computeAuthorizedTartaroActions`):

1. **One membership predicate.** Only memberships that confer authority now
   count: membership active, team status active, `starts_at` null or not
   after now, `ends_at` null or not before now. This is the single
   `authorizationMembershipPredicate` the RBAC subject projection uses. The
   grants of all those teams are read in one statement, and only grants on
   the configured Tartaro instance
   (`YGGDRASIL_TARTARO_INSTANCE_NAMESPACE`/`_NAME`) count.
2. **A god-mode verdict.** Both variants answer a boolean `god_mode`: true
   if and only if the collaborator status is exactly `active` and
   `traits.yggdrasil_admin` is the boolean `true` or exactly the string
   `"true"` or `"1"`. This is the reading of dakasa-commons
   `security.YggdrasilIsGodMode` plus the active-status requirement. It is
   never derived from a team grant: a `*` grant on a yggdrasil-self instance,
   which is Core's own console god mode, does not make anyone a Tartaro god.
   `god_mode` is reported next to the actions and never merged into them.
3. **Wildcard expansion.** A grant with `action_name` `*` on the configured
   Tartaro instance expands to every entry of that instance's
   `action_catalog` whose `category` is exactly `permission`, taken from the
   active `integration_type` the instance's active version selects through
   its `type_ref` (the same selection ADR-0021 uses for event grants). The
   expansion is merged with the explicit grants, deduplicated and sorted, per
   team and in the union; `*` never appears literally in an answer. The
   catalog is read only when such a grant is present, at most once per
   computation. When the catalog cannot be resolved (no active instance
   version, no active type, unreadable data or a failed read) the wildcard
   contributes nothing, the failure is logged at warn level, and the request
   is still answered with the explicit grants: the expansion fails closed and
   never fails the read. `*` on any other instance keeps its existing
   meaning, including yggdrasil-self god mode and guard semantics.
4. **One active-record policy.** A collaborator whose status is not exactly
   `active` (`pending_start`, `on_leave`, `suspended`, `offboarded`) holds no
   Tartaro action and no god mode in either variant, whatever their
   memberships and grants say and however long a token minted before the
   status change stays valid. The directory variant keeps reading such a
   collaborator as absent (404, ADR-0019). The console variant answers `200`
   with empty `effective_via_teams` and `computed_tartaro_actions` and
   `god_mode` false, without reading memberships, grants or the catalog; it
   keeps the `200` because a console caller can already read that the
   collaborator exists. The console variant is the live authorization source
   of the Tartaro panel services (dakasa-tartaro-fe ADR-0015), called with
   the human's own token, so it must not be wider than the directory
   variant.

Response shapes:

- Console: `collaborator_id`, `effective_via_teams` (per team: `team_id`,
  `team_slug`, sorted `actions`), `computed_tartaro_actions`, `god_mode`.
- Directory machine: `collaborator_id`, `computed_tartaro_actions`,
  `god_mode`. This amends the minimal projection of ADR-0019 (retained by
  ADR-0031 and ADR-0032) by exactly one key. It carries no other trait value
  and no per-team, drift or personal data; every other rule of those ADRs
  (credential, capability, instance allowlist, inactive collaborator as
  absent, fixed 500 body, synchronous fail-closed audit) is unchanged.

## Consequences

- The two variants answer the same action set and the same god-mode verdict
  for the same active collaborator at the same moment. For a collaborator
  who is not active they differ only in shape: the console answers empty
  sets with `god_mode` false and the directory answers 404, and both mean no
  Tartaro authority (the Tartaro services already map a 404 to an empty
  set). The console variant can now be narrower than before for an expired,
  not-yet-started or deactivated-team membership and for a collaborator who
  is not active.
- A console "all actions" grant now gives the team every Tartaro permission.
  A permission added to the adapter catalog reaches existing wildcard holders
  at the next catalog sync, and a permission removed from it leaves them. A
  catalog outage can only narrow an answer, never widen it.
- **Rollout precondition.** The directory envelope gains a key, and three
  consumers decode it strictly: dakasa-tartaro-api, tartaro-legal and
  tartaro-review (`internal/authz/evidence.go`, which rejects any key other
  than `collaborator_id` and `computed_tartaro_actions` before their
  `god_mode` change). Those three services must run, in production, a build
  that accepts an optional boolean `god_mode` before any Core carrying this
  change is rolled out, including a Core built by cherry-picking it onto
  another lineage. Rolled out earlier, Core makes every evidence-gated
  private read of those services fail closed for every collaborator until
  they are redeployed; rolling Core back restores them. Core has no switch
  for the key: the order is a release step, recorded here and in the
  CHANGELOG. Consumers that also need older Cores treat an absent key as
  "not reported" and keep their previous source for god mode. Consumers
  that use the verdict to bypass action checks stay responsible for any
  approval flow that must not be bypassed.
- The grant walk no longer resolves each team and reads its grants one by
  one; a collaborator in many teams costs one membership read, one grant read
  and, only with a wildcard grant, one catalog read.
- Core's own console permissions (`repository.ResolveYggdrasilPermissions`)
  keep their separate rules, including the boolean-only reading of
  `yggdrasil_admin`.
- Follow-up, outside this decision: suspending a collaborator only changes
  their status. It revokes no Core session, sends no back-channel logout
  (offboarding does both) and leaves memberships in place, and reusing an
  existing Core session to complete an OIDC login does not check the
  collaborator status, so a suspended human can keep obtaining Tartaro
  tokens. The active-record policy above makes those tokens carry no
  Tartaro authority, but the session lifecycle gap stays open until suspend
  terminates sessions and session reuse checks the status.

## Related

- ADR-0085 (retires the materialized trait this computation replaces)
- ADR-0009 (superseded by ADR-0085; this ADR replaces its wildcard skip)
- ADR-0019, ADR-0031, ADR-0032 (directory machine routes; minimal projection amended here)
- ADR-0021 (logical instance and type_ref resolution reused for the catalog)
- dakasa-tartaro-fe ADR-0015 (Tartaro live authorization)
