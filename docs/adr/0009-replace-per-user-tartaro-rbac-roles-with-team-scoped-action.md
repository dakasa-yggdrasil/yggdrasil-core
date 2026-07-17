# ADR-0009: Replace per-user Tartaro RBAC roles with team-scoped action grants materialized via the reactor framework

- **Status:** Accepted
- **Date:** 2026-05-18
- **Deciders:** unknown (user-approved decisions per design doc)
- **Scope:** yggdrasil-core (canon events + team_grant endpoints), integration-tartaro-dakasa, dakasa-tartaro-fe (tartaro-operations, tartaro-api and sibling services), dakasa-commons
- **Supersedes:** —
- **Superseded by:** —

## Context

Tartaro authorization read a per-collaborator `traits.tartaro_roles` trait, requiring every access change to be a direct per-user role assignment via the `tartaro:assign_rbac_role`/`revoke_rbac_role` adapter capabilities — granting "moderator" to 5 people required 5 individual operations, with no team-level lever at all. This did not compose with Yggdrasil's team model (a collaborator can belong to multiple teams, and access should follow team membership) and forced role/action mapping logic to live outside Yggdrasil's own grant primitives. Yggdrasil already had a `team_grants` table linking `(team_id, integration_instance, action_name)`, intended to grant per-team capabilities to integrations, but nothing consumed it. The lifecycle reactor framework had just shipped, providing the exact machinery (canon events → adapter via AMQP) needed to make team membership changes propagate automatically.

## Decision

Move Tartaro authorization to **team-scoped, action-level grants**, computed as the union of grants across a collaborator's active team memberships, and materialize the result into a single trait the existing authz check reads directly:

- **Fine-grained actions, not roles, on `team_grants`** — a grant is `(team_id, integration_instance, action_name)` such as `tartaro:moderate_post`, not a role bundle. This is an explicit granularity choice aligning with `authz.Evaluate`'s existing per-action model.
- yggdrasil-core gains two new canon lifecycle events, `team_grant.added` and `team_grant.revoked`, emitted transactionally in the same handlers that mutate team grants (`POST/DELETE /api/v1/teams/{id}/grants`).
- **Materialize eagerly, not query-time:** `integration-tartaro-dakasa` declares reactors on `team_membership.added`, `team_membership.removed`, `team_grant.added`, `team_grant.revoked`. On any of these it recomputes `RecomputeUserTartaroActions` (single user) or `RecomputeTeamMembers` (fan-out to every active member of the affected team): fetch the user's active team memberships, fetch each team's grants scoped to `(integration_instance_namespace, integration_instance_name) == this adapter's own instance`, union the `action_name`s (wildcard `"*"` grants are V1-skipped, not expanded — never silently expanded, to avoid surprise over-grants), sort, and `PATCH` the result into `traits.tartaro_actions` via `UpdateCollaboratorTraits`. `tartaro-api`'s `authz.Evaluate` becomes a direct trait-membership check, with no recomputation at request time.
- **Always-full-recompute, no incremental diffing:** every trigger recomputes the entire action set from scratch rather than incrementally adding/removing — simpler, order-independent, atomic per user; judged an acceptable cost at DaKasa's scale.
- `dakasa-commons/security` gains `YggdrasilHasAction(collaborator, action)` reading `traits.tartaro_actions`, added alongside (not replacing) the existing `YggdrasilHasRole`; call sites migrate incrementally.
- **Big-bang migration, not coexistence:** `tartaro_roles` is fully deprecated in V1 — `tartaro-api` stops reading it. The old `tartaro:assign_rbac_role`/`revoke_rbac_role` capabilities are kept as no-ops (log a deprecation warning, return `{deprecated: true, hint: "Use POST /api/v1/teams/{id}/grants instead"}`) rather than deleted, to preserve the adapter contract for any caller still invoking them. This was an explicit choice over a slower coexistence rollout, for a simpler end state.
- **Deploy order is a hard sequence, not parallel:** (1) `tartaro-operations` ships a `role→actions` lookup endpoint (`GET /internal/admin/roles/:slug/actions`, becoming the source of truth for the role→action mapping), (2) the adapter ships the new capabilities, (3) core ships the new canon events + `/effective-tartaro-actions` + `/sync-tartaro-actions` endpoints, (4) an idempotent find-or-create migration script converts every collaborator's `tartaro_roles` into equivalent teams/grants/memberships (via the normal Yggdrasil write path, so materialization happens naturally) — **must pass `--validate` cleanly** before step 5, (5) only then does `tartaro-api` cut over to reading `tartaro_actions`. Step 5 denies every user whose trait wasn't correctly populated, making `--validate` a hard gate, not optional tooling.
- New operator escape hatches: `GET /api/v1/collaborators/{id}/effective-tartaro-actions` (trait vs. ground-truth recompute, with a `drift` flag) and `POST /api/v1/collaborators/{id}/sync-tartaro-actions` (force a synthetic recompute event) — both for diagnosing reactor lag without a UI. A `POST /effective-tartaro-actions` "sync" endpoint also serves as an on-demand fallback/drift-detector since recompute is otherwise asynchronous relative to the mutating API call.

## Consequences

- Any Tartaro authorization check must eventually read `traits.tartaro_actions` (action-level) instead of `traits.tartaro_roles` (role-level); `YggdrasilHasRole` remains only for legacy/UI label purposes during the transition.
- Access changes for a user now require either (a) changing team membership or (b) changing a team's grants — never a direct per-user capability call — and always flow through Yggdrasil's canon event → reactor pipeline. Tartaro authorization therefore has an eventual-consistency window (explicitly "Yes — eventual consistency" per the design's own failure table), converging within the reactor framework's normal retry/backoff window (seconds, worst case minutes on adapter hiccup).
- `authz.Evaluate` fails closed: an empty or absent `tartaro_actions` trait denies every action (with an info-level log for visibility) rather than falling back to any legacy check — post-migration, any collaborator whose trait failed to populate is silently locked out of everything until an operator runs `/sync-tartaro-actions` or investigates.
- A grant on `action_name: "*"` is intentionally NOT expanded to concrete actions in V1 — operators must grant explicit action names; wildcard grants are silently ignored by the recompute, a known V1 gap deferred to V2 if there's real demand.
- The big-bang choice means there is no gradual rollback per-user — the only rollback path is reverting the `tartaro-api` deploy (step 5) so it reads `tartaro_roles` again, which is why that column is deliberately preserved (not dropped) through V1; cleanup (column drop) is deferred to a V2 after the migration is proven stable.
- Every tartaro-side service that vendors `dakasa-commons` must re-vendor after the `YggdrasilHasAction` addition, or it will keep building against the stale copy.
- Recompute is scoped per `(integration_instance_namespace, integration_instance_name)` — a grant on a different integration instance (e.g. a Slack adapter's grant) is correctly ignored by the Tartaro adapter's recompute, so multiple adapters can share the same team/grant primitives without cross-contaminating each other's materialized trait.
- UI for managing team grants is explicitly out of scope for V1 (backend + API only) — operators must use the API/migration script directly until a V2 TeamDetailPage ships.
- This decision is architecturally downstream of and reuses ~90% of the lifecycle reactor framework (materialization, dispatcher, backoff, dead-letter) without modification — any future change to that core framework's retry/backoff semantics silently changes Tartaro's permission-propagation latency too.

## Related
- scratch: `docs/superpowers/plans/2026-05-18-tartaro-team-permissions.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-18-tartaro-team-permissions-design.md`
