# ADR-0010: Team-mirroring reactors ack via a reserved envelope into a provisioning log, self-healed by an anti-join reconcile sweep

- **Status:** Accepted
- **Date:** 2026-05-18
- **Deciders:** unknown
- **Scope:** yggdrasil-core (reactor dispatcher extension), integration-slack, integration-github, integration-google-workspace
- **Supersedes:** —
- **Superseded by:** —

## Context

Yggdrasil already emits `team.created/updated/deleted` and `team_membership.added/removed` canon lifecycle events via the reactor framework and dispatches them to adapters that declare a matching `reactors` entry, but the framework only guaranteed at-least-once *delivery* of the event — it had no notion of whether the adapter's mirror actually landed (e.g., a Slack channel was actually created for a team), nor any mechanism to notice and fix gaps left by pre-existing teams created before an adapter installed its reactor, or by transient dispatch failures that exhausted retries. Adapter-side coverage of the *team* events was also incomplete and inconsistent: Slack had membership handlers but no `on_team_created/updated/deleted`, so a membership-add would fail if the channel didn't already exist; GitHub had `on_team_created` and membership handlers but not `updated/deleted`, so renaming/deleting a Yggdrasil team left the GitHub team stale; Google Workspace had only membership handlers.

## Decision

Extend the reactor framework with a provisioning-tracking and self-healing layer, scoped specifically to team mirroring — reusing the provisioning-log pattern from the shipped `collaborator_external_identities` envelope convention and the "dumb" reconcile-cron pattern from the shipped `manifest_sync` addon, deliberately not reinvented:

- New table `team_provisioning_log (team_id, integration_instance_id, external_id, external_metadata jsonb, last_success_at, last_event_type, UNIQUE(team_id, integration_instance_id))` — one row per (team, instance) mirror, upserted via `ON CONFLICT`, recording that a given team has been successfully mirrored into a given integration instance's external system.
- Adapters signal successful provisioning by returning a reserved response envelope block, `_yggdrasil.team_provisioned {external_id, external_metadata}`, on the ack of `on_team_created` (and are extended to also implement `on_team_updated`/`on_team_deleted` where previously missing). The core reactor dispatcher extracts this envelope (mirroring the existing `internal/externalidentity/envelope.go` pattern) and `UPSERT`s the log row on successful ack — idempotent under repeated adapter acks.
- Each adapter implements exactly 3 reactor handlers (`on_team_created`, `on_team_updated`, `on_team_deleted`) with **sensible fixed defaults, not a configurable `external_config` field** — an explicit YAGNI call, no per-team override mechanism ships in V1: Slack creates a private channel prefixed `team-<slug>`; GitHub creates a `closed`-privacy team with no repo grants; Google Workspace creates a mailing-list group at `<slug>@<domain>` with `INVITED_CAN_JOIN`.
- **Adapters must treat "already exists" and "already gone" as success**, not error (conflict → lookup-and-continue on create; 404 → success on delete) — this idempotence is what makes the reconcile cron safe to blindly re-emit against, and is now a hard contract, not a nice-to-have.
- A cron addon `internal/teamreconcile/runner.go` (5-minute tick, same shape as `internal/manifestsync/runner.go`) finds `(team, instance)` pairs where the instance's `integration_type.spec.reactors` declares `team.created` but no log row exists — computing the anti-join `teams × integration_instances MINUS team_provisioning_log` — and **re-emits `team.created` unconditionally** for that team, relying on `MaterializeReactions`'s natural fan-out plus adapter idempotence rather than filtering per-instance in the cron query itself. This trades 1-2 wasted no-op RPCs per tick for a simpler emit path, judged negligible at DaKasa's scale (≤100 teams × 3 adapters). This is the self-healing mechanism: any team never successfully mirrored (pre-existing team, adapter installed later, or an exhausted-retry dead-letter) gets automatically re-attempted without operator intervention, with no special bootstrap step needed — the first post-deploy cron tick reconciles all pre-existing teams within one cycle (≤5 min).
- Two new HTTP endpoints expose state to operators: `GET /api/v1/teams/{id}/provisioning-status` for current mirroring state, and `POST /api/v1/teams/{id}/sync` to force re-emit `team.created` for debugging/replay after fixing an adapter.
- Google Workspace's group email is documented as an accepted **cross-provider limitation**: renaming a Yggdrasil team renames the Slack channel and the GitHub team, but the GW group's email stays at the original slug (only its display `name` updates) — GW group emails are immutable by the provider's own API.

## Consequences

- Team mirroring for slack/github/google-workspace becomes eventually consistent by construction — the reconcile sweep guarantees convergence rather than relying solely on the reactor framework's bounded retry-then-dead-letter behavior.
- All 3 adapters must implement idempotent create/update/delete or the reconcile cron will generate a steady stream of failed/no-op RPCs every 5 minutes for any team stuck out of sync. Every adapter that wants its `team.*` reactors counted as "done" must return the `_yggdrasil.team_provisioned` envelope correctly on ack; an adapter that mirrors the team but omits the envelope will be silently re-attempted by the cron sweep every 5 minutes indefinitely (looks successful externally but never converges internally).
- There is no per-team customization (private vs. public channel, team privacy level, etc.) in V1 — any team wanting a different default must wait for a V2 `external_config` field or be handled manually outside the framework.
- Observability piggybacks entirely on the existing reactor framework's backoff/dead-letter/status machinery (`integration_event_reactions.status`) — no new metrics or alerts were added in V1; `GET /api/v1/teams/{id}/provisioning-status` is the only new introspection surface, and it has no UI consumer yet (deferred to a TeamDetailPage "Sistemas vinculados" card).
- The reconcile query deliberately does not diff the *other* direction (external resources that exist in the provider but have no matching Yggdrasil team) — orphan GitHub teams, for example, are not surfaced by this design.
- Renaming a team is a 3-adapter side-effect fan-out with one silent partial-failure mode baked in by design (GW email immutability) — operators must know this rather than being warned by tooling.
- The pattern (provisioning log + periodic anti-join sweep + ack envelope) is reusable for other "must eventually mirror" resources beyond teams, but this decision only wires it for teams.
- Adding a new adapter capability requires updating the reactor entries in the adapter's `integration_type` manifest example alongside the code — a mismatch would show up as `contract_mismatch`, not a team-provisioning failure.

## Related
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-18-team-reactor-framework.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-18-team-reactor-framework-design.md`
