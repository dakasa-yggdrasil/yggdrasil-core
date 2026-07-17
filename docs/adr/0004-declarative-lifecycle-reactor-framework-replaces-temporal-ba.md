# ADR-0004: Declarative lifecycle reactor framework replaces Temporal-based onboarding/offboarding workflows

- **Status:** Accepted
- **Date:** 2026-05-15
- **Deciders:** unknown
- **Scope:** yggdrasil-core (event/reactor pipeline, core lifecycle propagation architecture), dakasa-system (workflow removal), integration adapters
- **Supersedes:** Temporal-orchestrated lifecycle workflows (`onboard`, `offboard`, `absence-start`, `absence-end`, `role-change`, `re-onboard`, `cleanup-offboarded-collaborator` in `dakasa-system/yggdrasil/dakasa/workflows/`)
- **Superseded by:** —

## Context

Yggdrasil had no automatic propagation of people/group lifecycle to integrations: creating a collaborator in the console triggered nothing in Slack, GitHub, Google Workspace, AWS, etc. Collaborator/team lifecycle transitions (onboarding, offboarding, absence, role change) instead triggered integration side-effects via hand-authored Temporal workflow JSON files living in `dakasa-system`, but this central-workflow model — a single workflow enumerating every integration step-by-step — never actually got applied to the cluster and does not scale: adding a new integration required editing a central workflow file, and reactions were wired externally rather than owned by an integration's own manifest. Without automatic propagation, Yggdrasil risked becoming "a directory of people with little value."

## Decision

Build a declarative, closed-catalog reactor framework directly in yggdrasil-core, replacing the abandoned central-workflow model entirely:

- **Closed canon event catalog — 11 events, immutable, schema-validated**: `collaborator.{created,offboarded,absence_started,absence_ended,role_changed,re_onboarded}` and `team.{created,updated,deleted}` / `team_membership.{added,removed}`. Any change to this list is a governance chokepoint, treated as a breaking change requiring deliberate care. A reserved `reactor.*` event prefix (e.g. `reactor.dead_lettered`) is explicitly excluded from ever triggering reactors itself, preventing infinite loops.
- **Integrations react only to core-canon entities** — events emitted by one integration never trigger reactors in another integration, deliberately avoiding a directed dependency graph between integrations.
- **Zero core code per new integration:** `integration_type` manifests declare a `spec.reactors: [{event_type, capability, description}]` block. A manifest validator rejects any `event_type` outside the canon set, any `capability` not present in the manifest's own `action_catalog`, and duplicate `(integration_type, event_type)` pairs — validated at manifest-apply time. A brand-new integration works purely by declaring reactors, no core deploy required.
- **Transactional materialization:** a new table `integration_event_reactions` records one row per `(event, integration_instance)` match. `MaterializeReactions` runs **inside the same transaction** as `repository.EmitEvent` — inserting one row per active `integration_instance` whose type declares a reactor for that event_type — so reactions and the event commit or roll back atomically; this closes the skew window entirely (an event can never exist without its reactions, or vice versa). Non-canon event types (including `reactor.dead_lettered` itself) are a no-op.
- **Dispatch is a separate polling Runner** (addon, `FOR UPDATE SKIP LOCKED` batch claiming so multiple core pods claim disjoint work without external coordination) that dispatches pending/failed reactions over the existing RabbitMQ RPC path (`messagecontroller.RunIntegrationOperation`), tracking per-reaction state `pending → in_progress → succeeded | failed → dead_lettered`. Retry is a fixed/exponential backoff schedule of 1m → 5m → 15m (env-overridable), then `dead_lettered` on the 4th attempt (max-attempts also env-overridable), emitting the reserved `reactor.dead_lettered` meta-event for external alerting rather than re-entering the pipeline. A periodic heal pass recovers rows stuck `in_progress` past a threshold (crashed pod recovery).
- **Failure isolation is per-row, not per-event:** one reactor dead-lettering does not affect another reactor's independent row for the same event.
- Every reactor payload is the raw event payload merged with a reserved `_context` block (`event_id`, `event_type`, `schema_version`, `emitted_at`, `actor`, `attempt`) — the `_` prefix is reserved for core-injected metadata and overwrites any conflicting key in the event payload. Idempotency is explicitly the integration's responsibility — `_context.attempt` signals retry count; adapters must tolerate receiving the same `event_id` more than once, stated as a hard contract.
- **No backfill by default:** reactors only process events emitted after a reactor declaration goes active; propagating pre-existing people/teams into a newly-reactor-enabled integration requires a separate ad-hoc replay workflow (explicitly deferred).
- The Temporal-based lifecycle workflow JSON files in `dakasa-system` are deleted as part of this change — verified beforehand that none remained `active=true` (in fact none had ever been applied to the cluster, making the deletion purely cosmetic) — the reactor framework is the sole mechanism for lifecycle-driven integration side-effects going forward.
- A latent bug is fixed in the same effort: `handleCollaboratorCreate`/`CreateCollaborator` did not create an `auth_identities` row, silently breaking the password-setup flow; `collaborator.created` reactions now act on a consistent identity row.

## Consequences

- Any integration wanting a lifecycle reaction must express it declaratively in its manifest's `reactors` block against the closed canon set — it cannot react to arbitrary event types, and extending the canon set is itself a core code change (new constant + `CanonLifecycleEventTypes` entry + JSON Schema pair for the event and its reactor-input variant).
- Reaction delivery is at-least-once with bounded retries; integrations must implement their reactor capabilities idempotently.
- Every one of the 11 core handlers (collaborator CRUD/lifecycle, team CRUD, team_membership CRUD) must perform its internal side effects and its canon-event emit inside the *same* transaction — any handler that emits outside its state-mutating transaction reintroduces the exact skew window this design eliminates.
- Removing the Temporal workflow files is a one-way migration for this batch of lifecycle behaviors — any future need for that Temporal path would have to be re-justified against the reactor model.
- The reactor and manifest-validation code paths become a dependency every new `integration_type` manifest author must understand before declaring `reactors`.
- Observability in this phase is Prometheus metrics + structured logs only — no inspection API or console dashboard for reactor health (explicitly deferred), so debugging a stuck/dead-lettered reactor requires log/metric access, not a UI.
- Reactor declarations are validated only at manifest-apply time — a manifest hand-pushed bypassing that path (e.g. directly via DB) could violate the canon/duplicate constraints; the design relies on the HTTP manifest-apply path being the only legitimate write path.
- This framework is the direct foundation two later decisions build on: the team-provisioning-log extension (adapter-side team resource tracking) and the Tartaro team-scoped permission grants (`team_grant.*` events) both assume and reuse this exact materialization/dispatch/backoff machinery rather than reimplementing it.

## Related
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-15-lifecycle-reactor-framework.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-15-lifecycle-reactor-framework-design.md`
