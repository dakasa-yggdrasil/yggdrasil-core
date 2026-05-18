# Team Reactor Framework — Design

**Date**: 2026-05-18
**Status**: Approved (brainstorming phase complete)
**Repos affected**: yggdrasil-core, integration-slack, integration-github, integration-google-workspace

## Motivation

Yggdrasil already emits 5 canon events for team lifecycle (`team.created`, `team.updated`, `team.deleted`, `team_membership.added`, `team_membership.removed`) and the reactor framework picks them up. What does *not* exist yet is the adapter-side coverage: when a team is created in Yggdrasil, no external resource is provisioned.

Concretely, today:

- **Slack**: `on_team_membership_added/removed` exist (add user to channel). `on_team_created/updated/deleted` do not — so the channel referenced by membership.added must already exist, otherwise the call fails.
- **GitHub**: `on_team_created` and `on_team_membership_added/removed` exist. `on_team_updated/deleted` do not — renaming or deleting a team in Yggdrasil leaves the GH team stale.
- **Google Workspace**: `on_team_membership_added/removed` exist. No team-level handlers.

This spec closes the gap and adds a reconciliation path so pre-existing Yggdrasil teams (created before adapter coverage) are eventually provisioned without manual intervention.

## Current state inventory

| Component | Status |
|---|---|
| Canon events declared in `repository/event_types_lifecycle.go` | ✅ all 5 |
| Events emitted transactionally in team CRUD handlers (`controllers/httpapi/server.go`) | ✅ all 5 |
| `MaterializeReactions` materializes per-`integration_instance` reaction rows | ✅ |
| Reactor `Runner` claims pending rows and dispatches over AMQP | ✅ |
| Adapter handlers for `team_membership.added/removed` (slack, gh, gw) | ✅ |
| Adapter handler for `team.created` (gh only) | partial |
| Adapter handlers for `team.updated/deleted` | ❌ none |
| Reconcile / drift detection for teams | ❌ none |

## Architecture

```
                  ┌─────────────────────────────────────────────┐
                  │                yggdrasil-core                │
                  │                                              │
  team CRUD ─────▶│  EmitEvent (in tx)   ─▶  event_log           │
  (HTTP)          │                            │                 │
                  │                            ▼                 │
                  │                MaterializeReactions          │
                  │                            │                 │
                  │                            ▼                 │
                  │              integration_event_reactions     │
                  │                            │                 │
                  │                            ▼                 │
                  │           Reactor.Runner (5s tick)           │
                  │           Claim → Call adapter → ack         │
                  │                            │                 │
                  └────────────────────────────┼─────────────────┘
                                               │ AMQP RPC
                  ┌────────────┬───────────────┼──────────────┐
                  ▼            ▼               ▼              │
            integration-  integration-   integration-         │
              slack         github      google-workspace      │
                  │            │               │              │
                  │  on_team_created          ◀───── canon evt│
                  │  on_team_updated          ◀───── canon evt│
                  │  on_team_deleted          ◀───── canon evt│
                  │  on_team_membership_*     ◀───── canon evt│
                  │                                          │
                  │  Return envelope with                    │
                  │  _yggdrasil.team_provisioned             │
                  └──────────────┬───────────────────────────┘
                                 │ ack with envelope
                                 ▼
                  ┌─────────────────────────────────────────────┐
                  │  yggdrasil-core                              │
                  │  Dispatcher reads envelope                   │
                  │  → upsert team_provisioning_log              │
                  │                                              │
                  │  team_reconcile cron (5min):                 │
                  │     teams × instances MINUS log              │
                  │     → re-emit team.created (idempotent)      │
                  └─────────────────────────────────────────────┘
```

### Components

1. **Canon events** (existing) — emitted transactionally in team CRUD handlers
2. **Reactor framework** (existing) — `MaterializeReactions` + `Runner` dispatches over AMQP
3. **Adapter reactor handlers** (new) — 8 new handlers across slack/gh/gw + spec.reactors entries
4. **Provisioning log + cron** (new) — 1 table + 1 envelope handler + 1 cron addon

### Design principles

- **Reuse, don't reinvent**: the envelope-back pattern is identical to `collaborator_external_identities` (sha-817a028). The cron pattern is identical to `manifest_sync_addon` (sha-cd073df).
- **Adapters are idempotent**: `on_team_created` must handle "already exists" as success via lookup, `on_team_deleted` must handle 404 as success. This is what makes the reconcile cron safe to re-emit.
- **Fan-out is implicit**: a single `team.created` event triggers all integration_instances with a matching reactor declaration. No enumeration in core.
- **Sensible per-adapter defaults**: V1 chooses defaults (private channel, closed team, mailing-list group). No per-team config field.

## Data model

### New table: `team_provisioning_log`

```sql
CREATE TABLE team_provisioning_log (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                  UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    integration_instance_id  UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    external_id              TEXT NOT NULL,
    external_metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_success_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_type          TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, integration_instance_id)
);

CREATE INDEX idx_team_provisioning_log_team ON team_provisioning_log(team_id);
CREATE INDEX idx_team_provisioning_log_instance ON team_provisioning_log(integration_instance_id);
```

Field rationale:

| Field | Purpose |
|---|---|
| `external_id` | Stable identifier from provider (slack channel ID, gh team slug, gw group email). Lets `on_team_updated` target the right resource without re-listing. |
| `external_metadata` | Provider-specific extras (gh team_id numeric, slack channel name, gw etag). JSONB for evolution without migration. |
| `last_success_at` | Timestamp of last OK ack. Cron may re-emit if `> N days` stale. |
| `last_event_type` | Debug — which event produced the latest log row. |
| `UNIQUE(team_id, integration_instance_id)` | One mirror per team per instance. Upsert via `ON CONFLICT`. |

### Envelope schema (adapter response payload)

```json
{
  "_yggdrasil": {
    "team_provisioned": {
      "external_id": "T_kwDOL_abcd",
      "external_metadata": {
        "github_team_slug": "engineering",
        "github_team_id": 123456,
        "privacy": "closed"
      }
    }
  }
}
```

The dispatcher in core (where reactor ack is processed) extracts this envelope when present and upserts `team_provisioning_log`.

## Adapter contract

Each adapter implements 3 reactor handlers (created/updated/deleted) and declares them in its `integration_type.spec.reactors` array.

### Slack

| Capability | Input (canon payload) | Action | Idempotence | Envelope output |
|---|---|---|---|---|
| `on_team_created` | `slug`, `name` | `conversations.create({name: "team-" + slug, is_private: true})` → on `name_taken`, `conversations.list` lookup | conflict = success via lookup | `external_id: channel_id`, `external_metadata: {channel_name}` |
| `on_team_updated` | `id`, `slug`, `name` | `conversations.rename({channel: external_id, name: "team-" + new_slug})` | same name = no-op | metadata only |
| `on_team_deleted` | `id`, `slug` | `conversations.archive({channel: external_id})` | already-archived = success | — (CASCADE clears log) |

**Defaults**: prefix `"team-"` on channel name to avoid collision with ad-hoc channels; always private.

### GitHub

| Capability | Input | Action | Idempotence | Envelope output |
|---|---|---|---|---|
| `on_team_created` | `slug`, `name`, `description`, `org` (= instance.default_owner) | `POST /orgs/{org}/teams` → on `422 already_exists`, `GET /orgs/{org}/teams/{slug}` | already-exists = lookup | `external_id: slug`, `external_metadata: {team_id, privacy: "closed"}` |
| `on_team_updated` | new `slug`, new `name` | `PATCH /orgs/{org}/teams/{old_slug}` | same values = no-op | metadata only |
| `on_team_deleted` | `slug` | `DELETE /orgs/{org}/teams/{slug}` | 404 = success | — |

**Defaults**: privacy `closed`, no repo grants, description derived from team.name.

### Google Workspace

| Capability | Input | Action | Idempotence | Envelope output |
|---|---|---|---|---|
| `on_team_created` | `slug`, `name` | `groups.insert({email: slug + "@" + domain, name, description: "Time " + name})` → on `409 entityExists`, `groups.get` | conflict = success via lookup | `external_id: group_email`, `external_metadata: {group_id, etag}` |
| `on_team_updated` | new `slug`, new `name` | `groups.patch({groupKey: external_id, name})` — email does NOT change (GW groups can't rename email without migration) | same name = no-op | metadata only |
| `on_team_deleted` | `slug` | `groups.delete({groupKey: external_id})` | 404 = success | — |

**Defaults**: mailing-list group, email `<slug>@<workspace-domain>`, `accessLevel: INVITED_CAN_JOIN`.

**Cross-provider caveat**: GW group email is immutable. Renaming a team in Yggdrasil renames the slack channel and the GH team, but the GW group email stays at the original slug. The group `name` field updates. This is a known limitation, documented for operators.

### Spec.reactors entries

Each adapter's `integration_type.spec.reactors` ends with these 3 entries (github already has `team.created` declared, so it only adds the latter two):

```json
{"event_type": "team.created", "capability": "on_team_created", "description": "Provision external team resource"},
{"event_type": "team.updated", "capability": "on_team_updated", "description": "Update external team resource"},
{"event_type": "team.deleted", "capability": "on_team_deleted", "description": "Archive/delete external team resource"}
```

These entries make `MaterializeReactions` enqueue a reaction row whenever the canon event is emitted.

## Reconcile cron + bootstrap

A new addon, `internal/teamreconcile/runner.go`, follows the same shape as `internal/manifestsync/runner.go`. It runs every 5 minutes.

### Query

```sql
SELECT t.id AS team_id,
       ii.id AS instance_id
FROM teams t
CROSS JOIN manifests ii
JOIN manifests it
  ON it.kind = 'integration_type'
  AND it.namespace = (ii.spec->'type_ref'->>'namespace')
  AND it.name = (ii.spec->'type_ref'->>'name')
  AND it.active = true
LEFT JOIN team_provisioning_log tpl
  ON tpl.team_id = t.id
  AND tpl.integration_instance_id = ii.id
WHERE t.deleted_at IS NULL
  AND ii.kind = 'integration_instance'
  AND ii.active = true
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(COALESCE(it.spec->'reactors','[]'::jsonb)) r
    WHERE r->>'event_type' = 'team.created'
  )
  AND tpl.id IS NULL;
```

For each row, the cron emits `team.created` for `team_id`. `MaterializeReactions` naturally creates rows for all matching instances; for instances that already have a log entry, the adapter responds with a no-op idempotent path. This trades 1-2 wasted RPCs per cron tick for code simplicity. At DaKasa scale (≤ 100 teams × 3 adapters), the cost is negligible.

### Bootstrap

No special bootstrap step. The first execution of the cron after deploy emits events for every team that lacks a log entry. The full reconcile completes within one cron cycle (≤ 5 min) for any reasonable team count.

### Operator-triggered force-sync

Endpoint `POST /api/v1/teams/{id}/sync`: re-emits `team.created` for the given team. Returns `{events_emitted: N}` on success. Useful for debugging or replaying after fixing an adapter.

## Error handling & observability

### Inherited from reactor framework (no new code)

- **Exponential backoff** via `internal/reactors/backoff.go` (1s, 4s, 16s, 64s, ...)
- **Dead letter** after configurable max attempts → `integration_event_reactions.status = 'dead_lettered'` and emits `reactor.dead_lettered` canon event
- **Status tracking** via `integration_event_reactions.status ∈ {pending, in_progress, succeeded, failed, dead_lettered}`
- **Audit log** integration via `/ops/audit`

### New endpoints

1. **`POST /api/v1/teams/{id}/sync`** — force re-emit `team.created`
2. **`GET /api/v1/teams/{id}/provisioning-status`** — returns:
   ```json
   {
     "team_id": "...",
     "provisioning": [
       {"integration_instance_id": "...", "integration_type": "slack", "external_id": "C123", "last_success_at": "..."},
       ...
     ],
     "pending": [...],
     "dead_lettered": [...]
   }
   ```

The surface-console TeamDetailPage will consume this in V2 for a "Sistemas vinculados" card.

### Failure scenarios

| Failure | Behavior | Sufficient? |
|---|---|---|
| GH API 401 (token expired) | Adapter error → backoff → eventual dead_letter | Yes — operator renews token + force-sync |
| Slack `name_taken` (channel exists manually) | Adapter lookup + returns external_id. No error. | Yes — idempotence |
| GW domain mismatch (invalid email chars in slug) | Adapter 400 → eventual dead_letter | Acceptable — operator sees audit + renames team |
| Network partition (core ↔ rabbit) | Runner won't claim → events stay pending | Yes — retry on recovery |
| Team deleted while adapter offline | `team.deleted` pending → archive on adapter recovery | Yes |

## Testing

### Core (yggdrasil-core)

| Component | Test | Type |
|---|---|---|
| `team_provisioning_log` migration | Schema valid + indexes present | Migration |
| `repository.UpsertTeamProvisioningLog` | Upsert via `ON CONFLICT`, `updated_at` advances | DB integration |
| Dispatcher envelope handler | Adapter response with `_yggdrasil.team_provisioned` → log upsert | Unit |
| `teamreconcile.Runner.tick()` | Mock DB: 3 teams + 1 instance with 1 log → emit 2 events | Unit + DB |
| `/teams/{id}/sync` | Emits + returns count | HTTP |
| `/teams/{id}/provisioning-status` | Returns log + pending + dead_lettered | HTTP |

### Adapters

Each adapter gains tests for its new handlers (3 for slack, 2 for github, 3 for google-workspace; github's `on_team_created` already has tests):

| Handler | Cases |
|---|---|
| `on_team_created` | (a) create-new, (b) already-exists lookup, (c) API 5xx error |
| `on_team_updated` | (a) rename success, (b) same value no-op, (c) provider-restricted (GW email immutable) |
| `on_team_deleted` | (a) success, (b) 404 idempotent, (c) other errors propagated |

Reuse existing `httptest` mocks (slack, github) and Google SDK fakes.

### Manual E2E (runbook)

Five scenarios to validate on staging post-deploy:

1. **Happy path**: create team via UI → all 3 adapters reflect within 30s
2. **Adapter down**: pause integration-slack → create team → reaction pending → resume slack → catch-up
3. **Rename**: edit team name → 3 renames fire (GW group name only, not email)
4. **Delete**: delete team → 3 archives/deletes
5. **Bootstrap**: confirm pre-existing teams reconcile within first 5-min cycle after deploy

### Tests deliberately skipped (YAGNI)

- Performance benchmarks (DaKasa scale doesn't justify)
- Chaos / partition tests
- Multi-tenant isolation (single-tenant today)

## Out of scope (V2+)

- Surface UI for provisioning status (TeamDetailPage card + retry button)
- List + diff reconcile (would surface orphans on the external side — gh teams not in Yggdrasil)
- Per-team `external_config` JSONB field for default overrides
- GitHub team repo permission sync (today, teams are created with no repo grants)
- Slack channel pinned message / runbook automation
- Cross-adapter consistency check (e.g., 3 logs present but slack archive failed silently)

## File inventory (target shape for the plan)

### yggdrasil-core
- `migrations/00043_team_provisioning_log.sql` — new (next free number; pick highest+1 at implementation time)
- `model/team_provisioning_log.go` — new
- `repository/team_provisioning_log.go` — new + `_test.go`
- `internal/reactors/payload.go` — extend envelope handler for `team_provisioned` + `_test.go`
- `internal/teamreconcile/runner.go` — new + `_test.go`
- `controllers/httpapi/team_sync.go` — new (`/teams/{id}/sync`, `/teams/{id}/provisioning-status`) + `_test.go`
- `controllers/httpapi/server.go` — route registration

### integration-slack
- `internal/adapter/spec.go` — 3 new operation constants + spec.reactors entries
- `internal/adapter/reactors.go` — `onTeamCreated`, `onTeamUpdated`, `onTeamDeleted` + `_test.go`
- `examples/integration_type.example.json` — 3 new reactors entries

### integration-github
- `internal/adapter/spec.go` — 2 new operation constants (`on_team_updated`, `on_team_deleted`) + spec.reactors entries
- `internal/adapter/reactors.go` — `onTeamUpdated`, `onTeamDeleted` + `_test.go`
- `examples/integration_type.example.json` — 2 new reactors entries

### integration-google-workspace
- `providers/runtime/adapter/spec.go` — 3 new operation constants + spec.reactors entries
- `providers/runtime/adapter/reactors.go` — `onTeamCreated`, `onTeamUpdated`, `onTeamDeleted` + `_test.go`
- `providers/runtime/manifest.json` — 3 new reactors entries

## Decisions log

| Decision | Rationale |
|---|---|
| Provisioning log (Opção A) over stateless ensure or list+diff | Single table + envelope reuse from `collaborator_external_identities`. Zero spam events. Cheap observability via SQL. |
| Sensible per-adapter defaults over `external_config` JSONB | V1 YAGNI. All teams want private slack + closed gh team + mailing list. Customization can live in V2 if anyone asks. |
| Re-emit "dumb" (not filtered by instance) in cron | Trades 1-2 wasted no-op RPCs per tick for simpler emit path. DaKasa scale: irrelevant. |
| Channel name prefix `"team-"` (slack) | Avoids collision with ad-hoc channels. Operators can override in V2 if needed. |
| GW group email is immutable on rename | Provider limitation, documented. Operators choose meaningful slugs at create time. |
| No new alerts/metrics in V1 | Reactor framework already emits `reactor.dead_lettered`. Operator dashboards can subscribe. |
