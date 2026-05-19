# Tartaro Team-scoped Granular Permissions — Design

**Date**: 2026-05-18
**Status**: Approved (brainstorming phase complete)
**Repos affected**: yggdrasil-core, integration-tartaro-dakasa, dakasa-tartaro-api (`backend/dakasa-tartaro-api` + `backend/tartaro-operations`)

## Motivation

Yggdrasil teams have `team_grants` — a (team_id, integration_instance, action_name) link that's intended to grant per-team capabilities to integrations. Today this exists but nothing in tartaro consumes it: tartaro authorization runs through `collaborator.traits.tartaro_roles`, a per-user array maintained by `tartaro:assign_rbac_role`. To grant 5 collaborators "moderator" you need 5 individual operations.

This spec replaces the role-based per-user model with **action-level grants scoped to teams**, materialized via the team reactor framework (sha-7b10c31). End-state: create a team `moderators`, grant it actions `tartaro:moderate_post` + `tartaro:decide_report`, add 5 users → all 5 inherit those actions via `traits.tartaro_actions`. Tartaro-api's `authz.Evaluate(collab, action)` reads `tartaro_actions` directly.

User-approved decisions:
- **Fine-grained actions** (not roles) on team_grant
- **Materialized trait** `tartaro_actions` written by reactor (eager sync)
- **Full migration**: `tartaro_roles` deprecated in V1 (big-bang)
- **Backend + API only**: UI for managing grants is V2

## Current state inventory

| Component | Status |
|---|---|
| `team_grants` table + CRUD | ✅ exists (yggdrasil-core) |
| Canon events `team_grant.added/revoked` | ❌ table mutates emit no events today |
| Team reactor framework (canon events → adapter via AMQP) | ✅ shipped 2026-05-18 (item #2) |
| `integration-tartaro-dakasa` capabilities | partial — 8 collaborator-level capabilities, none team-level |
| `tartaro-operations` role catalog `GET /internal/admin/roles` | ✅ exists |
| `tartaro-operations` role→actions mapping endpoint | ❌ not exposed |
| `tartaro-api authz.Client.Evaluate` reads | `tartaro_roles` — needs swap to `tartaro_actions` |
| `traits.tartaro_actions` populated | ❌ trait doesn't exist yet |

## Architecture

```
                          ┌──────────────────────────────────────────┐
                          │              Yggdrasil-core              │
                          │                                          │
   POST /teams/{id}/      │  TeamGrant CRUD          team_grants     │
   grants (existe) ──────▶│   (action_name = e.g.    table           │
                          │    tartaro:moderate_post)                │
                          │                            │             │
                          │                            ▼             │
                          │              EmitEvent team_grant.*      │
   POST /teams/{id}/      │              EmitEvent team_membership.* │
   memberships ──────────▶│                            │             │
                          │                            ▼             │
                          │              MaterializeReactions        │
                          │                            │             │
                          │                            ▼             │
                          │              Reactor.Runner → AMQP       │
                          └────────────────────────────┼─────────────┘
                                                       │
                                                       ▼
                          ┌──────────────────────────────────────────┐
                          │     integration-tartaro-dakasa adapter   │
                          │                                          │
                          │   on_team_membership_added/removed       │
                          │   on_team_grant_added/revoked  (NEW)     │
                          │                                          │
                          │   For each affected user:                │
                          │     1. List active team memberships      │
                          │     2. List grants per team (this        │
                          │        integration_instance only)        │
                          │     3. UNION action_names                │
                          │     4. PUT collaborator.traits.          │
                          │        tartaro_actions = sorted_union    │
                          └──────────────────────────────────────────┘
                                                       │
                                                       ▼
                          ┌──────────────────────────────────────────┐
                          │              tartaro-api                 │
                          │                                          │
                          │   authz.Evaluate(collab, action):        │
                          │     return action ∈ tartaro_actions      │
                          │   (legacy tartaro_roles path REMOVED)    │
                          └──────────────────────────────────────────┘
```

### Four critical flows

1. **Operator grants action to team**: `POST /teams/{id}/grants` → emit `team_grant.added` → adapter recomputes trait for every active team member
2. **User joins team**: `team_membership.added` → adapter recomputes trait for one user
3. **User leaves team**: `team_membership.removed` → adapter recomputes (UNION shrinks)
4. **Team deleted**: cascade emits `team_grant.revoked` × N + `team_membership.removed` × M → adapter recomputes ex-members

### Reuse vs new

- **Reuse 90% from item #2**: canon events table, MaterializeReactions, Reactor.Runner, AMQP dispatch
- **New core**: 2 canon events (`team_grant.added`, `team_grant.revoked`), 2 endpoints (`/effective-tartaro-actions`, `/sync-tartaro-actions`)
- **New adapter**: 4 capabilities (membership added/removed + grant added/revoked) — even though we list the 4, `on_team_membership_*` already exists by name in the spec but currently no-ops; replace with the recompute logic
- **New tartaro-api**: authz.Evaluate rewrite (one function, ~10 lines) + sweep call sites

## Data model

### New canon events

In `yggdrasil-core/repository/event_types_lifecycle.go`:

```go
EventTypeTeamGrantAdded   = "team_grant.added"
EventTypeTeamGrantRevoked = "team_grant.revoked"
```

Add both to `CanonLifecycleEventTypes` set. Update `TestSyncEventTypesAreNotCanonLifecycle` if it asserts a fixed count.

### Payloads

```json
// team_grant.added
{
  "id": "<grant_uuid>",
  "team_id": "<uuid>",
  "integration_instance_namespace": "dakasa",
  "integration_instance_name": "integration-tartaro-dakasa",
  "action_name": "tartaro:moderate_post",
  "scope": null,
  "granted_by": "giovanni@dakasa.me"
}

// team_grant.revoked
{
  "id": "<grant_uuid>",
  "team_id": "<uuid>",
  "action_name": "tartaro:moderate_post"
}
```

Emitted transactionally in the existing grant CRUD handlers (`controllers/httpapi/server.go::handleTeamGrantCreate` / `handleTeamGrantRevoke`) inside the same DB transaction as the row mutation.

### Schema (no migration)

`team_grants` table already exists from migration `00036_team_grants.sql`. No new columns. Just emit events on mutation.

### New collaborator trait

`collaborator.traits.tartaro_actions: []string` — sorted, deduped UNION of all action_names from grants on teams the collaborator is an active member of, scoped to the tartaro instance.

Written exclusively by the adapter's recompute helper. Read by tartaro-api.

### `tartaro_roles` trait fate

Preserved in DB during V1 for audit/rollback only. Tartaro-api stops reading it. Adapter stops writing it (the `tartaro:assign_rbac_role` and `tartaro:revoke_rbac_role` capabilities are deprecated — see migration section).

## Adapter contract (integration-tartaro-dakasa)

### Four new dispatcher cases

In `internal/capabilities/dispatch.go`:

```go
case "tartaro:on_team_membership_added", "tartaro:on_team_membership_removed":
    var p struct { CollaboratorID string `json:"collaborator_id"` }
    if err := json.Unmarshal(payload, &p); err != nil { return Result{}, err }
    actions, err := RecomputeUserTartaroActions(ctx, ygg, p.CollaboratorID)
    if err != nil { return Result{}, err }
    return Result{OK: true, Data: map[string]any{
        "collaborator_id": p.CollaboratorID,
        "tartaro_actions": actions,
    }}, nil

case "tartaro:on_team_grant_added", "tartaro:on_team_grant_revoked":
    var p struct {
        TeamID                       string `json:"team_id"`
        IntegrationInstanceNamespace string `json:"integration_instance_namespace"`
        IntegrationInstanceName      string `json:"integration_instance_name"`
    }
    if err := json.Unmarshal(payload, &p); err != nil { return Result{}, err }
    if !isThisInstance(p.IntegrationInstanceNamespace, p.IntegrationInstanceName) {
        return Result{OK: true, Data: map[string]any{"skipped": "different integration_instance"}}, nil
    }
    affected, err := RecomputeTeamMembers(ctx, ygg, p.TeamID)
    if err != nil { return Result{}, err }
    return Result{OK: true, Data: map[string]any{
        "team_id":          p.TeamID,
        "users_recomputed": len(affected),
    }}, nil
```

### Helper `RecomputeUserTartaroActions`

New file `internal/capabilities/effective_actions.go`:

```go
func RecomputeUserTartaroActions(ctx context.Context, ygg *yggdrasilclient.Client, collabID string) ([]string, error) {
    memberships, err := ygg.ListTeamMemberships(ctx, collabID, true)
    if err != nil { return nil, fmt.Errorf("list memberships: %w", err) }

    instanceNS, instanceName := tartaroInstanceRef()
    seen := map[string]struct{}{}
    for _, m := range memberships {
        grants, err := ygg.ListTeamGrants(ctx, m.TeamID)
        if err != nil { return nil, fmt.Errorf("list grants team %s: %w", m.TeamID, err) }
        for _, g := range grants {
            if g.IntegrationInstanceNamespace != instanceNS || g.IntegrationInstanceName != instanceName {
                continue
            }
            if g.ActionName == "*" { continue }
            seen[g.ActionName] = struct{}{}
        }
    }

    actions := make([]string, 0, len(seen))
    for a := range seen { actions = append(actions, a) }
    sort.Strings(actions)

    if err := ygg.UpdateCollaboratorTraits(ctx, collabID, map[string]any{
        "tartaro_actions": actions,
    }); err != nil {
        return nil, fmt.Errorf("update traits: %w", err)
    }
    return actions, nil
}

func RecomputeTeamMembers(ctx context.Context, ygg *yggdrasilclient.Client, teamID string) ([]string, error) {
    members, err := ygg.ListTeamMembershipsByTeam(ctx, teamID, true)
    if err != nil { return nil, err }
    var collabIDs []string
    for _, m := range members {
        if _, err := RecomputeUserTartaroActions(ctx, ygg, m.CollaboratorID); err != nil {
            // log + continue — single user's failure shouldn't block others
            continue
        }
        collabIDs = append(collabIDs, m.CollaboratorID)
    }
    return collabIDs, nil
}
```

### `isThisInstance` guard

Compares against the adapter's own (namespace, name) read from its config. Prevents tartaro adapter from recomputing on a `team_grant.added` event that targets `integration-slack-dakasa`.

### Yggdrasil-client extensions

`internal/yggdrasilclient/`:

- `ListTeamMemberships(collabID, activeOnly)` — likely exists; verify
- `ListTeamMembershipsByTeam(teamID, activeOnly)` — `GET /api/v1/team-memberships?team_id=X&active=true`
- `ListTeamGrants(teamID)` — `GET /api/v1/teams/{teamID}/grants`
- `UpdateCollaboratorTraits(collabID, traits)` — `PATCH /api/v1/collaborators/{id}/traits`

### Reactor declarations

`integration.yaml` adds 4 reactors to the existing list:

```yaml
reactors:
  - event_type: team_membership.added
    capability: tartaro:on_team_membership_added
    description: Recompute traits.tartaro_actions for the user joining
  - event_type: team_membership.removed
    capability: tartaro:on_team_membership_removed
    description: Recompute traits.tartaro_actions for the user leaving
  - event_type: team_grant.added
    capability: tartaro:on_team_grant_added
    description: Recompute traits.tartaro_actions for every active member
  - event_type: team_grant.revoked
    capability: tartaro:on_team_grant_revoked
    description: Same — revoke side
```

### Deprecation of role capabilities

`tartaro:assign_rbac_role` and `tartaro:revoke_rbac_role` are deprecated in V1. They remain in the manifest for backward compat but their implementation becomes a no-op + warning log. Operators should grant actions at team level instead.

## Tartaro-api refactor + migration

### `authz.Client.Evaluate` rewrite

`backend/dakasa-tartaro-api/internal/authz/client.go`:

```go
func (c *Client) Evaluate(ctx context.Context, collabID, action string, scope map[string]any) (bool, error) {
    collab, err := c.yggdrasil.GetCollaborator(ctx, collabID)
    if err != nil {
        c.logger.Warn("authz.Evaluate fetch collaborator failed",
            zap.Error(err), zap.String("collab", collabID))
        return false, err
    }

    actions, _ := collab.Traits["tartaro_actions"].([]any)
    if len(actions) == 0 {
        // Telemetry: surfaces users without the migrated trait — useful
        // post-deploy to spot migration gaps.
        c.logger.Info("evaluate: tartaro_actions trait empty or absent",
            zap.String("collab", collabID), zap.String("action", action))
    }
    for _, a := range actions {
        if s, ok := a.(string); ok && s == action {
            return true, nil
        }
    }
    return false, nil
}
```

### Call-site sweep

```bash
grep -rn 'tartaro_roles\|Traits\["tartaro_roles"\]\|tartaroRoles' \
  backend/dakasa-tartaro-api/ backend/tartaro-{review,legal,operations,notify}/
```

Each match is migrated to read `tartaro_actions` (the implementation already calls `Evaluate(action)` in most places; the trait reads are only in helpers that build user-facing role labels). Expect ~5-10 sites. Tests are updated in the same commit.

### New endpoint in tartaro-operations

`GET /internal/admin/roles/{slug}/actions` — returns the canonical action set for a role slug. Powers the migration script.

```go
// backend/tartaro-operations/internal/handlers/role_actions.go (new file)
func (h *Handler) GetRoleActions(c *gin.Context) {
    slug := c.Param("slug")
    actions, err := h.roleCatalog.ActionsForRole(slug)
    if err != nil {
        c.JSON(404, gin.H{"error": "role not found", "slug": slug})
        return
    }
    c.JSON(200, gin.H{"role": slug, "actions": actions})
}
```

The implementation depends on how tartaro-operations stores role→actions today. The plan investigates as task 1.

### Migration script

Path: `yggdrasil-core/scripts/migrate_tartaro_roles_to_actions/main.go`.

Behavior (steps run sequentially, idempotent):

1. Connect to Yggdrasil DB + tartaro-operations API
2. SELECT collaborators with non-empty `traits.tartaro_roles`
3. For each distinct role slug, GET `/internal/admin/roles/{slug}/actions` → cache the action set
4. For each role, find-or-create `team` named `tartaro-legacy-{role_slug}` (with description noting it's auto-generated for migration)
5. For each (role, action), find-or-create `team_grant`
6. For each (collaborator, role), find-or-create active `team_membership`
7. Print JSON summary: `{users_migrated, teams_created, grants_added, errors}`

Modes:
- `--dry-run`: print what would change, don't mutate
- `--validate`: compare expected `tartaro_actions` per user (via lookup) against current `tartaro_actions` trait; list any drift; non-zero exit on drift
- (default) `apply`: do the migration

Idempotent: find-or-create everywhere. Re-runnable without producing duplicates.

Audit log: all team/grant/membership creates emit canon events through the normal Yggdrasil flow → reactor materializes traits.tartaro_actions naturally.

### Deploy order (big-bang sequence)

1. **Ship `tartaro-operations`** — adds `/internal/admin/roles/{slug}/actions` endpoint
2. **Ship `integration-tartaro-dakasa`** — new capabilities + helper; deprecate role capabilities
3. **Ship `yggdrasil-core`** — new canon events + `/effective-tartaro-actions` + `/sync-tartaro-actions`
4. **Run migration script** with `--validate` first (must pass cleanly). Then `apply`
5. **Ship `tartaro-api`** — authz.Evaluate reads `tartaro_actions`; sweep call sites

Step 4 must complete successfully before step 5. Step 5 will deny every user whose trait wasn't populated, so `--validate` is mandatory.

Rollback path: revert step 5 deploy → tartaro-api goes back to reading `tartaro_roles` (still preserved in DB).

## Error handling & observability

### Inherited from reactor framework

- Exponential backoff on reactor failures (1s, 4s, 16s, 64s, ...)
- Dead letter after max attempts
- Per-reaction status visible in `integration_event_reactions.status`
- Audit log via `/ops/audit`

### Tartaro-specific failure modes

| Failure | Behavior | Sufficient? |
|---|---|---|
| `ListTeamMemberships` 500 | Adapter error → reactor retries. Trait stale for a tick. | Yes — eventual consistency |
| `UpdateCollaboratorTraits` 409 (concurrent edit) | Yggdrasil's optimistic concurrency. Adapter retry. | Yes — converges in seconds |
| `tartaro-ops /roles/{slug}/actions` 404 | Migration logs warning + skips that role (no team created) | Operator reviews logs |
| `tartaro-api Evaluate` with `tartaro_actions` empty | Deny + log info-level "trait empty or absent" | Yes — fail closed |
| User in 5 teams all granting same action | UNION dedup, single trait entry | Yes — set semantics |
| Wildcard `*` in a team_grant | V1 silently skipped (debug log) | Yes — V2 expands |
| Network partition between adapter and Yggdrasil | Reaction stays pending; retries on recovery | Yes |

### New endpoints

**`GET /api/v1/collaborators/{id}/effective-tartaro-actions`**

```json
{
  "collaborator_id": "...",
  "trait_tartaro_actions": ["tartaro:moderate_post", "..."],
  "effective_via_teams": [
    {"team_id": "...", "team_slug": "moderators", "actions": ["..."]},
    ...
  ],
  "drift": false
}
```

Returns the trait (what tartaro-api will see) plus the ground-truth recomputation (what reactor *should* have set). `drift: true` when the two disagree — signals reactor lagged or failed.

**`POST /api/v1/collaborators/{id}/sync-tartaro-actions`**

Operator escape hatch. Emits a synthetic event that the tartaro adapter receives and processes the same as a normal `team_membership.*` reaction → recomputes + PUTs. Returns the resulting trait. 202 Accepted.

### Logging conventions

Adapter handler logs structured fields on every recompute:

```go
logger.Info("recomputed tartaro_actions",
    zap.String("collab_id", collabID),
    zap.Int("teams_count", len(memberships)),
    zap.Int("actions_count", len(actions)),
    zap.String("trigger", capability))
```

Powers queries like "users whose actions changed in last 1h" via /ops/audit.

### No new metrics in V1

V2 can add `tartaro_trait_drift_total` gauge and `tartaro_recompute_duration_seconds` histogram.

## Testing

### Yggdrasil-core

| Component | Test | Type |
|---|---|---|
| `EventTypeTeamGrantAdded/Revoked` in `CanonLifecycleEventTypes` | Set inclusion + sync_events_are_not_canon test extension | Unit |
| `handleTeamGrantCreate/Revoke` emits canon event | POST `/teams/{id}/grants` → event_log row | HTTP |
| `/effective-tartaro-actions` | Materialized + recomputed, drift detection | DB integration |
| `/sync-tartaro-actions` | Emits synthetic event, recompute returns trait | HTTP |

### integration-tartaro-dakasa

| Capability | Cases |
|---|---|
| `on_team_membership_added` | (a) 1 team → trait = grants; (b) 3 teams → UNION; (c) no teams → trait `[]` |
| `on_team_membership_removed` | (a) shrinks; (b) action retained via overlap |
| `on_team_grant_added` | (a) 5 members → 5 recomputes; (b) different instance → skipped |
| `on_team_grant_revoked` | (a) all members recompute; (b) wildcard skipped |
| `RecomputeUserTartaroActions` helper | Mock client; varied membership/grant combinations |

### tartaro-api

| Component | Test |
|---|---|
| `authz.Client.Evaluate` reads `tartaro_actions` | Trait has action → allow; doesn't → deny; trait absent → deny + log |
| Sweep call sites | Each updated call site has regression test |

### tartaro-operations

| Endpoint | Test |
|---|---|
| `GET /internal/admin/roles/{slug}/actions` | Returns actions for existing role; 404 for unknown |

### Migration script

| Mode | Test |
|---|---|
| `--dry-run` | Lists planned mutations, doesn't apply |
| `--validate` | Computes expected `tartaro_actions` per user, compares with current; non-zero exit on drift |
| `apply` (default) idempotent | Run 2× → second run no-op |

### Manual E2E (staging runbook)

Seven scenarios post-deploy:

1. **Post-migration sanity**: query `/effective-tartaro-actions` for a known user, confirm matches role→action mapping
2. **Grant action to team**: POST grant `tartaro:moderate_post` → all members' traits include action within 30s
3. **Add user to team**: POST membership → user gains team's actions
4. **Remove user from team**: trait shrinks (preserves overlaps)
5. **Revoke action from team**: trait shrinks for all members
6. **tartaro-api Evaluate probes**: known-allow + known-deny actions match trait
7. **Force-sync outlier**: `POST /sync-tartaro-actions` for a user, then `/effective-tartaro-actions` → drift=false

### Skipped (YAGNI for V1)

- Performance benchmarks (DaKasa scale doesn't justify)
- Concurrent modification stress (Yggdrasil's 409 + retry covers)
- Wildcard expansion (`action_name="*"`) — V2

## Out of scope (V2+)

- Surface-console UI for managing team grants for tartaro (TeamDetailPage card with action picker)
- Wildcard `action_name="*"` resolution at adapter level
- Per-action scope expansion (today `scope` field is preserved but unused by tartaro)
- Self-service "request access" flows
- Migration of `tartaro_roles` field cleanup (drop column in V2 after stable)
- Tartaro-fe admin page showing effective permissions per user (debug surface)
- Cross-action constraints (e.g., "can only moderate posts in own region")

## File inventory

### yggdrasil-core
- `repository/event_types_lifecycle.go` — modify (2 new constants + set entries)
- `controllers/httpapi/server.go` — modify (`handleTeamGrantCreate/Revoke` emit canon events)
- `controllers/httpapi/tartaro_actions.go` — new (2 endpoints + `_test.go`)
- `controllers/httpapi/server.go` — modify (route registration)

### integration-tartaro-dakasa
- `internal/capabilities/dispatch.go` — modify (4 new cases)
- `internal/capabilities/effective_actions.go` — new (RecomputeUserTartaroActions + RecomputeTeamMembers + `_test.go`)
- `internal/yggdrasilclient/client.go` — modify (3 new methods)
- `integration.yaml` — modify (4 new reactors, 4 new capabilities, deprecate 2 old)
- `example.json` — modify (4 new examples)

### dakasa-tartaro-api (`backend/dakasa-tartaro-api`)
- `internal/authz/client.go` — modify (Evaluate rewrite)
- (call-site sweep — N files identified via grep during plan)

### tartaro-operations (`backend/tartaro-operations`)
- `internal/handlers/role_actions.go` — new (+ `_test.go`)
- routes registration — modify

### Migration script
- `yggdrasil-core/scripts/migrate_tartaro_roles_to_actions/main.go` — new
- `yggdrasil-core/scripts/migrate_tartaro_roles_to_actions/main_test.go` — new

## Decisions log

| Decision | Rationale |
|---|---|
| Action-level grants over roles (B over A) | User-specified granularity preference; aligns with tartaro-api's per-action Evaluate model |
| Materialize trait via reactor (over query-time) | Fast Evaluate path, source of truth in Yggdrasil, eventual consistency acceptable for RBAC at DaKasa scale |
| Big-bang migration (over coexistence) | User-chosen; simpler end-state; relies on `--validate` mode for safety |
| Backend + API only in V1 | YAGNI; UI work is independent and can come in V2 without re-spec |
| Wildcard `*` skipped in V1 | Avoids surprise grants; explicit only |
| Always-full-recompute (no diff) | Simpler, order-independent, atomic per-user; cost is acceptable at DaKasa scale |
| Find-or-create migration script | Idempotent retries; safe to re-run after failure |
