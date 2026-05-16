# Sync Manifest From Describe — Design Spec

**Date:** 2026-05-16
**Status:** Approved — ready for implementation plan
**Drives:** Auto-heal of `integration_type` manifest drift against live adapter describe responses; eliminates the `contract_mismatch` blocker discovered post-reactor-framework deployment.

---

## 1. Background

Each `integration_type` manifest persisted in the cluster describes one
adapter's contract: `action_catalog`, `capabilities`, `credential_schema`,
`discovery`, `execution`, `extensions`, `instance_schema`, `normalization`,
`provider`, `resource_types`, and (operator-managed) `reactors`.

The adapter itself, at runtime, exposes the same contract live via the
`describe` RPC over RabbitMQ. The handshake runs on every `integration_health`
check (~30s interval) and stores the live response as
`integration_runtime_states.details.live_contract`.

**Problem:** these two snapshots drift apart. Adapters evolve on their own
cadence (new capabilities, schema additions). The persisted manifest is
frozen at the version last applied via `dakasa-system` PRs or manual
`apply_reactors.py`. When drift exceeds the runtime monitor's tolerance,
the instance is marked `status=contract_mismatch`, which **blocks all
operations** on that instance — including the lifecycle reactor dispatch
that just shipped, and ad-hoc operator workflows like creating new repos.

This was discovered as the immediate blocker preventing live propagation
of reactor framework events on 2026-05-15. Manual bootstrap of one
integration (`integration-github-dakasa` → manifest v28 merged from
live describe) was performed and validated this design empirically.

---

## 2. Goal

Auto-heal drift between adapter live describe and persisted
`integration_type` manifest. Drift becomes self-healing within seconds
of detection, with no operator action required.

**Non-goals:**
- Not in scope: `integration_instance` spec sync (instance spec is
  operator-owned, no adapter counterpart).
- Not in scope: other manifest kinds (`workflow`, `cron`,
  `manifest_source`, etc.).
- Not in scope: replacing the existing manifest-source reconciler that
  pulls `dakasa-system` PRs — that flow remains for human-managed
  manifest changes.

---

## 3. Architecture

Single core addon `manifest_sync`, priority **75** (immediately after
`reactor_dispatcher@70`). Self-contained in `yggdrasil-core`; does not
depend on any specific integration or surface.

```
                               ┌────────────────────────┐
        ┌──────────────────────│ runtime monitor        │
        │ contract_mismatch    │ (integration_health.go)│
        │ event                └────────────────────────┘
        │
        ▼
┌──────────────────┐         ┌─────────────────────┐
│ manifest_sync    │         │ cron ticker (1h)    │
│ event subscriber │         │ enumerate types     │
└──────────────────┘         └─────────────────────┘
        │                              │
        └──────────────┬───────────────┘
                       ▼
            ┌──────────────────────┐
            │ SyncIntegrationType  │
            │   (typeID)           │
            └──────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   describe RPC    merge logic    POST manifest
   (10s timeout)   live + reac.   apply v(N+1)
        │              │              │
        └──────────────▼──────────────┘
            emit canon event
       (synced|sync_no_op|sync_skipped)
```

**Three trigger paths converge on the same `SyncIntegrationType(typeID)`
function** — that is the only place spec rebuilds + applies happen.

---

## 4. Components

### 4.1 New files

| Path | Responsibility |
|---|---|
| `addons/manifest_sync.go` | Bootstrap addon. Registers runner, wires HTTP endpoint, starts on `Bootstrap` |
| `internal/manifestsync/runner.go` | Event subscriber goroutine + cron ticker goroutine. Both call `SyncIntegrationType` |
| `internal/manifestsync/syncer.go` | `SyncIntegrationType(ctx, db, rabbit, typeID)` — single source of truth for the algorithm |
| `internal/manifestsync/merge.go` | `MergeSpec(currentSpec, liveContract) (newSpec, diffSummary)` — preserves `reactors`, replaces everything else from live |
| `internal/manifestsync/events.go` | Emit helpers: `EmitSynced`, `EmitSyncNoOp`, `EmitSyncSkipped` |
| `controllers/httpapi/integration_type_sync.go` | `POST /api/v1/integration-types/{id}/sync` synchronous manual trigger |
| `docs/contracts/events/v1/integration_type/synced.json` | JSON Schema for `integration_type.synced` |
| `docs/contracts/events/v1/integration_type/sync_no_op.json` | JSON Schema (rarely emitted; debug only) |
| `docs/contracts/events/v1/integration_type/sync_skipped.json` | JSON Schema |
| `docs/contracts/events/v1/runtime_state/contract_mismatch_detected.json` | JSON Schema |

### 4.2 Modified files

| Path | Change |
|---|---|
| `controllers/message/integration_health.go` | After handshake outcome, if `status=contract_mismatch` and (no prior emit OR last emit > 60s ago), publish `runtime_state.contract_mismatch_detected` event. In-memory debounce map keyed by `instance_id` |
| `repository/event_types_lifecycle.go` | Add 4 new canon event type constants + entries in `CanonLifecycleEventTypes` map (or new `CanonSyncEventTypes` if the existing map is reactor-scoped) |
| `controllers/httpapi/server.go` | Register `POST /api/v1/integration-types/{id}/sync` route guarded by admin auth |
| Addon registry (wherever `reactor_dispatcher` is wired) | Register `manifest_sync` addon at priority 75 |

---

## 5. Algorithm

```
SyncIntegrationType(ctx, db, rabbit, typeID):
    1. currentType ← repository.GetLatestActiveIntegrationType(typeID)
       if not found:
         emit sync_skipped(reason="type_not_found"); return

    2. instances ← repository.ListIntegrationInstancesByType(typeID)
       if empty:
         emit sync_skipped(reason="no_instances"); return

       sourceInstance ← pickFirstHealthy(instances)
                        or pickAny(instances)  # fallback: even mismatched
                                               # instances can describe;
                                               # adapter is alive, manifest
                                               # is wrong, that is the case
                                               # we are healing.
       if sourceInstance is nil:
         emit sync_skipped(reason="no_describable_instance"); return

    3. liveContract, err ← messagecontroller.InvokeDescribe(
                              ctx, rabbit, sourceInstance,
                              timeout=10s)
       if err != nil:
         emit sync_skipped(reason="rpc_failed", error=err); return

    4. if liveContract.ActionCatalog is empty
        OR liveContract.CredentialSchema is missing
        OR liveContract.AdapterVersion is empty:
         emit sync_skipped(reason="invalid_describe"); return

    5. newSpec, diffSummary ← merge.MergeSpec(currentType.Spec, liveContract)

    6. if reflect.DeepEqual(currentType.Spec, newSpec):
         emit sync_no_op  # default: suppressed; toggle via DEBUG_SYNC_NO_OP env
         return

    7. err ← repository.ApplyIntegrationTypeVersion(ctx, db, {
            name:        currentType.Name,
            namespace:   currentType.Namespace,
            description: currentType.Description,  # operator-owned, preserved
            active:      true,
            spec:        newSpec,
        })
       if err:
         emit sync_skipped(reason="apply_failed", error=err); return

    8. emit integration_type.synced {
            type_id, from_version, to_version,
            diff_summary, source_instance_id,
        }
```

### 5.1 Merge rules (`merge.MergeSpec`)

```
MergeSpec(current Spec, live LiveContract) -> (new Spec, diff Summary):
    new := Spec from live   # action_catalog, capabilities,
                            # credential_schema, discovery, execution,
                            # extensions, instance_schema,
                            # normalization, provider, resource_types
                            # adapter (version metadata)
    new.Reactors := current.Reactors  # operator-managed, preserved verbatim
    return new, diff(current, new)
```

The merge is **rule-based, not user-configurable**. Only `reactors` is
preserved because it is the only field today that operators can edit
post-deploy via the manifests API. If future operator-owned fields are
introduced, this merge rule extends mechanically.

`diff` is a small structural summary: `{added_actions: [...],
removed_actions: [...], schema_changed: bool, capabilities_changed: bool}`,
embedded in `integration_type.synced` payload for audit.

---

## 6. Detection (event emission + in-process signal)

`controllers/message/integration_health.go` already runs the describe
handshake per instance. After computing the result, it does two things
atomically: persist the canon event to the outbox (audit trail) AND
send a non-blocking in-process signal so the runner reacts immediately
without polling the events table.

```
if newStatus == "contract_mismatch":
    cacheKey := instance.ID
    lastEmittedAt := emitDebounceMap[cacheKey]
    if lastEmittedAt is zero OR now - lastEmittedAt > 60s:
        # 1. Persisted audit (always)
        repository.EmitEvent(ctx, db, "runtime_state.contract_mismatch_detected", {
            instance_id, type_id, instance_namespace, instance_name,
            type_namespace, type_name, detected_at: now,
        })
        emitDebounceMap[cacheKey] = now

        # 2. In-process signal to runner (fire-and-forget)
        manifestsync.Notify(type_id)   # see §7.1
```

In-process debounce map is sufficient because each handshake worker is
single-threaded per instance. Map is bounded by number of instances
(~30 in current cluster).

---

## 7. Triggers

### 7.1 Event-driven (primary)

`internal/manifestsync/runner.go` exports a buffered Go channel
`notifyCh chan uuid.UUID` and a wrapper function:

```go
package manifestsync

var notifyCh = make(chan uuid.UUID, 128)

// Notify enqueues a sync request for typeID. Non-blocking: if buffer is
// full, drops the signal — the next cron tick (within 1h) will pick it
// up. Callers (e.g. integration_health) MUST tolerate dropped signals.
func Notify(typeID uuid.UUID) {
    select {
    case notifyCh <- typeID:
    default: // buffer full, rely on cron safety-net
    }
}
```

The runner consumes:

```go
for typeID := range notifyCh {
    go func(id uuid.UUID) {
        mu := perTypeMutex(id)
        mu.Lock()
        defer mu.Unlock()
        SyncIntegrationType(ctx, db, rabbit, id)
    }(typeID)
}
```

Concurrent syncs of the same `typeID` are serialized via a per-type
mutex (`map[uuid.UUID]*sync.Mutex` guarded by an outer mutex). POST
manifests is idempotent (creates new version) but we avoid wasted RPC
round-trips.

**Why a channel, not a DB tailer:** detection happens in the same
process as the runner (both inside `yggdrasil-core`); a channel is
~µs latency vs the reactor dispatcher pattern's 5s table-poll. The
persisted event in step 1 of detection is the audit record; the
channel is purely a fast-path nudge. On core restart, the channel
buffer is lost — the cron loop within 1h covers correctness.

### 7.2 Cron-driven (safety-net)

`time.Ticker` at `MANIFEST_SYNC_INTERVAL` (default `1h`). Each tick:

```
types := repository.ListAllActiveIntegrationTypes(ctx, db)
for each type:
    go SyncIntegrationType(type.ID)
```

Goroutines are unbounded only by type count (~30 today). If types grow
past ~200, introduce a worker pool. YAGNI for now.

### 7.3 Manual (operator on-demand)

`POST /api/v1/integration-types/{id}/sync` runs synchronously, returns
the same outcome shape as the event payload, so operators can verify
result without polling events.

```
HTTP 200 → {status: "synced"|"no_op", from_version, to_version, diff_summary}
HTTP 422 → {status: "skipped", reason, error}
HTTP 404 → type not found
HTTP 401 → unauthorized
```

Same admin auth pattern as `/api/v1/manifests` POST.

---

## 8. Error handling

Every failure path emits exactly one `integration_type.sync_skipped`
event with structured `reason`:

| Reason | Trigger | Retry behavior |
|---|---|---|
| `type_not_found` | Type ID resolves to nothing | No retry (consistent bug; alert) |
| `no_instances` | Type has no `integration_instance` rows | Next cron tick or future instance create |
| `no_describable_instance` | All instances `inactive` | Next cron tick |
| `rpc_failed` | Describe RPC timeout/error | Next cron tick or new mismatch event |
| `invalid_describe` | Adapter returned malformed/empty spec | Next cron tick (likely adapter bug → alert) |
| `apply_failed` | POST `/api/v1/manifests` rejected | Next cron tick |

**No internal retry.** Addon is stateless. Cron (1h) + event-driven
together guarantee re-attempt without explicit backoff. This keeps the
runner trivial and observable: every attempt is a fresh event in the
event log.

If `invalid_describe` or `apply_failed` recurs >5 times within 24h for
the same type, an operator should investigate. (Out of scope: alert on
recurrence — operators monitor event log manually for now; future work
could add a `manifest_sync.flapping` aggregate event.)

---

## 9. Observability

### 9.1 Canon events (4 new)

| Event | Emitted by | Payload |
|---|---|---|
| `runtime_state.contract_mismatch_detected` | `integration_health.go` | `{instance_id, type_id, instance_namespace, instance_name, type_namespace, type_name, detected_at}` |
| `integration_type.synced` | `syncer.go` (success path) | `{type_id, type_namespace, type_name, from_version, to_version, diff_summary, source_instance_id, synced_at}` |
| `integration_type.sync_no_op` | `syncer.go` (no diff) | `{type_id, checked_at, source_instance_id}` — **default suppressed**; toggle `DEBUG_SYNC_NO_OP=true` |
| `integration_type.sync_skipped` | `syncer.go` (any failure path) | `{type_id, reason, error, attempted_instance_id, attempted_at}` |

### 9.2 JSON Schemas

Each event has a schema in `docs/contracts/events/v1/<aggregate>/<event>.json`,
validated via the existing `events_validator` pipeline. Schema
constraints (illustrative for `integration_type.synced`):

- `type_id`: format=uuid, required
- `from_version`: integer ≥ 1, required
- `to_version`: integer ≥ from_version + 1, required
- `diff_summary`: object with `added_actions[]`, `removed_actions[]`,
  `schema_changed`, `capabilities_changed` — required

### 9.3 Why no DB audit table

`manifest_sync_runs` was considered but rejected: events already provide
complete audit (with payload), the `manifests` table itself records every
version applied with timestamp, and an extra table duplicates state.

---

## 10. Configuration

Env vars (all optional, sensible defaults):

| Var | Default | Purpose |
|---|---|---|
| `MANIFEST_SYNC_ENABLED` | `true` | Kill switch; if `false`, addon registers but runner exits immediately |
| `MANIFEST_SYNC_INTERVAL` | `1h` | Cron safety-net frequency |
| `MANIFEST_SYNC_DESCRIBE_TIMEOUT` | `10s` | Per-instance describe RPC timeout |
| `MANIFEST_SYNC_DEBOUNCE` | `60s` | Cooldown between `contract_mismatch_detected` emissions per instance |
| `DEBUG_SYNC_NO_OP` | `false` | Emit `sync_no_op` events (default: silent) |

No PostgreSQL migration required.

---

## 11. Testing strategy

### 11.1 Unit tests

`internal/manifestsync/merge_test.go` (table-driven):

1. Reactors-only-change: current has `reactors:[A]`, live has no reactors → new has `reactors:[A]` + live rest
2. Adapter added capability: current `action_catalog:[a,b]`, live `[a,b,c]` → new has `[a,b,c]` + current reactors
3. Schema rev: current `credential_schema:{v1}`, live `{v2}` → new has `{v2}` + current reactors
4. Adapter removed action: current `[a,b,c]`, live `[a,b]` → diff shows `removed_actions:[c]`
5. Identical: current.spec == live → return current.spec (caller detects no-op)
6. Live missing required field (`adapter_version`) → caller bails on `invalid_describe`
7. Current has no reactors field, live no reactors → new has no reactors field
8. Live has unexpected `reactors` field (shouldn't happen but defensive) → ignored, current's reactors win

`internal/manifestsync/syncer_test.go` (mocked DB + RPC):

1. Happy path: describe ok, diff exists, apply succeeds → emits `synced`
2. RPC timeout → emits `sync_skipped(rpc_failed)`
3. No instances → emits `sync_skipped(no_instances)`
4. No-op path → emits no event in default mode; emits `sync_no_op` with `DEBUG_SYNC_NO_OP=true`
5. Apply returns 409 (race with concurrent operator apply) → emits `sync_skipped(apply_failed)`
6. Invalid describe (empty action_catalog) → emits `sync_skipped(invalid_describe)`
7. First instance offline, second healthy → uses second
8. All instances `contract_mismatch` → uses first one anyway (paradox case: heal by describe)

### 11.2 Integration tests

`internal/manifestsync/sync_integration_test.go` (real Postgres + RabbitMQ + mock adapter):

1. **Bootstrap drift fix:** seed integration_type v1 (incomplete spec), fake adapter responds with full describe → sync → DB has v2 matching describe + preserved (empty) reactors
2. **Reactors preserved:** seed v1 with `reactors:[X]`, fake adapter responds without reactors → v2 still has `reactors:[X]`
3. **Idempotency:** second invocation after sync → no new version, emits `sync_no_op` (with DEBUG flag), no error
4. **Multi-instance:** two instances, first AMQP-unreachable, second responds → sync uses second's describe
5. **Event-driven:** publish `contract_mismatch_detected` directly to internal event bus → addon picks up → sync happens

### 11.3 E2E smoke (manual, in CHANGELOG/spec)

Replicates the 2026-05-15 bootstrap exactly:
1. Pick an `integration_type` X with `live_contract` != `spec` in
   `integration_runtime_states`.
2. Confirm at least one `integration_instance` of X exists.
3. Wait for handshake or manually `POST /api/v1/integration-types/{X}/sync`.
4. Verify new manifest version applied (`SELECT version FROM manifests
   WHERE name=X ORDER BY version DESC LIMIT 1` returns N+1).
5. Verify `integration_type.synced` event emitted.
6. Wait for next handshake → instance transitions to `healthy`.
7. Confirm operations against instance now succeed (e.g., dispatch any
   workflow that uses one of the instance's capabilities).

---

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Adapter bug returns broken describe → sync writes broken manifest | Validation at step 4 of algorithm rejects empty `action_catalog`, missing `adapter_version`, missing `credential_schema`. `sync_skipped(invalid_describe)` emitted; operator alerted via event log |
| Sync overwrites operator-managed adapter field | Only `reactors` is operator-managed today. If new operator fields emerge, extend merge rule. Document this contract in `addons/manifest_sync.go` package comment |
| Event storm during massive cluster restart | Per-instance 60s debounce on `contract_mismatch_detected`. Per-type mutex in runner prevents concurrent syncs |
| Apply race vs operator manual edit | POST manifests is "next-version creates" — no overwrite. If operator just applied v(N+1) and sync wanted to write same-content v(N+2), step 6 deep-equal catches no-op |
| Adapter offline indefinitely | Sync keeps retrying every 1h cron tick; emits `sync_skipped(rpc_failed)`. Manifest stays at old version. Instance stays unhealthy. No operations attempted (intended behavior — fix the adapter, not the manifest) |

---

## 13. Alternatives considered

**Workflow-based (option B in brainstorm)**: declarative steps in YAML
workflow + cron entity + reactor of `kind:core`. Rejected because: (1)
merge logic is awkward in workflow DSL; (2) adds three new manifest kinds
to wire; (3) reactor framework currently doesn't support `kind:core`
reactors (per memory note on gap).

**Hybrid (option C in brainstorm)**: core addon dispatches workflow.
Rejected: duplicates abstractions, doesn't add value over A.

**Cached `live_contract` from runtime_states**: read from already-stored
DB column instead of re-invoking describe. Rejected: cached data could
be ~30s stale (handshake interval); two code paths (event vs cron)
diverge; live RPC is consistent and not expensive.

**Per-instance manifest sync**: instead of per-type, sync each
instance's "effective spec" independently. Rejected: integration_type
is intentionally type-scoped (one spec serves all instances). Per-
instance overrides are a different abstraction (instance config), not
managed here.

---

## 14. Implementation phases (sketch — actual plan to be authored separately)

1. **Foundation:** new package `internal/manifestsync/` with merge + tests, no wiring
2. **Event types & schemas:** 4 canon event types + JSON Schemas + validator registration
3. **Detection:** modify `integration_health.go` to emit `contract_mismatch_detected` with debounce
4. **Syncer:** `SyncIntegrationType` function + unit tests with mocked deps
5. **Runner:** event subscriber + cron loop + per-type mutex
6. **Addon bootstrap:** wire runner into `addons/` at priority 75
7. **HTTP endpoint:** `POST /api/v1/integration-types/{id}/sync` + admin auth
8. **Integration tests:** real Postgres + RabbitMQ + fake adapter
9. **E2E smoke:** repeat the github bootstrap manually; verify all events emitted
10. **Documentation:** README in `internal/manifestsync/` + ADR if needed

---

## 15. Success criteria

- `integration_type` drift between adapter live describe and persisted
  manifest is detected and resolved within 5 minutes (event-driven) or
  60 minutes (cron-only worst case).
- Operator-managed `reactors` block survives across syncs.
- No new manual operator action required to keep manifests healthy.
- Existing reactor dispatch + workflow operations resume normal
  function on instances previously blocked by `contract_mismatch`.
- 85%+ unit + integration test coverage in `internal/manifestsync/`.
- Zero observed cases of sync writing an invalid manifest version.

---

## 16. E2E smoke results (2026-05-16)

Addon shipped to production at `sha-cd073df` (includes the bug fix from sha-109d859 → cd073df: `[]string` arrays in `diff_summary` were rejected by the JSON Schema validator's reflect-based type check; converted to `[]any` to match validator expectations).

**Event-driven path** — proven on pod start with 5 pre-existing drifted instances:

| Type | from | to | detected_at | bumped_at | gap |
|---|---|---|---|---|---|
| google-workspace | v8 | v9 | 04:59:19.706 | 04:59:23.333 | 3.6s |
| slack | v6 | v7 | 04:59:19.799 | 04:59:23.331 | 3.5s |
| schema-migrations-goose-postgres | v1 | v2 | 04:59:20.105 | 04:59:23.241 | 3.1s |
| tartaro | v2 | v3 | 04:59:20.401 | 04:59:23.275 | 2.9s |
| yggdrasil-self | v14 | v15 | 04:59:20.601 | 04:59:23.354 | 2.8s |

All 5 transitioned `contract_mismatch` → `healthy` within ~60s on subsequent handshake cycles.

> **NOTE:** The synced events for the initial 5 were NOT persisted because of the `[]string` validator bug. The bug fix landed in sha-cd073df. After redeploy, forcing a fresh drift on `slack` (re-applying v6 spec as v10) produced a clean test that confirmed the full pipeline:
>
> | Step | Result |
> |---|---|
> | Operator applies slack v10 with v6's spec (drift forced) | OK |
> | Runtime monitor detects mismatch on next handshake (~30s) | `runtime_state.contract_mismatch_detected` emitted at 05:15:21 |
> | Runner consumes Notify, runs SyncIntegrationType | apply v11 succeeded |
> | Synced event emitted | `integration_type.synced` `{from_version:10, to_version:11, diff_summary:{added_actions:[], removed_actions:[], schema_changed:true, capabilities_changed:false}}` |
> | Next handshake (~30s) | slack runtime_state `v11 healthy` |

**Manual HTTP path** — proven on `grafana` (version_mismatch case):

```bash
POST /api/v1/integration-types/4633462c-3865-4a03-b456-76c648df1c81/sync
→ HTTP 422
→ {"error":"describe integration type global/grafana through transport \"rabbitmq\": version_mismatch...","reason":"rpc_failed","status":"skipped"}
```

`integration_type.sync_skipped` event persisted with reason=rpc_failed.

**Slack no-op path** — proven on second manual trigger after auto-sync resolved:

```bash
POST /api/v1/integration-types/8de5e107-30ef-4101-a6cf-54c59f390754/sync
→ HTTP 200
→ {"status":"no_op"}
```

No event emitted (default `DEBUG_SYNC_NO_OP=false`).

**All 5 originally-drifted manifests reached steady state**: latest active versions now match live describe responses; runtime monitor reports them healthy. Framework production-ready.
