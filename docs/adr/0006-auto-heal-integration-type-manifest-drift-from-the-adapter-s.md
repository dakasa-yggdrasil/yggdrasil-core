# ADR-0006: Auto-heal `integration_type` manifest drift from the adapter's live `describe` response, preserving only the operator-owned `reactors` field

- **Status:** Accepted
- **Date:** 2026-05-16
- **Deciders:** unknown
- **Scope:** yggdrasil-core (`integration_type` manifest lifecycle)
- **Supersedes:** —
- **Superseded by:** —

## Context

Each `integration_type` manifest persists a snapshot of an adapter's contract (action catalog, capabilities, credential schema, etc.), while the adapter also exposes the live version of that same contract via a `describe` RPC on every `integration_health` handshake (~30s), stored as `integration_runtime_states.details.live_contract`. The two snapshots drift as adapters evolve independently of when a manifest version was last applied (via `dakasa-system` PRs or manual `apply_reactors.py` runs). When drift exceeds tolerance the instance is marked `status=contract_mismatch`, which blocks *all* operations on that instance — discovered as the hard blocker preventing the lifecycle reactor framework from dispatching to a live instance, and also blocking routine operator workflows. A manual bootstrap (`integration-github-dakasa` → manifest v28 merged from live describe) validated the fix empirically before this design was written.

## Decision

Add a single core addon, `manifest_sync` (priority 75, immediately after `reactor_dispatcher@70`), that converges `integration_type` manifests with adapter live `describe` responses via one function, `SyncIntegrationType(ctx, db, rabbit, typeID)`, reachable through three trigger paths:

- **Event-driven (primary):** when `integration_health` observes `contract_mismatch`, it emits `runtime_state.contract_mismatch_detected` (debounced 60s per instance) and sends a non-blocking in-process Go channel signal (`manifestsync.Notify`) so sync reacts in seconds, not on the next poll.
- **Cron (safety net):** a `time.Ticker` (default 1h) walks all active integration types and syncs each, covering a dropped channel signal (lost on restart) or drift that never crossed the mismatch threshold.
- **Manual:** `POST /api/v1/integration-types/{id}/sync` runs the same algorithm synchronously and returns the outcome inline.
- **Merge is rule-based, not configurable:** the new spec is built entirely from the live `describe` response (`action_catalog`, `capabilities`, `credential_schema`, `discovery`, `execution`, `extensions`, `instance_schema`, `normalization`, `provider`, `resource_types`, adapter version) — **except** `reactors`, which is preserved verbatim from the currently persisted spec because it is the one field operators edit post-deploy via the manifests API. Any future operator-owned field extends this rule mechanically, not by adding configuration.
- Sync is a hard no-op (emits nothing by default) when the merged spec `reflect.DeepEqual`s the current one; every other outcome (`synced`, `sync_no_op` behind a debug flag, `sync_skipped` with a structured reason) is a canon event — there is deliberately no separate DB audit table, since the event log plus manifest version history already provide full audit.
- No internal retry logic: the addon is stateless per invocation; the 1h cron plus event-driven re-trigger together provide re-attempt without backoff bookkeeping.
- Always re-invokes `describe` live rather than reading the cached `live_contract` off `integration_runtime_states` — a rejected alternative, ruled out because cached data can be ~30s stale and would create two diverging code paths between the event-driven and cron triggers.
- Scope is explicitly per-`integration_type`, not per-instance: `integration_instance` spec sync and other manifest kinds are out of scope, as is replacing the existing `dakasa-system` PR-based manifest-source reconciler for human-managed changes. A rejected alternative did per-instance "effective spec" sync; that model is not used.

## Consequences

- `contract_mismatch` stops being an operator-manual-intervention state in the common case — it self-heals within seconds (event path) to at most 1h (cron worst case) as long as the adapter is reachable and returns a valid describe response.
- Operators' only durable customization surface on an `integration_type` manifest is `reactors`; any other hand-edit is silently overwritten on the next sync — a deliberate constraint, documented in the addon's package comment.
- Instance-level manifest overrides remain a separate, unaddressed abstraction — this decision does not extend to `integration_instance` specs.
- Validation at the merge boundary (non-empty `action_catalog`, present `credential_schema`, non-empty `adapter_version`) is the only defense against a broken/incomplete describe response; failure there yields `sync_skipped(reason=invalid_describe)` rather than writing a bad manifest.
- Production validated: a `[]string` vs `[]any` JSON Schema type mismatch bug in the initial `diff_summary` event payload (sha-109d859) was caught and fixed (sha-cd073df) — schema validators here are strict about JSON's lack of native array element typing; new event payload fields must use `[]any`-compatible encoding.

## Related
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-16-sync-manifest-from-describe.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md`
