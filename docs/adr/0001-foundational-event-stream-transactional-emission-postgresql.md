# ADR-0001: Foundational event stream — transactional emission, PostgreSQL-backed cursor pull, JSON Schema contracts

- **Status:** Accepted
- **Date:** 2026-04-10
- **Deciders:** unknown
- **Scope:** yggdrasil-core

## Context

Yggdrasil-core needed a foundational primitive so external, language-agnostic consumers could react to state-change events (manifest mutations, product installs, workflow completions, authorization decisions) without polling every domain endpoint or depending on Go-typed internal structures. It needed to be atomic with the mutation that caused it (no orphaned events on rollback), support ordered replay by any consumer, and evolve without breaking existing consumers.

## Decision

Implement a single `event_log` table as the system-wide event stream primitive:

- **Schema**: `public.event_log` with `event_id UUID` (v7, time-ordered) as primary key and a `sequence BIGSERIAL` for global monotonic ordering, plus `type`, `schema_version`, `aggregate_type`, `aggregate_id`, optional `actor_type/actor_id/actor_context`, `emitted_at`, `payload JSONB`, `metadata JSONB`. Indexed by `(sequence)`, `(type, sequence)`, `(aggregate_type, aggregate_id, sequence)`, and `emitted_at`.
- **Transactional emission**: `repository.EmitEvent(ctx, tx *sql.Tx, req)` MUST be called with an existing, caller-owned transaction (never opens its own) — the event only persists if the state mutation it accompanies commits. It validates the payload against the event type's JSON Schema before insert and rejects on failure.
- **Contracts**: every event type has a JSON Schema (`docs/contracts/events/v1/<domain>/<name>.json`, draft 2020-12) embedded into the binary via `//go:embed` and compiled/cached at first use. `schema_version` is part of both the row and the contract path; `v1` is declared **forever non-breaking** — new optional fields only, never removed/renamed/retyped fields. Breaking changes require a new `v2` schema family coexisting with `v1`.
- **Consumption**: a pull-based RPC (`event_stream.pull`) takes an **opaque** cursor string (internally `seq:<N>`), a limit (default 100, max 1000), and filters (`types` with `*` wildcard via SQL `LIKE`, `aggregate_type`, `aggregate_id`, `supported_schema_versions`, `emitted_after`), returning `{events, next_cursor, has_more}`. Per-aggregate ordering is guaranteed; cross-aggregate ordering is monotonic by `sequence` but not strictly causal.
- **Retention**: a separate `event_retention_policy` table maps `type_pattern` (wildcard) → `ttl_days` (0 = infinite), seeded with defaults (90 days catch-all, 2555 days/~7yr for `authorization.*`, infinite for `manifest.*`, 365 for `buildproject.*`, 30 for `workflow.step.*`, 180 for `workflow.run.*`). A background addon (`event_log_cleaner`) periodically runs `CleanupExpiredEvents`, one `DELETE ... WHERE type LIKE ... AND emitted_at < NOW() - ttl_days` per active policy.
- **No secrets in payloads**: events are documented to never carry credential/secret values in clear — only `secret_ref` pointers.

## Consequences

- Every future domain mutation that wants to notify external consumers must emit through `EmitEvent` inside its existing transaction; this is now the canonical extension point rather than ad hoc webhooks or direct RPC fan-out per feature.
- Consumers in any language integrate by polling `event_stream.pull` and persisting the opaque cursor themselves — the core makes no delivery guarantee beyond "resume from your last cursor, no backfill/no gaps for cross-aggregate correlation."
- `v1` schemas are a long-term compatibility commitment — any field removal/retype is a breaking change requiring a new schema_version, not an in-place edit.
- Retention is enforced destructively (hard DELETE) per type pattern; a wrong `ttl_days` on a pattern silently deletes events, so retention_policy changes need care (`manifest.*` is intentionally infinite/`0` since it doubles as audit history).
- This event stream is later reused as the delivery mechanism for higher-level canon events (e.g. `team_grant.added/revoked`, `collaborator_external_identity.*`) defined in later work — those events ride the same `event_log` table, `EmitEvent` transactional contract, and JSON Schema validation established here.

## Related
- scratch: `docs/superpowers/plans/2026-04-10-event-stream-implementation.md`
