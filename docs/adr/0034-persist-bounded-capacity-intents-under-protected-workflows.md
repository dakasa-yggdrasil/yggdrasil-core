# ADR-0034: Persist bounded capacity intents under protected workflows

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / provider-neutral capacity planning and workflow receipts
- **Supersedes:** None
- **Superseded by:** None

## Context

Independent metric observers can trigger conflicting expansions and reductions.
Missing data is not evidence of spare capacity. Provider operations may time out
after mutation, and a process restart must not erase unfinished work. The Core
also serves authentication and must not gain a privileged autonomous dispatch
path as a side effect of capacity planning.

## Decision

Represent each operator-owned environment/domain/dimension with a bounded
`capacity_policy` and one durable PostgreSQL intent. Serialize assessment and
lease changes, coalesce unclaimed proposals, preserve unfinished generations,
and fence lease recovery with monotonically increasing tokens. Require an exact
active protected workflow for the in-process capacity operations. Keep both
process-wide execution and each policy disabled by default.

Require finite source samples, independently fresh timestamps, declared units,
window extrema, coverage and bounded observation gaps before changing capacity
above the protected floor. Restore a breached floor from a fresh identified
snapshot even when demand telemetry is unavailable. Require external workflow
receipts for preparation, canary, drain and promotion, and observed target state
before recording completion. Price and validation declarations must remain valid
through the profile's declared preparation horizon.

## Consequences

- PostgreSQL is the durable coordinator; a database outage stops new decisions.
- Native HPA remains the fast replica controller. Provider-specific adapters
  enforce identity, ownership, bounds, CAS and replay semantics separately.
- A Core lease is not atomic with a provider API. An expired owner can still be
  executing remotely. Fixed workflows must renew before mutation, pass fencing
  tokens and idempotency keys, and reconcile uncertain writes through readback.
- Recovery-only leases can record authoritative completion or verified no-effect
  outcomes under the original immutable policy after quote expiry or revision.
  They require mutation quiescence and provider fencing receipts, authorize no
  new acquisition and do not imply that skipped canary phases were executed.
- Receipt fields are assertions by a protected operator-owned workflow, not
  cryptographic provider attestation. Core does not invent health or drain probes.
- Resource replacement, traffic switching and cross-provider data migration
  require separate workflows. This protocol preserves resource UIDs throughout
  one generation and does not silently move stateful workloads.
- This foundation does not activate a fleet, certify provider stock, migrate
  storage, or promise a cost/DAU/availability result.

## Related

- ADR-0017: exact machine workflow dispatch and run ownership.
- ADR-0024: final-state assertions fail on drift.
- ADR-0027: authenticated actor channels for protected workflows.
- [Capacity protocol](../features/capacity-intents.md).
