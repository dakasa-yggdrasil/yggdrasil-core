# ADR-0035: Prune expired capacity history without changing intent authority

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity event maintenance
- **Supersedes:** None
- **Superseded by:** None

## Context

Capacity phase and fencing transitions append event history. Continuous
operation needs a review horizon and bounded maintenance, while pending
provider recovery must preserve its exact policy, generation and lease state.
Several Core replicas may attempt maintenance concurrently.

## Decision

Provide an explicitly enabled, default-off retention addon for historical
`capacity_intent_events`. Remove one bounded batch per tick, using database time,
row claims with `SKIP LOCKED` and a five-second cancellation bound. Require a
matching authoritative current intent and retain its current and immediately
previous generations regardless of age. Never delete or rewrite intent state,
lease/fencing authority, orphan history or provider resources. Cancel and join
the panic-safe worker during shutdown.

## Consequences

- Source delivery alone enables no cleanup or actuation. The operator chooses
  and explicitly activates a review horizon of at least 30 days.
- Defaults after opt-in are 90 days, 1000 rows and a 15-minute cadence. Bounded
  settings and invalid-configuration refusal prevent an accidental fast sweep.
- Concurrent replicas can perform disjoint batches. Protected generations and
  orphan events remain retained, so this is not a hard table size cap.
- PostgreSQL integration CI must prove bounded concurrent deletion and exact
  preservation of live private intent/lease state before delivery.

## Related

- [ADR-0034](0034-persist-bounded-capacity-intents-under-protected-workflows.md).
- [Capacity protocol](../features/capacity-intents.md).
