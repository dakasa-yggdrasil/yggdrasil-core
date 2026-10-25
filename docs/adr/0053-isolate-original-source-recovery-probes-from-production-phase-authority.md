# ADR-0053: Isolate original Source recovery probes from production phase authority

- **Status:** Proposed
- **Date:** 2026-10-18
- **Deciders:** Pending repository owner review
- **Scope:** yggdrasil-core / original Guest native qualification recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

The original qualification serving probe reserves and finishes its signed echo under a normal execution lease. A recovered intent has a historical, readback-only lease. Reusing the normal probe methods for that intent fails their existing lease check; changing those methods would widen production phase authority.

Source qualification also needs to distinguish an unchanged live baseline during partial recovery from confirmation of an already settled original creation after a policy pause. Neither elapsed time nor a baseline GET alone proves that a late mutation is absent.

## Decision

Keep the original production probe methods and migration constraints unchanged. Compile the recovery probe protocol only with `linux && nativequalification`. Require the exact historical lease and `RecoveryOnly` in its repository methods, and retain the original signed challenge, enrollment, transport return, freshness and deadline checks. Store those returns in separate fixture-owned Source tables with closed recovery usage and stage values. Install the original immutable-update/delete trigger on both tables before their first use.

Activate each recovery scenario only through its exact Source-owned selector and the existing authenticated workflow. A partial result requires actual complete membership, zero outstanding mutations, a fresh signed echo and a fresh physical observation. Historical creation confirmation requires the original settled grant and authentic fresh observation of the same resource; it cannot mint another creation permission.

For terminal recovery, retain the actual first and replayed typed mutation returns separately, with their identities, modes and body hashes. These are typed reserializations, not raw HTTP captures. Retain the exact terminal refusal class, predicate, return count and byte hash when an outstanding mutation prevents termination. An unchanged grant and a boolean alone do not establish custody of those returns.

Keep failed-owner cleanup separate from successful creation, positive admission and ordinary compensation. Its Source-only authority, physical return and terminal accounting must be separate immutable records. Actual termination, Wait/EOF/close and anchored disk absence establish physical cleanup; a cleanup label does not. Preserve the original creation settlement and receipt.

A Source failed-floor scenario may use a separate, qualification-only reconciliation method bound to the exact Source case, current actors, source identities and recovery lease. That method must validate the signed cleanup terminal for its exact failed parent, reject every other outstanding mutation, and retain the normal snapshot, freshness, floor, fencing and generation checks. It cannot alter the ordinary production reconciliation method or claim that a settled parent became canonically compensated. A floor-policy bridge must bind the actual prior and current policy manifests and allow only the declared floor increase; it cannot manufacture a new baseline observation.

Keep the original two-slot limit and outer, provisioning and child deadlines. A recovered database lease does not renew the original caller deadline. Preserve ordinary production behavior and every existing negative gate.

## Consequences

These Source cases exercise bounded protocol components. They do not certify production business health, provider cancellation, the complete original test matrix or a runtime fit. Their generated records must retain their Source-only scope, current source identities and original owners' returns.

Separate fixture tables are a qualification implementation detail, not an approved production migration. Production adoption would require its own reviewed contract and evidence. Compilation, original execution, complete custody and independent actual readback remain necessary before runtime credit.

## Related

- ADR-0036 (provider mutation authority)
- ADR-0037 (fixed native observations)
- ADR-0046 (bounded capacity intents)
- ADR-0050 (original Guest admission and retirement)
