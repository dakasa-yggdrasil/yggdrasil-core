# ADR-0040: Separate native process lifetimes from reservation decisions

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / protected native HPA reservation and process lifetimes
- **Supersedes:** ADR-0039 (selected-subset execution design).

## Context

The native HPA/Deployment controller may retire any existing Pod after reservation
bounds change. Protecting a selected subset and deleting that subset separately
can retire an additional unprotected baseline lifetime. A process startup nonce
cannot be invented for a predecessor, and an all-baseline bootstrap prerequisite
would prevent a controlled rolling adoption. Resolved lifetime history must not
permanently exhaust a bounded active ledger.

## Decision

Use an independent immutable lifetime ledger for every actual current native
Pod/container/start/restart/process nonce. Protect and acknowledge the complete
current baseline before pressure CAS. The fixed executor never deletes a Pod;
actual controller-selected victims require complete current native termination,
durable acknowledgement and a separate one-use finalizer release.

Separate protected candidate admission from pressure execution. Current schema-two
candidates can receive actual projection/startup acknowledgement while old schema-one
baseline stays frozen and explicitly unqualified. No admission flag, caller
receipt, generic process snapshot or predecessor nonce establishes readiness.
Each consumer must await its actual startup acknowledgements before opening roots.

Keep reservation completion distinct from lifetime completion. Applied envelope
and hold decisions retain alive obligations across generations. Reconcile unknown
redeemed sends through native reads only and preserve the global write fence.
Archive only authoritative complete terminal bundles with immutable records,
digests and permanent UID/command/token fences. Never prune unresolved or alive
records by TTL, age or a scrape disappearing.

## Consequences

This supersedes the selected-subset execution design in immutable ADR0039 without
rewriting its historical proposal. New binding mode, schema two process admission,
protected workflows and actual mixed-rollout/controller adversary qualification
are required. Local successful joins, native process/Pod termination, useful
capacity, warm stock and provider uncertainty remain separate. No production or
provider activation follows from source implementation.
