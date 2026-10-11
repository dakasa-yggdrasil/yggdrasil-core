# ADR-0037: Produce native VM proofs through fixed protected observers

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / provider-neutral VM observation and mutation readback

## Context

The durable mutation ledger needs native membership, owning creation labels,
terminal actions and auxiliary absence. A workflow-supplied boolean or an unused
pure transformer does not establish those facts. Native VM presence also does
not establish Kubernetes membership, warm models, healthy business capacity or
writer fencing.

## Decision

Expose four fixed protected operations: `capacity.observe_vm_inventory`,
`capacity.observe_failed_vm_creation`, `capacity.record_vm_inventory` and
`capacity.confirm_native_mutation`. Select adapter capabilities and inputs inside
Core, from an exact operator-approved policy binding. Resolve the active instance
and type UUIDs/checksums, hydrate through the existing secret boundary, validate
the actual action/resource catalog and verify the live Describe contract. Accept
only explicit closed VM-slot observation responses with fresh source timestamps.
Caller input contains no native proof, adapter selector, URL, completeness,
readiness, drain or fencing assertion.

Keep physical membership distinct from useful capacity. Require a complete
bounded partition of configured slots, exact approved projections, immutable
native tuples and standard ownership labels. Preserve an authenticated partial
failed creation as an explicit unresolved member, excluded from physical-member
registration. Pin its original private receipt and any stored native readback;
complete terminal failed history does not itself authorize cleanup.

Connect internally obtained facts to the existing guarded membership and grant
stores. Reuse private invocation/executor, lease owner and fencing epoch checks,
including empty inventories and already-confirmed readbacks. Per-slot registration
can partially commit on later refusal; exact retries are safe, and a separate
ledger comparison must pass before reporting registered coverage. Never infer a
missing member's deletion or revive a tombstone. Confirm a mutation only after
owning transport settlement, exact current native target and successful owning
actions. Require every independently billable auxiliary absence for deletion.
Replay does not emit a second applied event.

## Consequences

These operations do not dispatch native creates/deletes, issue grants, acquire
leases, calculate demand or qualify a provider. Observations remain non-atomic.
Physical configuration assertions are trusted only from the exact reviewed
adapter/type/instance contract; Core independently binds the closed identity and
scope. Ordinary confirmation excludes compensation children. Their existing
separate compensation authority remains responsible for cleanup admission.

Unknown deletion actions after resource absence remain reserved. Cross-profile
migration, node bootstrap, workload warmth, business canary, healthy floor,
routing withdrawal and drain require separate authoritative producers. Fake
native APIs plus PostgreSQL validate source integration, not real provider
availability, cost, throughput, stock, account identity or production readiness.

## Related

- [ADR-0036](0036-redeem-provider-mutations-once-under-durable-capacity-authority.md)
- [Native VM observations](../features/capacity-native-observations.md)
