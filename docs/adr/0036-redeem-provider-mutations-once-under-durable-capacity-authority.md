# ADR-0036: Redeem provider mutations once under durable capacity authority

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / provider-neutral capacity mutations

## Context

A leased capacity intent is not native provider fencing. Some VM APIs have no
mutation CAS or idempotency header. After a lost response, a current GET or lease
expiry cannot prove that an older invocation will never create a resource.
Repeating the write can overspend, conflict with deletion or violate the floor.

## Decision

Bind each non-secret canonical adapter dry-run spec to an operator-approved
profile/slot digest, exact instance/type checksums and adapter principal. Issue
grants only inside the policy's active authenticated workflow and private live
executor lease. PostgreSQL holds one unresolved grant per logical native slot
and counts live membership plus reservations against the intended envelope.
Register existing membership from fresh protected native reads; never adopt
replacement or overwrite a deletion tombstone implicitly.

Allow one successful atomic redemption to return `write_once`. Every replay,
including the same attempt, returns `read_only`. The adapter privately generates
its attempt and settlement nonce before redemption. Core stores only the nonce
hash. SDK writes do not retry. Owning transport settlement is authenticated on
an exact independent callback surface and remains available after execution
pause or policy replacement. Public receipts contain neither private executor
authority nor settlement material.

Keep accepted or uncertain mutations reserved until owning transport facts and
fresh complete native action/immutable resource proof are both recorded. Only
never-redeemed permissions expire safely. Native rejections can retire a grant
only through an exact operator-reviewed no-acceptance status/error contract;
the default list is empty. Refuse floor deletion, require a durably admitted
drain, preserve immutable identity/action history and block terminal capacity
intents while any grant remains unresolved.

Represent this authority as `core_mutation_grants`, with no fabricated native
provider fencing token. It is distinct from existing provider-CAS recovery.

## Consequences

The private adapter credential grants callbacks for one exact instance and a
bounded capability set. It cannot issue grants, dispatch workflows, access the
console or inherit a session. Opt-in inventories are parsed once, hashed,
rotation/expiry scoped and checked against all existing credential families.
Callback bodies and secret nonce headers must not enter logs or workflow output.

An unknown provider write may remain unresolved indefinitely. This is an honest
recovery state, not a cancellation certificate. External operators and ungated
mutators remain outside this ledger and require exclusive fleet ownership.
Capacity, bootstrap, business readiness, canary routing, dependency reserve,
drain and paid auxiliary-resource removal require their own observations.
Slot/grant history is authoritative and is not pruned by event retention.

## Related

- [ADR-0034](0034-persist-bounded-capacity-intents-under-protected-workflows.md)
- [Provider mutation contract](../features/capacity-mutations.md)
