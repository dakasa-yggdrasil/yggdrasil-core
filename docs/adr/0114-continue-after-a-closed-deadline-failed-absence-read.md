# ADR-0114: Continue after a closed deadline-failed absence read

- **Status:** Proposed
- **Date:** 2026-11-12
- **Deciders:** DaKasa
- **Scope:** Core / automatic read-only settled-retirement continuation
- **Supersedes:** —
- **Superseded by:** —

## Context

An accepted, settled DELETE can outlive its original absence-polling budget.
The final read may be prepared with only milliseconds remaining and close with
an authentic context failure. Its prepared and returned records are complete,
but it has no observation or absence receipt. The failed owning workflow and
dispatch can be fully acknowledged while the expired intent remains draining.

The classic Pending continuation cannot use this failed return. Selecting an
earlier successful Pending would hide the latest failure; treating the failure
as absence, renewing the original invocation or issuing another DELETE would
break custody. The zero-own-read branch also cannot describe an owner that did
prepare this read.

## Decision

Extend the existing read/confirm-only `settled_absence_continuation` mode with
the distinct proof discriminator
`original_settled_absence_closed_failed_read_continuation_v1`.
Its optional `closed_failed_read` object contains exactly `read_id`,
`prepared_sha256` and `returned_sha256`. The old ten-field proof remains exact;
the new proof has eleven fields and leaves its Pending ID and hash empty.

Authenticate the absolute latest returned absence read and the prepared record
with that same ID. Require their complete immutable wires and hashes, matching
embedded request, admission, root, tuple, creator binding and existing DELETE.
The return must have an empty status, `call_failed=true` and
`original_context_failed=true`, with no plan, observation or receipt. Validate
the actual finite deadline and all Core/PG ordering against the exact failed
owner, its whole returned dispatch and real finalization ACK. Refuse an open
challenge, missing or foreign data, changed wire, unknown transport, fabricated
clock or unacknowledged owner. The settled DELETE must still have its complete
accepted transport and auxiliary-inventory receipt.

After natural lease expiry and existing quiet checks, the ordinary scheduler
may request and claim one fresh fenced owner. That invocation must obtain fresh
inventory, the existing survivor floor/canaries and a new bounded absence read
before confirming the same DELETE. The closed failed read grants no absence,
poweroff, mutation issue, redemption or replacement DELETE authority.

A subsequent read-only owner that fails before preparing any own read may use
the same explicit failed anchor only after its own genuine failure, ACK and
expiry. Authenticate one unique direct-origin typed request and revalidate it
once for the new requester. Do not recursively traverse the history or choose
an older successful read. Classic Pending and pre-read schemas keep their
existing rules.

```mermaid
flowchart LR
    A[Accepted settled DELETE] --> B[Latest read closes with context failure]
    B --> C[Failed owner ACK and natural expiry]
    C --> D[Authenticate exact failed pair and immutable custody]
    D --> E[New fenced read-only owner]
    E --> F[Fresh inventory, floor and absence]
    F --> G[Confirm the same DELETE]
```

## Consequences

Migration102 adds only the necessary validation helpers and extends the closed
continuation proof constraint and validator. Historical migrations, all retained
records and the migration101 quiet predicate remain unchanged. Downgrade
refuses while new proof custody exists; otherwise it restores the prior
constraint and validator exactly.

Go and PostgreSQL must agree on the positive case and strict JSON, identity,
hash, clock, ACK, latest-read and provider-settlement negatives. The existing
PostgreSQL owning root exercises a live OFF-qualified origin, real expiry and
read-only repetition without adding a new workflow, job, test ID or timer.
CI fixtures confer no production or clean-cycle credit.

## Related

- [ADR-0105](0105-continue-settled-retirement-absence-under-a-new-owner.md): classic settled-absence custody.
- [ADR-0108](0108-resume-a-failed-settled-continuation-before-its-first-read.md): bounded zero-own-read repetition.
- [ADR-0110](0110-recover-a-closed-failed-finish-after-normal-guest-poweroff.md): separate pre-DELETE normal-finish recovery.
