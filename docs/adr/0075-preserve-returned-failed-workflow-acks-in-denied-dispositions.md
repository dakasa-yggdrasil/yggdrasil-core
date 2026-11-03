# ADR-0075: Preserve returned failed-workflow ACKs in denied dispositions

- **Status:** Proposed
- **Date:** 2026-10-23
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity original-provider accounting
- **Supersedes:** —
- **Superseded by:** —

## Context

An original workflow can return a failed result and receive its original dispatch
acknowledgment while the provider create settlement remains uncertain with no
native identities. An ACK records the workflow return; it does not prove a
successful provider create. The native-denied V1 ledger admits only an unknown
dispatch with no observed ACK. Relabelling an existing ACK as unknown, clearing it,
or replacing the uncertain settlement would destroy original history.

## Decision

Extend the separate native-denied ledger with an explicit V2 representation for
an expired returned dispatch whose complete original workflow and result failed,
with an ACK observed after its return and before its original lease deadline.
Retain V1 and its JSON representation for unknown dispatches with NULL ACKs.

Begin snapshots the complete dispatch and failed run. Complete repeats those
snapshots under the same original scope and native-slot locks, obtains the same
source-pinned read-only native-denial evidence, and compares the original state
and ACK in its terminal CAS. V2 records the exact observed ACK timestamp and says
that the failed workflow's ACK was preserved. It does not claim an unknown ACK or
a successful create. The administrative POST still accepts only grant and job
UUIDs; its Begin, fresh observation and Complete remain internal.

Migration75 extends the predecessor constraints and trigger guards without
editing migrations61 or74. Anonymous predecessor CHECKs are located by relation
and exact parsed expression, each required to occur once. The terminal ledger,
grant pointer, dispatch pointer and failed-intent fence must close atomically.
Original ACK, run, preregistration, uncertain settlement and NULL native
identities remain immutable. Both versions require a new generation and fence
before any new assessment can authorize a new grant, including after a supplier
IID or scope upgrade. Admitted V2 history prevents downgrade to V1.

Permit the independently reviewed AWS1.65.5 supplier for normal creation and
retirement only with its exact published source, full existing lifecycle catalog
and inventory operation. This adds no alias to the historical1.65.4 disposition
resolver. A new current IID, physical profile and compiled policy remain separate
required registry inputs.

## Consequences

No provider mutation, historical HTTP response reconstruction, auxiliary absence,
Guest admission, business readiness or serving authority follows from this
ledger. Missing or changed original ACKs, successful or foreign workflow results,
incomplete native evidence, concurrent work or stale snapshots remain held.
Existing unknown-ACK ledgers and their immutable history retain their meaning.

## Related

- [ADR-0074](0074-record-native-authorization-denied-originals-separately.md)
- [ADR-0073](0073-record-terminal-failed-witnessed-original-lifetimes.md)
