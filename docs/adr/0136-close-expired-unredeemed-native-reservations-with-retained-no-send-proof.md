# ADR-0136: Close expired unredeemed Native reservations with retained no-send proof

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giomaster
- **Scope:** Core / Native reservation failure handling before a provider send
- **Supersedes:** None
- **Superseded by:** None

## Context

A private bootstrap can fail before the actor redeems its original create
command. Its reserved overlay address and finite charge must not remain held
forever. A timeout or expired progress lease alone cannot distinguish that
case from a create whose original response was lost.

## Decision

Add `CapacityNativeWorkerCommandStore.CloseUnredeemed` as a protected process
operation, with no new HTTP route or workflow capability. After the immutable
original command deadline, serialize with Redeem through the same mutation
scope and Attempt row. Only revision-one `reserved` authority without physical
birth, Node identity or original return can close.

Retain the exact original command context, original revision and database time
in an immutable private closure row. Commit that proof, the `absent` state and
the normal Attempt event in one transaction. The SQL guard independently checks
the same unsent facts. Concurrent closers share the original proof; they cannot
renew a command, replenish its generation's original creation budget or create
another child under that budget.

A committed `send_started`, an unknown transport or any retained original
response always refuses this operation. A proven unsent closure cannot later
acquire original provider custody or be reopened. The existing physical-birth
and pre-admission-abort paths remain responsible for every possible real send.

## Consequences

Closing this case releases a reservation for which no provider mutation was
ever authorized. It asserts neither an HTTP404 nor deletion of a real machine.
The original Attempt, command and event history remain available, and rollback
cannot discard a closure. A failed or unknown commit requires a read of the
original row; it never grants a create or cleanup send.

The Native store and process execution gates remain required. This delivery
does not install a live controller or change a provider, Node, network peer,
registry or retained data. CI uses PostgreSQL's actual clock and immutable
deadlines, with no rewritten history or local test execution.

## Related

- [ADR-0131](0131-record-native-worker-attempts-under-fenced-parent-reservations.md)
- [ADR-0132](0132-bind-private-native-creator-commands-to-original-reservations.md)
- [ADR-0134](0134-fence-preadmission-worker-cleanup-separately-from-admission.md)
