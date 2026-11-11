# ADR-0110: Recover a closed failed finish after normal Guest poweroff

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** DaKasa
- **Scope:** Core / automatic ordinary Guest retirement finish recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

A normal, authenticated V2 Guest retirement can complete its four-record journal
and return its full successful body before its original deadline, while the
following native OFF read fails. The owning workflow then closes as failed with
a final dispatch acknowledgement and leaves an expired draining intent without
a forward marker. Ordinary assessment preserves that claimed intent. The
partial-poweroff forward lane intentionally excludes successful original
callers, and its historical admission additionally requires a replacement Core
process. Relabelling this original success as a failed caller would break those
contracts.

## Decision

Add a separate `normal_finish_recovery` forward mode. The real plan automatically
selects it only after natural expiry of the capacity lease and original context,
an exact uniquely owning failed workflow/dispatch ACK, complete authenticated
normal Guest success, a closed failed original native OFF read and no owning
DELETE. The existing seven-field operator CAS may select the same state; the
caller supplies no proof, clock or replacement observation.

Persist a closed typed proof referencing the exact successful caller/journal,
failed run and failed OFF challenge/return. Preserve all original bytes,
deadlines, failures, lease history and provider receipts. The proof closes a
read-only failed finish; it does not prove native OFF. Unlike historical partial
admission, its fully closed original caller and workflow permit a same-process
new fenced owner. Keep the old live/historical/settled-absence and pre-read
continuation rules unchanged.

The new owner must perform a fresh five-second OFF read and a fresh surviving
floor proof before the first ordinary DELETE. Guest commands and an already
issued DELETE are never replayed. Failed read-only attempts without a DELETE
may obtain another finite owner only after their actual failed ACK and natural
expiry. After an accepted DELETE, the existing settled-absence continuation
retains the new origin proof and remains read/confirm only.

Add Goose migration 97 with independent PostgreSQL proof/mode guards. Down
restores the prior trigger and mode constraint only if no new provenance has
been retained; otherwise it fails closed.

## Consequences

This closes a missing automatic transition without changing production timers,
read caps, mutation bindings, protected floor, recovery budget or Guest protocol.
A successful Guest poweroff return remains distinct from native OFF and physical
absence. PostgreSQL guards supplement, and never replace, Go validation of
canonical retained bytes, signatures and complete original transport joins.
The new mode cannot be used for a partial caller or an unresolved provider write.

## Related

- ADR-0101 (retains the separate partial-poweroff forward lane)
- ADR-0105 (retains settled-absence continuation)
- ADR-0108 (retains zero-own-read continuation)
- ADR-0109 (retains independent read-only inventory provenance)

