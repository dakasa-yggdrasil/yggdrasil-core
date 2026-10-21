# ADR-0063: Own fresh Notify canaries in original Guest sessions

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** DaKasa architecture maintainers; implementation within the authorized elastic migration
- **Scope:** Core / original production Guest capacity
- **Supersedes:** —
- **Superseded by:** —

## Context

Provider creation and original application enrollment do not demonstrate useful
business capacity. A historical Notify record eventually expires. Repeating its
read or keeping application roots open cannot make that creation fresh again.
The original Core caller, Guest kernel and PostgreSQL lease/commit clocks belong
to different owners and cannot safely compare wall-clock instants.

## Decision

Use a source-owned, one-use publish-then-read operation in the same enrolled
Notify process. Core signs a closed challenge for one member, enrollment,
generation, fence and lease. A separately signed Guest nonce authenticates the
same actor, runtime and writer and a local kernel monotonic expiry. The Core
five-second context starts before nonce acquisition and remains the parent of
publication and read; neither return nor persistence renews it. Read and publish
have different signed purposes, schemas and HTTP methods. A read names the
original publication challenge but receives its own one-use nonce.

Notify uses its original Commons critical publisher and transaction, a fixed
two-recipient template and its actual consumer. The original consumer persists
inbox, notification, both recipient states and a native process witness in one
transaction. The dedicated canary consumer suppresses realtime publication and
external delivery. The publisher receipt preserves PostgreSQL JSONB wire bytes;
Core independently checks the template and joins that actual wire hash to the
consumer witness. Source marshal bytes cannot substitute for the actual relay
wire. The native SQL reader closes its rows and reports physical database,
table and transaction identities. Guest read V2 accepts the physical server's
actual `track_commit_timestamp` on/off setting. Each of the five original rows
returns the real commit timestamp when enabled and explicit NULL when disabled;
no reboot or fabricated commit timestamp is needed. Legacy EKS reads keep their
existing contract. Freshness follows the actual newly signed publication,
original critical publish/commit, reliable consumption, same-transaction witness
visibility and completed original read inside the SAME original Core five-second
window. The read must use the same immutable executor and deadline bounded by
the parent publication; it cannot grant an old publication another window.
Subsequent age is conservatively the whole five-second creation upper bound
plus actual elapsed time on the Core PostgreSQL ledger clock. Native commit
and observed wall timestamps remain diagnostics, not cross-clock authority.

Carry exact bounded original process-control frames over the persistent private
Notify pipe. Do not invent an EOF or Close for that persistent pipe. Core retains
the enclosing original HTTP read, EOF and Close facts separately. Guest process
and census timestamps are compared only within that Guest. Core deadlines and
HTTP returns are compared only within the original Core caller. Convert a fresh
PostgreSQL lease sample to a remaining duration and conservatively subtract its
whole native round trip before constraining that Core budget.

Declare stable queues through the existing owning Notify broker definitions.
Pin namespace, mutation binding, provider, slot, canonical queue name and actual
definitions hash in the protected source profile. Bind the canary database,
recipient set, source query and publication limits into the compiled production
profile contract. Queues do not derive from enrollment and do not grant broker
configuration privileges to Notify. An authentic enrollment in the fixed
template and the same original process remain mandatory. A declared topology
hash alone does not assert that the broker applied it.

Refresh after promotion through a separate protected workflow operation. It
derives its owner from the actual workflow invocation and rereads a stable
capacity epoch under the dimension lock for every ledger mutation. The epoch
must have no VM lease, recovery authority or unresolved provider grant. It
cannot accept a caller-selected generation, fence or owner, and cannot publish
after a concurrent epoch change. This authority only refreshes the fixed
synthetic business canary; it never renews a VM lease or provider quote, advances
a phase, authorizes retirement or reserves a provider mutation. Retain the same
one-use nonce, original five-second context, immutable ledgers and source rate
limits. A periodic owning workflow may invoke it for continued fresh evidence.

Migration 70 creates empty immutable challenge, Guest nonce, possible-send and
original-return ledgers. Commit possible-send before the sole original call.
Duplicate or uncertain calls do not receive another publication permission.
Accepted canonical bodies are retained separately from diagnostic transport
metadata; unknown response bodies do not become evidence. Rollback keeps these
identities permanent. Publication rate and useful evidence age are bounded by
the fixed source binding. Phase changes and retirement with this explicit binding independently require
fresh original useful creations from surviving physical members, their original
installed enrollment and source profile. The target and pending destroys never
count toward the useful floor. Delete additionally requires a new after-retirement
creation issued on Core PG after the original caller acknowledgement was durably
retained. The independent native slot floor remains mandatory. These source
checks do not add a compiled production registry entry. Production retirement
still needs its separate monotonic original owner contract.

## Consequences

Portable contract tests verify signatures, closed JSON, native wire joins,
cross-clock separation and late original Close rejection. They do not claim
native PostgreSQL effects, broker reconciliation or production qualification.
Owning Linux integration must exercise actual publish, relay, consume, original
transaction and read, including expiry, uncertainty and replay. Compiled
production profile approval and real physical evidence remain separate gates.

## Related

- [ADR-0058](0058-anchor-qualification-freshness-in-original-monotonic-owners.md)
- [ADR-0059](0059-pin-production-guest-admission-to-compiled-contracts.md)
- [ADR-0060](0060-own-original-guest-provider-per-workflow-invocation.md)
