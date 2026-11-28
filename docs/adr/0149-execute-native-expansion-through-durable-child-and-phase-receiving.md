# ADR-0149: Execute Native expansion through durable child and phase receiving

- **Status:** Proposed; activation gated
- **Date:** 2026-11-28
- **Deciders:** Giomaster
- **Scope:** Core Native same-profile worker expansion
- **Supersedes:** —
- **Superseded by:** —

## Context

The Native bound workflow could assess demand but refused execution. Existing
stores separately provided a market Claim, child reservation, one-send provider
callbacks, network installation, registry phases and sealed physical reads.
None of those phase receipts by itself advanced the child to registered or
admitted. Reusing generic HPA Advance would require unrelated health/inflight
assertions and cannot close this Native lifecycle honestly.

An RPC can also be uncertain before its SDK redeems. A child still marked
reserved is not proof that no SDK invocation is in flight. The immutable114
command cannot be overwritten to disguise that uncertainty, and the existing
Attempt state machine deliberately has no reserved-to-reserved mutation.

## Decision

Execute only same-profile expansion through the existing protected owner and
stores. Borrow the current owner synchronously for the whole operation, matching
the exact DB and persisted policy. The owner carries no controller authority.
Restore that identity only from the original private command114, checked against
the current parent generation/fence and original active Source workflow. A fresh
Claim may create its first command only with its still-owning invocation. A
different invocation cannot adopt a Claim that crashed before its first command.

Look up existing children and reserve a new one under the same market,
dimension, parent and child locks. A pending, unknown or aborting child holds the
slot. An absent child still consumes its original generation budget. New children
require a current complete useful pool that preserves every original baseline
Node/provider identity and contains only the generation's exact admitted
additions. Counts and worker profile never come from workflow input.

Use migration120 as an append-only dispatch barrier keyed by the exact target
UUID and one of provider_create, registry_phase or network_install. Commit its
original Attempt/policy/generation/fence/Source snapshot before the SDK RPC. A
lost commit outcome or existing barrier permits only receiving/HOLD. Its presence
proves neither RPC delivery nor remote success. A crash before RPC can remain
reserved and uncertain until the existing original unsent/cleanup proofs apply.
The original command, SDK redeem and native CAS authorities remain mandatory.

Feed real phase receiving into Record through an executor-only runtime wrapper.
The normal provider callback runtime stays ACK-only. Registration requires the
actual complete original Lease ACK and a fresh selected read of the same
Node/registry/birth. Admission additionally requires observed admission and
quarantine-release phases, the original native ACKs, current Ready/heartbeat and
independent network/warmup/physical qualification. A GET-applied permit alone
does not qualify a child. Late original custody remains historical truth after
permit expiry; it never reopens issuance or redemption. Current reads retain
their own Source, scope, time and actual request identity separately from the
immutable HCloud birth witness; no request ID is manufactured.

Promote the parent only through a dedicated Native closure under its existing
transaction and locks, with real complete useful-pool/birth joins, exact target,
original finite child budget and current parent authority. Do not call HPA
Advance or invent Healthy/Inflight values. Expired parents only receive original
ACK truth and remain held for separate recovery; they are not re-Claimed.

## Consequences

All write paths remain default-off behind protected installation, policy/process
execution gates and real exact Source-bound clients. Admission and quarantine
release additionally retain the admission process gate. The admission-only
operation never Claims or Reserves capacity. Unknown outcomes fail the workflow
step with safe receiving metadata rather than declaring success or retrying a
mutation. Nil independent readiness remains HOLD.

This slice does not implement cross-profile handoff, shrink, admitted worker
retirement or automatic pre-admission cleanup. It never uses never-admitted
Abort to retire an admitted Node. No public API, caller-selected prices,
adapter/count, new cloud credentials or production activation is added. CI alone
executes the concurrency, restart, custody, substitution and PostgreSQL16/17
cases. Source publication does not qualify provider throughput or live capacity.

## Related

- ADR-0131 / ADR-0132: child ledger and private original command authority
- ADR-0140 / ADR-0145: sealed floor network permissions and concrete runtime
- ADR-0146: protected guest witness identity and independent readiness boundary
- ADR-0147: separately authorized abort closure
