# ADR-0082: Reconcile a partial Guest retirement with a separate native OFF proof

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Core maintainers
- **Scope:** Core capacity retirement and administrative recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

A legacy Guest can durably report its original attempt, writer quiescence and
possible poweroff start, then close its caller with a refusal during shutdown.
Three authenticated records and a provider reporting OFF do not establish the
normal fourth `poweroff_command_returned` record or a successful Guest response.
The original command may already have taken effect. Reissuing it would create an
unnecessary and potentially ambiguous mutation. Neither a never-sent recovery nor
a refusal before the Guest journal applies after authenticated journal effects.

## Decision

Use a separate, explicitly admitted, append-only reconciliation. An authenticated
GodMode collaborator with `manageWorkflows` supplies only the original
preregistration and existing retirement request IDs. Core derives the current
failed disposal, the already issued recovery lineage, the acknowledged failed
workflow and the zero-useful-capacity state. No scheduler automatically admits it.

Before admission and before qualification, authenticate the exact three-record
prefix, full writer/runtime/census quiescence, four authorized original authority
returns, two signed runtime snapshots, five closed nested transports and the exact
closed legacy refusal. Revalidate historical signed DTOs at their retained
original transport instants. Preserve all original deadlines, signatures, results
and business effects. Lock the scope and original retirement row while comparing
this snapshot. The protocol authority remains independent of the current build;
retain the complete four-profile compatibility snapshot used by these issues.

An admission permits at most three separately selected, five-second, owning
provider GET attempts. Each attempt is durable before its read and has a new read
ID and deadline. The caller must supply the previous read ID from the ledger;
an unknown POST response is reconciled by GET, never resent blindly. An expired
or returned failed read can permit the next explicit read. It cannot renew the
Guest operation or create a new retirement request, fence, nonce or lease.

Retain every original read result even when it supplies no authority. Only the
latest complete, timely provider observation of the exact enrolled VM physically
OFF, joined to the original create receipt and full native plan, can atomically
append the reconciliation qualification and existing disposal quiescence. Use an
explicit reconciliation branch for subsequent terminal validation. Never label
these records as the normal four-record Guest proof or a caller HTTP success.

Cleanup remains a separate operation after qualification. It must establish the
exact native target and its auxiliary resources, perform only the authorized
cleanup, and supply fresh absence observations before Core completes the disposal.
A reconciliation does not itself delete a VM or authorize useful capacity.

## Consequences

- Migration 81 adds separate immutable admission/qualification and read-attempt
  ledgers. Existing retirement, disposal and recovery records remain unchanged.
- Normal four-record/caller-success retirement and recovery families 79 and 80
  retain their original validators and meanings.
- Reconciliation can fail closed on a changed snapshot or exhausted read budget.
  Further action requires a new reviewed contract, not an unbounded retry loop.
- Source CI reports this lane's six roots and physical PostgreSQL shutdown in a
  distinct artifact. Historical 49-, 16- and additional 10-root censuses remain
  separate evidence.

## Related

- ADR-0078 (immutable protocol authority and actual issuer provenance)
- ADR-0079 (failed installed Guest disposal and native absence)
- ADR-0080 (never-sent retirement recovery)
- ADR-0081 (authenticated refusal before journal admission)
