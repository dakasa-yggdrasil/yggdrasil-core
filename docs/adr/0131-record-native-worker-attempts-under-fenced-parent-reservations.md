# ADR-0131: Record Native worker attempts under fenced parent reservations

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giovanni Martins
- **Scope:** Core / Native disposable worker lifecycle
- **Supersedes:** —
- **Superseded by:** —

## Context

The market planner can reserve useful capacity, but provider creation is a
different lifetime. A possible start cannot become free when a lease expires or
the parent pool finds healthy fallback capacity. The historical Guest protocol
has fixed slot and authority contracts that cannot be repurposed for a dynamic
Native pool. A pricing collector must not acquire creation credentials.

## Decision

Add a separate opt-in Native lifecycle binding and server-owned UUID child
ledger beneath the existing intent/reservation. Pin execution Source/catalog,
scope, bootstrap template and exact IPAM authority independently from pricing.
Keep global-before-logical serialization and the original parent send budget.
Commit a single send-started transition before returning a private permit.

Archive the original private response before independent SDK qualification,
including after lease expiry, without granting another send or admission.
Publish only a safe typed birth digest joined to the original Launch, current
physical lifetime and the exact execution adapter. Register/admit only through
separately received Node/registry/network/warmup evidence; never infer usefulness
from provider acceptance.

Issue separate short-lived registry/quarantine phase permissions from protected
independent reads. Pin a dedicated writer principal and integration instance.
Revalidate the locked current attempt and qualification on single redemption;
archive original PATCH returns before ACK decoding. GET-only reconciliation
preserves late truth without granting resend. Unknown or observed sends block
successors; only a complete typed atomic rejection, or proven never-redeemed
expired issuance, permits a new permission. Keep exact raw annotation and Node
CAS preconditions. This does not claim cross-resource atomicity between a Lease
and Node: fence outstanding release permissions before any owner/epoch handoff.

```mermaid
flowchart LR
  Claim[Fenced parent Claim] --> Child[UUID and owned IP]
  Child --> Send[One committed send permit]
  Send --> Archive[Private original custody]
  Archive --> SDK[Independent SDK and Launch join]
  SDK --> Birth[Safe typed birth]
  Birth --> Future[Separately qualified registry and admission]
  Archive --> Unknown[Finite retained uncertain charge]
```

## Consequences

Legacy schemas, histories and fixed-slot semantics are unchanged. Unknown
children retain known unit charges instead of poisoning a whole account as an
unbounded unknown. A bounded Source profile and current protected pool authority
are mandatory; fresh Lease observation alone is not cross-resource atomic epoch
handoff. Raw response bytes/digests remain private and cannot enter public
workflow metadata or birth hashes.

This Source is a ledger/permission/observation delivery. It does not claim live
provider execution, useful capacity, parent completion, cross-provider routing,
automatic replacement or persistent-floor migration. CI supplies executable
schema/concurrency evidence; no local or cloud/load test is included.

## Related

- ADR-0128: fresh market observations and shared reservations.
- ADR-0129: independent Native worker pool observation.
- ADR-0130: owned-worker retirement without a new price quote.
- [Native worker child lifecycle](../features/native-worker-lifecycle.md).
