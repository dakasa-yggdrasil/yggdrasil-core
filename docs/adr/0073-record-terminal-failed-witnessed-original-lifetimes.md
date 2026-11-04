# ADR-0073: Record terminal failed witnessed original lifetimes

- **Status:** Proposed
- **Date:** 2026-10-23
- **Deciders:** Core maintainers and production operator
- **Scope:** Failed original Guest accounting and administrative dispatch closure
- **Supersedes:** —
- **Superseded by:** —

## Context

An accepted native create can have an authentic immutable create witness while
the same provisioning invocation expires before enrollment or installation.
The native lifetime may subsequently be destroyed by an independently authorized
operator. Neither missing enrollment nor network failure proves that a writer
process never started. The original accepted create, witness and failed run must
remain truthful. An unknown final acknowledgment also cannot become an ordinary
return or an acknowledgment after its original deadline.

The existing unadmitted-create disposition explicitly requires witness absence.
It must retain that meaning and its database constraints.

## Decision

Append a separate terminal failure ledger for an expired, witnessed original
Hetzner lifetime with no enrollment, installation, retirement or serving member.
Require the exact accepted original tuple and retained witness, its failed
original provisioning run and unknown expired dispatch, and fresh authenticated
complete absence of the native resource and all originally owned auxiliaries.
The administrative caller supplies only the grant and job identities; Core
obtains the native observation through the existing source-pinned read observer.
The endpoint performs no provider mutation, Guest operation or workflow replay.

Keep grant state, grant JSON, accepted settlement, witness, failed workflow result
and error, original ownership and deadlines unchanged. Keep the original dispatch
acknowledgment null. Atomically append the ledger, attach matching one-way foreign
keys, transition the dispatch to the distinct `failed_disposed` state, close the
failed intent and advance its fence. Database guards validate both links and the
failed intent at commit; a ledger alone cannot release a native reservation.

Preserve the old disposition as a separate protocol. New assessments must exceed
the closed generation and fence of either terminal protocol. Do not claim that
the historical writer never started, that the failed run succeeded, or that the
terminal accounting provides useful capacity, health or savings authority.

## Consequences

- A lost administrative response is reconciled by reading its immutable ledger.
- Native presence, incomplete auxiliary absence, changed originals, active work,
  enrollment/installation races and stale observations remain held.
- Unknown ordinary acknowledgments stay unknown; administrative terminalization
  is explicit and cannot restart an old invocation.
- Native deletion remains independently authorized and outside this endpoint.

## Related

- ADR-0069: Separate expired unadmitted create dispositions
- ADR-0071: Reject superseded dispatches before start
- ADR-0057: Require original local installation before qualification
