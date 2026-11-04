# ADR-0057: Require original local installation before reserving qualification

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Pending review
- **Scope:** Core/Guest original provisioning contract
- **Supersedes:** —
- **Superseded by:** —

## Context

An authenticated provisioning registration is recorded before its signed enrollment
can be returned and installed by the original Guest. Treating that receipt as a
local readiness barrier permits the unique serving probe to arrive before install.
The actor correctly refuses the missing enrollment, but the one-shot probe cannot
be replayed safely.

## Decision

Require `guest_original_installation_v1` before the workflow advances from original
provisioning toward qualification. The existing original provisioner signs an exact
confirmation after installation readback and original writer admission, binding the
immutable registration receipt and enrollment digests plus ordered completion times.
Use its existing mTLS/service-principal scope and producer key. Core authenticates
against the same immutable preregistration, member, current policy, lease, fence and
original deadline; it stores one immutable confirmation and permits only an exact
repeat while those original conditions remain valid. Pending means no probe reserved.

The confirmation is an ordering barrier only. It does not replace native identity,
serving probe, retirement, billing or useful-capacity gates. The existing original
context bounds state reads; no fixed sleep, new deadline or probe retry is introduced.

## Consequences

This is a coordinated protocol and schema change, not backward-compatible fallback.
New Core with old Guest remains pending then fails closed at the original deadline;
New Guest with old Core refuses its unsupported callback, but old Core has no barrier
and can already reserve a probe. Therefore a mixed pair is not globally fail-closed:
exact coordinated source pins and preflight must prohibit it before launch.
Both exact source pins and migration 00069 must be deployed together after approval.
No new credentials, network scope or principal is required. A producer signature
attests its source-owned original completion; Core does not independently read the
Guest filesystem. Historical confirmations cannot satisfy a new preregistration.
The old registration and enrollment wire schemas remain unchanged.
