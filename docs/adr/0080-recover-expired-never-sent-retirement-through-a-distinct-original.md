# ADR-0080: Recover expired never-sent retirement through a distinct original

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Capacity platform maintainers
- **Scope:** Core / failed installed Guest retirement
- **Supersedes:** —
- **Superseded by:** —

## Context

A retirement intent may be durably issued while the original caller reservation
fails before any possible-send. Its original deadline subsequently expires.
An in-process Go deadline can carry monotonic or location state that JSON does
not retain. Comparing the original and durable signed DTOs then rejects the
caller despite equal UTC instants and equal canonical hashes. The reservation
comparison remains necessary to prevent a different operation from borrowing
the persisted authority.

## Decision

Canonicalize the selected V1 retirement deadline to UTC before constructing,
signing and persisting the intent. Preserve the complete request equality,
signature, original deadline and one-use caller checks.

An authenticated operator with GodMode and workflow management permission may
identify an original preregistration and its expired retirement request through
the dedicated retirement-recovery endpoint. Core derives every eligibility
fact. Restrict recovery to the existing explicit failed-installed legacy V1
disposal, its immutable claimed snapshot, a returned failed retirement run with
its final acknowledgment, an expired lease, the original complete contract and
zero accepted useful capacity. Acquire the existing mutation-scope lock and
the original intent lock. Any original possible-send, caller return, runtime
snapshot, authority read, retirement return, deletion binding or native
poweroff read refuses recovery.

Schema79 adds an append-only requested, claimed and issued recovery chain. The
scheduled workflow claims a fresh fence, lease owner and run while retaining
the original generation and immutable schema78 admission and claim. It issues
a separate signed retirement with fresh request, attempt, nonce and context,
bounded by that invocation's original deadline. Schema63 retains both actual
intent rows and every child keeps its own actual request foreign key. Its
insert guard permits at most one explicitly admitted successor and repeats
the original expired/never-sent proof before insertion. The expired parent's
deadline, wire, signature, issuance audit, failed run and acknowledgment stay
unchanged. A possible-send on the successor cannot authorize another recovery.

Quiescence may continue the existing disposal only by authenticating the exact
schema79 claim and issued successor. The actual Guest must complete its
original signed V1 retirement; a separate native observation must establish
poweroff. Exact-resource cleanup and Core's later complete native and auxiliary
absence observation remain independently required before terminal accounting.

## Consequences

Administrative admission grants neither Guest execution nor native mutation.
Recovery does not create useful capacity, erase business effects or qualify a
deployment. Normal V2 retirement and all other protected floors retain their
existing contracts. Historical actual Core issuers are authenticated through
their original exact compatibility maps; recovery records the actual new
issuer without changing the original enrollment authority.

## Related

- ADR-0064 (separate original retirement clock owners)
- ADR-0078 (stable protocol authority and actual issuer provenance)
- ADR-0079 (failed installed Guest disposal)
