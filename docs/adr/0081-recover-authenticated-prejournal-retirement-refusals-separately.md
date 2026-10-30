# ADR-0081: Recover authenticated prejournal retirement refusals separately

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Capacity platform maintainers
- **Scope:** Core / failed installed legacy Guest retirement
- **Supersedes:** —
- **Superseded by:** —

## Context

The legacy retirement actor requests its first live authority before reserving
its retirement journal or starting retirement work. That authority read can
receive an authenticated runtime snapshot while Core refuses to persist the
snapshot. A Go context deadline can retain monotonic or location state that the
stored JSON challenge cannot retain, causing the complete equality check to
refuse the response. The original retirement caller then receives a definite
refusal although its possible-send and the nested authenticated read are real.
This request cannot satisfy the never-sent recovery contract of ADR-0080.

## Decision

Canonicalize the bounded authority deadline to UTC before creating, signing and
persisting a new challenge. Preserve the complete challenge comparison,
signature verification and original deadline. Never rewrite an existing wire,
deadline, signature or return.

Use a separate, append-only schema80 admission for the narrow, authenticated
first-live refusal. The authenticated GodMode operator supplies only the
preregistration and refused retirement request identifiers. Core rederives the
immutable failed-installed claim, exact supported legacy Guest contract, failed
retirement run and final acknowledgment, expired lease, current complete
contract and zero accepted useful capacity.

Require the exact complete original caller refusal and its closed transport,
one first-phase authority read, and the complete original authenticated snapshot
transport returned within that read's original deadline. Revalidate the signed
snapshot rather than trusting a status code or stored summary. Require no
snapshot return, authority return, retirement observation, deletion binding or
native poweroff read. The supported actor's ordering establishes that this first
authority refusal precedes journal reservation, withdrawal, drain and poweroff.
A generic HTTP refusal, missing response, unknown possible-send, later authority
read or incomplete authentication cannot establish this boundary.

Serialize admission and issuance with the existing mutation-scope and intent
locks. Preserve the original schema63/78 records and all caller, authority and
business-effect records. Record requested, claimed and issued stages separately
from schema79. Claim a fresh scheduled run, lease owner and fence; issue one
distinct signed retirement request with its own attempt, nonce, context and
bounded deadline. Permit at most one explicit successor across both recovery
families. Recheck the original evidence and exact claim at issuance and when
continuing the disposal.

## Consequences

Admission proves a specific refusal boundary and grants no quiescence or useful
capacity credit. Earlier application effects remain real. The actual new Guest
retirement, separate native poweroff observation, exact-resource cleanup and
Core's complete native and auxiliary absence observation are still required.
The original failed request is never replayed or renewed. The never-sent
contract, normal V2 retirement and other protected floors remain unchanged.

## Related

- ADR-0064 (separate original retirement clock owners)
- ADR-0078 (stable protocol authority and actual issuer provenance)
- ADR-0079 (failed installed Guest disposal)
- ADR-0080 (distinct recovery for expired never-sent retirement)
