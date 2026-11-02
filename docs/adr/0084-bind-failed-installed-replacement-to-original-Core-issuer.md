# ADR-0084: Bind an explicit failed-installed replacement to its original Core issuer

- **Status:** Proposed
- **Date:** 2026-10-26
- **Deciders:** platform maintainers
- **Scope:** Core / original Guest failed-installed retirement
- **Supersedes:** None
- **Superseded by:** None

## Context

A failed original useful-business canary can involve an owning Core defect while
the installed Guest and its complete approved profile remain unchanged. Changing
the policy before retiring the original also invalidates its checksum fencing.
The old disposal Core identity describes the administrative request, not the
Core implementation that issued the failed original canary.

## Decision

Offer one explicit administrative mode, `original_canary_core_bound_v1`, for a
Hetzner original with a recorded failed fresh canary. Derive the original issuer
from that acknowledged original run's immutable accepted publication, held read,
signed challenges and atomic actual-issuer records. Record separately the exact
current replacement Core build at admission; require it to differ from the old
issuer. The caller supplies neither identity.

Retain all existing V2 writer drain, quiescence, provider-native VM and separate
AUX absence, zero-use, dispatch ACK, lease, fence, FIFO and immutable-history
requirements. A fresh same-Guest/profile epoch requires the exact recorded new
Core and independent current complete profile approval after the terminal chain.
No old attempt is replayed or retimed. A new original canary remains mandatory;
the mode makes no claim that the old failure's cause was identified or fixed.

Keep the old both-Guest-and-profile-changed route. Rows without the optional
marker fields retain that strict route and are never retrofilled. Add the three
optional keys and their all-or-none checks to migration82 without editing any
historical migration or weakening the stage-chain/immutability triggers.

## Consequences

The same-profile branch is bounded to one explicitly admitted replacement Core.
An unrelated later Core cannot use it. Legacy Guest548 retirement cannot select
this mode. Historical failed publications and possible business effects remain
visible; storage-only tests confer no native retirement or useful capacity.

## Related

- ADR-0078 (versioned protocol authority and immutable actual issuer provenance)
