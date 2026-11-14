# ADR-0116: Dispose a superseded equivalent-policy readonly maintenance failure

- **Status:** Proposed
- **Date:** 2026-11-14
- **Deciders:** Giomaster
- **Scope:** Core / capacity policy publication and immutable readonly dispatch disposition
- **Supersedes:** —
- **Superseded by:** —

## Context

A capacity policy can be published while its previous version owns a running
dispatch. An original readonly refresh may publish a genuine business canary,
issue its corresponding read, then fail before recording that read's return.
When the previous catalog pin becomes inactive before finalization, the original
failed workflow return is retained as `unknown` without a finalization ACK.
Normal dispatch admission correctly keeps that scope occupied. The older
maintenance dispositions require their original policy to remain active and
recognize different original failure and canary shapes.

## Decision

Serialize capacity policy publication and deletion with dispatch admission using
the same scope lock. Refuse a publication that would supersede an unfinalized
dispatch in either its old or new scope. Do not pause other scopes or change any
dispatch clock, lease or original catalog pin.

Provide a distinct operator disposition for the closed superseded-policy case.
Require the exact inactive original policy and a newer, uniquely active policy
of the same logical name and scope whose **whole Spec and checksum** equal the
original. A caller supplies only closed CAS expectations. The server derives the
original failed workflow, original no-ACK dispatch, complete current membership,
other active catalog pins, stable epoch and effect scan under scope and row locks.

Accept only one authentic publication/read pair for the same member and epoch:
two immutable challenges, two nonces, two possible sends, one accepted publication
return and no read return. The missing read is expired. Preserve its absence and
the actual generic workflow-returned error; neither is a successful read or ACK.
Require exactly the proved assessment and slot observation updates, no provider
authority, commands, outstanding grants or other mutation effects. Authenticate
historical birth enrollment and installation through unchanged Guest policy
lineage; birth generation need not equal the present maintenance generation.

The disposing Core process must have started after the original lease expired,
and at least 900 seconds must have elapsed since that expiry. Preserve all older
maintenance admission contracts and refusal cases. Write a separate immutable
receipt and move only dispatch state and its receipt timestamp to
`superseded_http_maintenance_disposed`. Do not rewrite the original workflow,
return, error, ACK, canary or provider evidence, and do not replay any operation.

Archive the complete PostgreSQL dispatch/run/policy/intent/member/pair preimages,
labeling their normalized row bytes separately from signed original canary wire
bytes. Historical receipt reads authenticate those retained preimages and pure
stored scan. They do not depend on a later active policy or later membership.
The next ordinary tick needs its own current admission and fresh usefulness proof.

## Consequences

The operator closes one specific unresolved scheduler blocker without asserting
provider quiescence, current business utility, exclusion of other Core replicas
or cycle completion. A different result, extra canary, missing publication,
foreign member, changed catalog, unresolved authority or immature executor barrier
continues to hold. The historical original policy remains inactive permanently.

CI distinguishes a current genuine Source producer/finalization witness from
separately declared historical storage operands that exercise the full age gate,
operator, refusal and concurrency contracts. The latter do not claim a live
900-second itinerary. Production acceptance still requires the actual mature
originals, current guards and actual fresh Core process.

## Related

- ADR-0094 (historical Guest policy lineage)
- ADR-0096 (preserved unknown maintenance returns)
- ADR-0103 (distinct recorded HTTP maintenance disposition)
