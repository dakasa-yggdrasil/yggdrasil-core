# ADR-0106: Close an accepted unwitnessed expansion with a separate cleanup

- **Status:** Proposed
- **Date:** 2026-11-05
- **Deciders:** Giomaster
- **Scope:** Core / failed unwitnessed AWS expansion cleanup
- **Supersedes:** —
- **Superseded by:** —

## Context

A successful original RunInstances return can be followed by an unavailable
first observation. The failed owning workflow can be acknowledged and expire
naturally without any create witness, enrollment or installed Guest. The
accepted CREATE is still real provider custody. Neither a never-started
accounting disposition nor an enrolled Guest retirement describes that state.
The existing AWS ordinary retirement contract can verify the owned running
instance and attached resources and send a normal, one-shot TerminateInstances.
Its grant wire rejects compensation ancestry, so a new Core ledger must own
that relationship without altering the adapter's immutable contract.

## Decision

Admit this state through the separate administrative
`failed-unwitnessed-expansion-cleanups` endpoint with exactly `grant_id` and
`job_id`. Core derives and seals the accepted original SDK/grant, failed ACK,
expired original context, unchanged current policy/intent, unwitnessed tail and
surviving enrolled roster. Migration94 stores immutable admissions and events.
The original accounting dispositions and all historical migrations are unchanged.

The original CREATE remains SETTLED and occupies the ordinary open-slot index
while cleanup is pending. Only the single FK-linked, privately admitted normal
DESTROY child is exempt from that index. Its wire has empty `compensation_of`;
only the typed94 ledger links it to the original CREATE. A genuine scheduler
run claims a new fencing epoch and finite lease. It does not renew an original
clock, forge a reduction or change the failed desired N2 into a historical N1.
The original deadline and received SDK bytes never change.

Use the existing source-pinned c34 ordinary retirement contract: read the full
owned physical instance and owned attached auxiliaries before sending; persist
possible-send before the one native call; and retain the new accepted DESTROY
settlement's complete sealed auxiliary identities. Original CREATE auxiliary
inventory remains exactly as known, including unknown. No detached/tagged
inventory claim, new adapter permission or alternate native writer is implied.
Fresh same-owner survivor publish/read canaries precede the send. The target
has no Guest authority and receives no Guest command.

Every absence read owns a new complete five-second challenge and authenticated
read-only observer return. Full raw returns are durable before qualification.
Only complete VM and every sealed paid-auxiliary absence, followed by fresh
survivor native observation and actual post-absence canaries, closes cleanup.
An authenticated Pending return can continue read-only under a new genuine
owner only after the former workflow's failed ACK and natural lease expiry.
An issued, uncertain or unknown native effect never gains a second send.

On terminal closure the DESTROY is confirmed and only the admitted CREATE
enters the new `cleanup_closed` state. This is neither CREATE confirmation nor
legacy compensation. Its original SDK/settlement bytes remain unchanged. The
intent records an unleased HOLD at the actual surviving count, explicitly
preserves the failed expansion and grants no Guest, serving, business, savings
or clean-cycle credit. The same failed policy stays latched. A genuinely later
compatible policy version can pass the normal source assessment and ADR0094
continuity path, remove only the active selector and make a new decision;
immutable94 history and consumed send authority remain permanent.

## Consequences

The public summary exposes identities and stage only, never SDK bodies,
credentials, nonce, private read wrappers or caller-supplied proof. Unknown
outcomes require exact read-only reconciliation, without a hidden provider
write. The distinct state and ledger keep physical cleanup separate from
successful Guest creation and from the acceptance of a clean elastic cycle.
Existing lease, RPC and native-write time limits are retained.

## Related

- ADR-0094: unchanged Guest contract continuity across policy versions.
- ADR-0095: the separately typed installed-tail disposal remains unchanged.
- ADR-0104: independent authenticated retirement read-only observer.
- ADR-0105: settled paid-absence continuation; original clocks stay immutable.
