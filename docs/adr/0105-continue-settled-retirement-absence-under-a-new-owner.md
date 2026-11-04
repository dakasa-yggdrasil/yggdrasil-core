# ADR-0105: Continue settled retirement absence under a new owner

**Status:** Proposed

Date: 2026-11-04

Scope: Original Guest retirement / scheduler / immutable native forward proof

## Context

An original accepted native DELETE can settle while its exact auxiliary resources
remain visible beyond the original sixty-second finish invocation. A complete,
authenticated Pending return proves neither absence nor a lost mutation. Repeating
the mutation, extending its deadline or treating an expired owner as current would
violate the original custody and fencing contracts. Administrative historical
recovery remains distinct from normal automatic completion.

## Decision

Add the source-owned `settled_absence_continuation` mode to the existing immutable
forward ledger. The actual scheduled plan may append one requested child of the
current admitted or OFF-qualified owner only after natural lease expiry, the exact
failed workflow return and finalization ACK, an accepted SETTLED owning DELETE,
complete immutable eligibility/receipt binding, and the last complete authenticated
Pending absence return. Any unfinished challenge, unknown transport, malformed
return, competing live job, unrelated unresolved grant or live canary refuses the
request. SQL/storage failures propagate. The existing unique parent-child index
and scope/profile locks make competing requests atomic.

The optional closed continuation proof pins the original failed run, whole dispatch
including ACK, grant record, delete eligibility and last Pending read. Parent/root,
original request/prefix and every old wire remain intact. A zero process barrier
states honestly that no process replacement is asserted. Live and administrative
historical modes keep their existing contracts.

The existing claim operation acquires a new fenced owner/executor/run and ordinary
policy lease. This is a new invocation, never renewal of the old lease or reset of
its original deadlines. Quiet is checked again at claim; only the independently
validated current scheduler run is excluded. The new mode cannot perform Guest
poweroff, native OFF, mutation issue/redemption or a new DELETE binding. It can
read the exact owning receipt, obtain fresh absence and survivor inventory and
useful canaries, and confirm that same settled grant through existing completion.
Pending history is provenance only; terminal qualification still needs the new
owner's fresh five-second read and fresh useful floor. Native absence, auxiliary
identity, epoch, ownership, source, invoice and terminal guards remain mandatory.

A later failed Pending owner may have one child on another scheduler tick under
these same conditions. No invocation loops across owners, changes a timer, retries
a mutation or releases a resource slot from Pending evidence.

## Consequences

Migration93 extends only the explicit mode/proof constraints and mode-specific
branches of migration90's guards. Migration90 and all old ledger rows are retained.
Old wire encoding omits the new optional proof. Actual delayed provider absence
can complete automatically under a new legitimate owner while unknown or failed
transport still requires its existing refusal/recovery path. Focused PostgreSQL
and controller tests exercise new ownership, retained mutation custody, fresh
floor, negative eligibility and concurrency; functional execution belongs to CI.
