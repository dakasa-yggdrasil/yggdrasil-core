# ADR-0098: Quarantine a previously serving single Guest before native absence

- **Status:** Accepted
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / original Notify single-member operational recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

An originally installed and useful Guest can lose its immutable writer while
its actor and runtime remain alive. The cause may be unknown. The original
writer cannot be manually recreated under its old enrollment. A previously
useful member does not satisfy failed-installed zero-useful disposal, and an
ordinary retirement cannot take the sole protected member below floor one.
Historical publication, accepted canaries and uncertain remote business effects
must survive recovery. Native absence cannot fabricate their completion.

## Decision

Introduce a distinct, named-human, history-preserving lane for slot one of a
complete one-member original Notify AWS or Hetzner fleet with floor one and
ceiling eight. The operator owns both exact native power-off and deletion.
Core sends no Guest work or provider mutation in this lane. It owns only an
immutable quarantine, bounded authenticated native reads, and the atomic
observed-deficit terminal after complete native absence.

POST `/api/v1/ops/capacity/failed-serving-guest-disposals` accepts exactly six
CAS expectations: preregistration UUID, current policy UUID/checksum, current
generation/fencing token, and SHA256 of the full PostgreSQL `intent::text`
wire. Under the existing dimension and global native-slot locks, require the
current latest active policy and workflow pins, unchanged approved Guest
contract, original confirmed create, preregistration, signed enrollment,
installation and exact surviving native tuple. Require a fresh, complete
same-profile native inventory containing only slot one and the other seven
slots explicitly missing. No caller supplies native facts, URLs or health.

Separate birth lineage from the current epoch. Birth generation and fence must
be positive and no greater than the current epoch. Retain an accepted original
read and a promoted event in the birth generation. The current stable intent
may be `promoted`, `reconciled` or `reconciled_partial`; require and hash its
exact current generation/fence/phase event. An older original slot can therefore
survive an ordinary expansion and contraction. No fresh accepted canary is
required from the failed member and no current readiness is asserted.

Require no active intent lease, pending recovery/degraded-floor/disposal,
queued/started/unknown dispatch, returned dispatch without acknowledgment,
unfinished protected workflow, live target canary deadline, unresolved native
mutation grant, or retirement intent for this original member. Original create
and provisioning contexts must already have expired. Immutable ADR-0096
`unknown_maintenance_disposed` dispatches remain admissible only after their
distinct original closure is revalidated. Preserve their NULL acknowledgment,
held canary sends and uncertain effects; elapsed time never proves zero effects.

Append the quarantine receipt while changing the current intent, by exact full
wire CAS, to pending/unleased `serving_guest_quarantined` with one incremented
fence and execution disabled. Preserve the full original intent wire, current
event hash, installation/enrollment hashes, original create/slot identity and
historical canary/unknown records. Put its admission ID on the global logical
slot. Every normal intent/recovery, canary and native mutation path refuses
this active marker, including access through another policy realm. The
scheduled planner returns HOLD before demand/member-coverage collection.

After the operator powers off the exact original tuple, POST `/native-off`
accepts only preregistration and admission UUIDs. Revalidate the frozen scope,
pins, histories and absence of live authority, then perform the ordinary fixed
GET-only native observation. Validate exact native OFF content; AWS also joins
the actual instance and lifecycle reads to the original create action. The
private original context and actual HTTP completion own read freshness, not
agreement between provider and Core clocks. Append an immutable `quiescent`
read; this claims no Guest drain, operator power-off acknowledgment or cause.
Stored GET never refreshes the native observation. The operator independently
checks current exact native OFF immediately before its deletion attempt.

After the operator deletes the exact original native and required owned
auxiliaries, POST `/complete` again accepts only the two UUIDs. The existing
source-owned closed absence GET reads the original CREATE tuple and complete
required auxiliary roster. Its DTO has no never-useful admission predicate;
new eligibility stays in this distinct Core lane. Independently obtain a fresh
complete same-profile inventory with zero members and all eight slots missing.
Target absence alone cannot prove fleet zero. Revalidate every frozen pin and
history under the locks, link the terminal to the retained native-OFF row, then
atomically tombstone only the original slot and append `disposed_failed_serving`.
The same-generation terminal retains the quarantine fence and reports only the
actual inventory-zero snapshot, an observed floor deficit and execution false.
It never synthesizes a Prometheus assessment, promotion, Guest ACK or DELETE ACK.

Each explicit operation retains a single bounded thirty-second original
context; native HTTP calls retain twenty-five-second limits and two-MiB content
caps. The private once-owned read context is neither a cryptographic V2
challenge nor a durable mutation/read lease. A failed GET may be repeated only
as a fresh explicit observation; no automatic retry, old-return relabel or
provider write is authorized. Each successful stage is unique; a lost successful
reply is reconciled through stored GET rather than repeating the stage. An
uncertain operator deletion must first be
reconciled by provider read before any later operator action.

Migration 88 makes the lineage append-only, binds exact original wire hashes,
scope, original create and native slot, and enforces admission→quiescent→terminal
foreign-key lineage and same-transaction intent linkage. SQL rederives structural
CAS and historical row facts. Original signed enrollment validation, native
authentication, complete provider content and actual HTTP completion remain
the source-owned Go validator/collector trust boundary. Public responses expose
only IDs, hashes, counts, stages and explicit truth flags. GET `/{preregistrationId}`
reads stored summaries only. Qualification builds refuse all three operations.

## Consequences

- Preserve every original accepted use, immutable enrollment, possible business
  effect and failed return. OFF and absence fence future execution on this VM;
  they do not settle remote business completion or prove a fixed cause.
- Provider reads are bounded observations, not an OFF-state CAS or a lease
  against an external operator starting/recreating a native. The operator must
  exclude concurrent native actions while applying the exact cleanup sequence.
- Ordinary next-generation floor repair independently requires live complete
  inventory zero, legitimate missing metric coverage, current approval, a new
  native lifetime and a new enrollment. This lane grants no replacement or
  health proof and imports no same-build peer exception.
- Other slots, multi-member failed-serving recovery, old zero-useful disposal,
  normal protected-floor retirement and their existing guards remain unchanged.
- Apply migration 88 before the new Core build. Current exact CI and production
  operator/native evidence remain independent gates; declared CI fixtures are
  never live provider or Guest qualification. No local functional tests are used.

## Related

- ADR-0079 (distinct failed-installed zero-useful lane, unchanged)
- ADR-0092 (relates-to: native OFF and explicit operator cleanup)
- ADR-0094 (depends-on: immutable installed-member policy continuity)
- ADR-0095 (relates-to: ordinary surviving-member history)
- ADR-0096 (depends-on: honest unknown maintenance closure)
