# ADR-0101: Finish an authenticated partial poweroff with a separate native forward proof

- **Status:** Proposed
- **Date:** 2026-11-03
- **Deciders:** Core maintainers
- **Scope:** Ordinary production Guest tail retirement and explicit historical forward recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

A useful, unprotected tail can authenticate its original withdrawal, drain and
poweroff admission before the host or transport disappears. Waiting for the
actual poweroff command return, persisting its fourth signed journal record and
returning HTTP200 are separate events. A physically stopped machine does not
supply a missing record or repair a false original caller acknowledgment.

The normal production V2 contract requires a complete nonce plus four-record
journal and successful closed original caller. Failed-installed zero-useful,
legacy partial-native-OFF and S1 failed-serving disposal have different scopes.
Replaying Guest retirement, stopping the machine again or pretending that one
of those decisions applies would lose the original effect boundary.

## Decision

Add a distinct Core-only forward proof without changing Guest V2, enrollment,
profile, wire usage classes or the existing normal five-row/caller200 validator.
Authenticate the entire original nonce/journal/caller/authority frame. Require
signed timely contiguous Guest sequences1–3 proving complete original
withdraw/drain/runtime/census quiescence and authorized-before-poweroff. When a
valid timely sequence4 is already retained, authenticate and preserve it too;
do not truncate it, manufacture it or infer the caller acknowledgment. Refuse
uncertain, late, duplicate, foreign and unlinked additions. An empty writer
roster is accepted only when it is the exact enrolled roster. This scoped
quiescence is not an assertion that all past business effects were absent.

One validator serves two separately admitted contexts. Future ordinary retire
execution can append a live admission after its actual failed caller return,
while its same capacity lease, generation, fence, owner and executor remain
valid. The ordinary workflow can then proceed through a clearly typed forward
outcome; it never calls the Guest command or nonce again. A historical failed
run requires a named administrative request with strict original-reference and
whole-current-intent CAS, current human authorization rechecked before commit,
expired original deadlines/lease and a server-derived replacement-Core barrier.
Only the actual scheduler claims that request into a distinct fenced epoch.

A live admission that later holds may acquire an immutable historical child.
The original admission and all original frames remain unchanged. The child
retains its root/parent admission hashes and can obtain fresh read identities.
Any issued, redeemed or uncertain destroy stays held and cannot be sent again.
Only an exact already-settled, transport-complete accepted owning destroy, or its
confirmed form, can be adopted for new absence reads and confirmation. Its
original grant epoch, binding and SDK receipt are never rebound or rewritten.

Provider observations are separately owned bounded GETs, with a committed read
identity before I/O and retained complete return/error afterward. Exact tuple,
provider birth, source/catalog bindings, scope, profile, ownership and native
OFF content are mandatory. Recognized stopping is pending, not OFF; a new GET
may observe progress under the live context/lease. No read authorizes Stop,
Guest replay, writer restart, a new nonce or an auxiliary mutation.

The new forward lane uses one fresh `after_retirement_floor` Guest publication
and read after a separate Core-private referenced admission/OFF custody barrier.
The normal V2 before/after-floor contract remains unchanged. Fresh survivor
publication/read must occur after that barrier, under the new owning epoch,
without resetting the existing publication interval/budget. The old successful
caller barrier remains unchanged. Complete fixed-scope inventory refreshes only
exact already-owned slots; an OFF member is never credited as useful.

After native OFF, current physical/useful survivor floor and quiet authority are
reproved, issue the one ordinary exact destroy through its existing Source
supplier and grant/redeem/settlement machinery. The distinct proof discriminant
is checked at issue, redemption, delete binding, absence, confirmation and final
reconciliation. Known accepted parent destroys take only the read/confirm path.
Actual target/all retained auxiliary absence and the immutable owned receipt
authorize exact slot tombstoning. Fresh complete reduced membership/coverage
and survivor business evidence separately gate terminal recording and promotion.
No invoice reconciliation or unrelated business-finality claim is implied.

Append-only PostgreSQL lineage binds actual original bytes and hashes, complete
scope, parent/child admissions, current ownership and one destroy per original.
Normal scheduler/Claim/Recover/Renew/Reconcile and cross-realm physical-profile
mutations cannot bypass an active marker. The early plan gate can find the
existing original before dead-target aggregate coverage blocks collection; it
cannot fabricate a reduced assessment or clear the failure. Original caller,
workflow failures, journal, signatures, deadlines, historical useful work and
publication budgets remain unchanged.

## Consequences and qualification

The normal successful V2 path remains independently valid. This alternate
proof establishes authenticated original drain plus separately observed native
OFF and owned cleanup; it does not establish a successful original Guest caller.
Automatic live completion is bounded by the existing workflow/lease; expiration
is HOLD and requires the distinct historical admission, not guessed cancellation.

CI must execute meaningful real PostgreSQL16/17 and actual Core HTTP/transport
paths for both providers, useful tails2–8, valid three/four-record frames,
concurrency/rollback, catalog/epoch/source/tuple drift, pending OFF, live-to-child
continuation and accepted-destroy read-only adoption. Unknown destroy and missing
auxiliary absence must remain held without resend. Declared transport/storage
fixtures do not qualify a native cloud, original Guest poweroff or production
A/B. Source review, exact-head CI and qualified rollout/native acceptance remain
separate gates; this Proposed decision records none of those future outcomes.
