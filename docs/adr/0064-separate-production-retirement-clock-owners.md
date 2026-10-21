# 0064 — Separate production retirement clock owners

- **Status:** Proposed
- **Date:** 2026-10-21
- **Scope:** Original production Guest retirement and native destroy confirmation

## Context

Core, PostgreSQL, Guest and provider clocks are independent. A Core wall-clock
issued-at checked against the Guest clock can reject a legitimate original
request. Replacing an expired original with a later GET would be unsafe. Native
resource absence also cannot stand in for the original writer drain or complete
native auxiliary cleanup.

## Decision

Use an explicit production V2 wire alongside unchanged qualification/V1. One
private Core owner begins before issuance and owns nonce exchange, durable
possible-send and the single POST for at most thirty seconds. An actual Guest
nonce is signed over the same enrollment, actor/runtime and writer roster. Core
subtracts its entire original elapsed duration before accepting a shorter Guest
kernel expiration. All Guest effects and original joins use that same accepted
expiration. No caller supplies an elapsed duration and no operation renews it.

Persist the actual original nonce HTTP body/Read/Close and final signed request
as sequence 1 with kind `production_clock_nonce_v2` in the existing immutable
journal. The four original Guest signed records retain their sequences 1–4 and
PreviousSHA chain byte for byte. Only their outer database indices become 2–5.
V2 success requires exactly these five discriminated rows, the final nonce hash
and accepted expiration, and a complete original caller acknowledgement inside
the same original deadline. V1 never projects or filters this into four rows.
Late authentic diagnostics are retained without becoming quiescence evidence.

The authority endpoint is fixed, mTLS/bearer scoped, exact-query and bound to the
full final intent hash. Every read reserves its ordinal before I/O and rechecks
the current original workflow epoch, policy/catalog revisions, native floor and
useful Notify floor afterward. The first before-start authority uses the actual
sealed Guest nonce exchange. Later authorities read the actual signed active
Guest journal. There are no arbitrary callback URLs or caller proofs.

After original acknowledgement, source-owned native GETs each receive a new
five-second Core budget beginning before their durable challenge and catalog
resolution. Their returned native timestamps remain diagnostics/content in their
own clock. A read's conservative freshness is its complete five-second bound
plus elapsed Core PostgreSQL custody age. The derived mutation proof explicitly
uses the actual Core PG custody observation time; provider bytes are not
rewritten. Only an exact V2 delete binding selects this validator. Legacy grants
retain their prior validators.

Issue a destroy only after original writer quiescence, independent native off,
fresh useful floor after acknowledgement, and an actual drained workflow phase.
The source does not generate metric assessments or advance phases to obtain a
grant. A prior issued, redeemed or uncertain destroy is never resent. An accepted
original may receive new GET-only reconciliation of its exact immutable native
tuple, action/request identity and complete retained auxiliary resources. EC2
request/lifecycle evidence stays separate from Hetzner native job actions. Native
absence alone never grants writer quiescence, fencing or invoice authority.

Existing migrations 63–64 provide the immutable generic journal and readback
custody. V2 adds no DDL. SQL columns holding original Core issued/deadline events
remain in that same Core clock domain; separate `recorded_at` custody samples
remain PostgreSQL time. Compare durations after a bounded sample, never Core and
PG absolute timestamps. Profile registries remain closed until owning native
qualification and actual production bindings are independently established.

## Consequences

Portable crypto/transport/content tests cover explicit clock skew, late Close,
non-renewal, request pinning and complete auxiliary absence negatives. Native
PostgreSQL negatives do not manufacture accepted authority. Positive native
runtime/provider evidence is separate and mandatory. A provider lacking its own
complete original retirement reader is refused before destroy until its owning
source is implemented, published and pinned.

## Owning provider retirement readers

The additive Hetzner 0.3 catalog must include ordinary destroy and
`observe_server_retirement` as idempotent, server-bound capabilities. Its exact
reviewed publication is `b375d438983b89601c0896fd77d73cde667bedaf`; check that
source before private hydration and recheck the live Describe. AWS retirement
requires 1.62 or 1.63; the reviewed creation-only 1.61 cannot acquire this effect.
Neither gate supplies a profile registry approval or changes an active pin.

Each original accepted destroy may be observed repeatedly under one finish
invocation of at most sixty seconds, each GET inside its own complete five-second
read budget and durable challenge. Only closed known pending native states may
poll. Uncertain originals never resend. The original Guest caller success stays
inside its original thirty-second owner and is never renewed by these GETs.

The current [official Hetzner SDK server schema](https://raw.githubusercontent.com/hetznercloud/hcloud-go/main/hcloud/schema/server.go)
exposes only `Action` on `ServerDeleteResponse`; `NextActions` belongs to create.
Do not invent a Primary IP deletion successor or mislabel its native target as a
server. Any retained successor still requires its actual original identity and
closed native target join. An unsupported provider shape remains held.
