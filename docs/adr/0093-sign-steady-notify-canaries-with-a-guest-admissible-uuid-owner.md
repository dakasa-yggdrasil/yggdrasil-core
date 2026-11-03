# ADR-0093: Sign steady Notify canaries with a Guest-admissible UUID owner, and spend the publication budget only on sendable publications

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / original Guest Notify canary (stable-epoch maintenance owner, challenge validation, publication budget, nonce hold diagnostics)
- **Supersedes:** —
- **Superseded by:** —

## Context

The stable-epoch maintenance path (`capacity.refresh_original_guest_notify`, and
the `refresh` mode of `complete_original_guest`) refreshes useful membership with
a `steady_useful_membership` Notify canary. Core signed that challenge with
`lease_owner = "notify-maintenance:" + sha256(executor)`, an 83-character string.
The installed Guest runtime (`integration-guest-bootstrap` b50976579e, and the
later heads f4d7483 and cd64acf) admits a canary challenge only when
`bootstrap.BootIdentity(lease_owner)` holds: exactly 36 characters, dashes at
8/13/18/23 and 32 hex digits. Its nonce handler runs that preflight first and
answers `400 guest_notify.closed_challenge_required` before any actor, writer,
journal or broker check. Core's own `validateGuestNotifyCanaryChallengeBase`
only required the owner to be non-empty, so Core issued and signed challenges
its Guest peer can never accept.

Production (2026-11-02, AWS dimension, gen 10 fence 23, preregistration
`2a23af4b…`): from 11:17:31Z every steady tick committed a publish challenge
and then failed at `nonce_acquire` about 80 ms later. No `notify-maintenance:*`
challenge on any preregistration has ever produced a nonce, a send or a return,
while UUID-owner challenges on the same Guest were accepted at 07:34Z.

A second, separate flaw made this worse. The publication rate limit
(`minimum_publication_interval_seconds`, `maximum_publications_per_hour`)
counted every publish challenge row, and the row is committed before the nonce
GET. Each failed attempt therefore spent the hourly budget; with 10-second ticks
and a budget of 120, a refusing Guest exhausts the hour in about 30 minutes and
every later tick is held at `issue_publication`, hiding recovery for up to an
hour. Core also kept no trace of the Guest's answer: the hold metadata had only
the stage name.

## Decision

1. `GuestNotifyMaintenanceOwner(executor)` returns the RFC 4122 UUIDv5 of the
   canonical executor UUID bytes under a fixed name-space, itself the UUIDv5 of
   `https://yggdrasil.dakasa.me/capacity/guest-notify-maintenance-owner/v1`
   under the RFC 4122 URL name-space
   (`04321c5b-fb9b-5087-9636-068fa7072abd`). It is deterministic per executor,
   distinct per executor, canonical lowercase, and separated from every
   generic UUIDv5 domain. VM lease owners are random UUIDv4, so the version
   nibble keeps the steady usage selection (`input.LeaseOwner ==
   GuestNotifyMaintenanceOwner(executor)`) from ever matching one; steady
   usage also still requires a stable epoch whose intent has no lease owner.
2. `validateGuestNotifyCanaryChallengeBase` requires `lease_owner` to be a
   canonical non-nil UUID, like every other field the Guest checks with
   `BootIdentity` (challenge, record, preregistration, policy, workflow). The
   issuer validates the preflight before inserting the row, so a challenge the
   Guest would refuse now fails at issue time and commits nothing.
3. The hourly maximum counts only publish challenges that have a possible-send
   row, or are still inside their own signed original window (they may still be
   reserved and sent). An unsent attempt past its deadline can never be sent,
   because `ReserveGuestNotifyCanarySend` revalidates the deadline, so it no
   longer spends the declared maximum. Refused attempts are bounded on their
   own, because each is a Guest nonce GET and an immutable challenge row on a
   stable epoch whose generation and fence never move: the gap required after
   the latest attempt is `minimum_publication_interval_seconds` doubled once
   per consecutive refused attempt in the hour since the last live one, capped
   at 15 minutes (never below the declared interval). A Guest that refuses
   every attempt costs about ten attempts per hour at the 5-second floor
   (0, 10, 30, 70, 150, 310, 630, 1270 s, then every 900 s), against 120 before.
   Every attempt in the hour, live or refused, also stays under a fixed
   ceiling of 120, the former all-attempt ceiling.
4. A `nonce_acquire` hold records, in the reconcile step metadata,
   `original_guest_notify_nonce_http_status` (the status actually received, 0
   when none was read) and, only when the body is exactly the Guest's canonical
   problem document with a known `guest_notify.*` code and that code's own
   status, `original_guest_notify_nonce_problem_code`. No body, transport
   error, identity or secret is retained.

No migration: the challenge table only requires `1 <= length(lease_owner) <= 256`,
and no SQL or constraint depends on the `notify-maintenance:` prefix.

## Consequences

- Transition is safe for existing production state without a compatibility
  branch. The maintenance owner was never stored on the intent: the stable
  epoch is the intent's generation and fence with an empty lease owner, and
  each tick derives the owner from its own executor, so every tick after the
  rollout issues and compares the new form. Legacy-owner rows exist only as
  unsent publish challenges (no nonce, send or return); nothing selects them
  for authority, and the new base validation would refuse them if anything
  tried to finalize, reserve or record them. The only reader that counts them
  was the publication budget, which now ignores them once expired, so the
  rollout immediately frees the hourly budget for the orphaned rows.
- A Core build that changes the name-space or the domain string changes every
  maintenance owner. It is a protocol constant pinned by a known-answer test.
- Core now refuses, at issue, any future owner that is not a canonical UUID,
  including uppercase or braced spellings the Guest would accept. Core never
  issues those, so this is stricter on Core's side only.
- A persistently refusing Guest now costs about ten publish attempts per hour
  per preregistration (exponential backoff to a 15-minute gap) instead of up
  to 120 before the hourly stop, so unsent rows grow far more slowly than
  before. `previousInstalledCanariesTx` still refuses an installed reconcile of
  a generation/fence with 256 or more challenges, unsent ones included. That
  limit is unchanged here on purpose: the list is part of the signed installed
  reconcile marker the Guest receives, and changing which rows it carries is a
  Guest-visible wire change this ADR does not make. The legacy orphans already
  written on production gen 10 / fence 23 (about 120 per hour while the old
  owner was refused) may already exceed it; an operator must check that count
  before relying on an installed reconcile of that fence.
- The steady path has never yet passed in production. After rollout the first
  steady canary can still fail for another reason (for example
  `original_actor_held` if the enrolled writer lifetime changed); the new
  nonce diagnostic shows which.

## Related

- ADR-0047 (relates-to: original live lease before the private Notify canary)
- ADR-0059 (relates-to: production Guest admission pinned to compiled contracts)
- ADR-0091 (relates-to: same Guest build b509 promoted on AWS gen10)
