# ADR-0092: Quiesce a V2 failed-installed disposal whose Guest refused the retirement, from a native OFF read

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity failed-installed Guest disposal (`original_production_v2`) operator resolution
- **Supersedes:** —
- **Superseded by:** —

## Context

Production Hetzner disposal `8ef5f76c` (preregistration `b8076d1e…`, gen8,
fence 21, lease owner `00e34a1a…`, mode `original_production_v2`) was claimed
by run `0b482d82`. Its plan step retired slot 1 with reason
`failed_installed_disposal`. The retire step issued V2 retirement intent
`fc853776…`:

- the Guest answered the nonce (journal row 1, `production_clock_nonce_v2`);
- the Guest journaled a signed `possible_start` (row 2) with
  `writer_quiescence_evidence=false`, `poweroff_command_returned=false` and
  `powered_off_observed=false`;
- the single caller POST then closed with HTTP 409. Core did not keep the
  194-byte body (`body_persisted=false`).

The retire step failed (`original-production-retirement-v2-held`), the finish
step was skipped, the intent's deadline and the claim lease expired, and every
plan tick now holds with `failed_installed_explicit_native_cleanup_pending`.
There are no native poweroff reads and no delete bindings for the intent.

No existing lane reaches `quiescent` from this history:

- `advance` requires the claim run to show retire `succeeded` and finish
  `failed`, the five-row V2 quiescence proof and a caller 200 with a persisted
  body (`guestQuiescentProofV2Tx`).
- `retirement-recoveries` (migration 79), `prejournal-refusal-recoveries`
  (migration 80) and `partial-native-off-reconciliations` (migration 81) are
  legacy-only (`legacy_guest548_original_v1`). Migration 79 also forbids any
  caller attempt, and 80 requires a refusal before the Guest journal.
- `complete` needs `quiescent` first.

Every fact these lanes check is append-only and tied to the expired intent, so
retrying changes nothing. The Guest's 409 is very likely caused by its dead
enrolled notify writer, but the body was not kept, so that is not proven.

## Decision

Add one V2-only, god-mode, operator-admitted lane that quiesces such a
disposal from a native OFF read of the expired intent's own tuple. It never
claims writer quiescence and never sends a Guest request, a poweroff or a
DELETE. Powering the server off and deleting it stay explicit owner actions at
the provider.

### 1. The route

`POST /api/v1/ops/capacity/failed-installed-guest-disposals/v2-refused-native-off`
with the closed body `{preregistration_id, admission_id, retirement_request_id}`
(three distinct canonical UUIDs; any other, duplicate, null or trailing key is
refused), and `GET …/v2-refused-native-off/{preregistrationId}`. Both use the
same god-mode operator gate and CSRF middleware as the other disposal lanes.
The error mapping matches `advance`: 400 for a malformed body, 409
`failed_installed_v2_refused_native_off_not_qualified` for anything else.
Responses carry ids, stages, hashes and the caller status only, and state
`Guest_writer_quiescence_claimed=false`,
`original_poweroff_command_returned_or_caller200_claimed=false` and
`new_Guest_request_or_poweroff_or_delete_sent=false`.

### 2. Strict admission evidence (under the scope lock)

`PrepareFailedInstalledV2RefusedNativeOffRead` requires all of:

- The disposal `admission_id` is `claimed`, belongs to `preregistration_id`
  and has mode `original_production_v2`.
- The current intent names it as `claimed`, carries no 79 or 80 recovery id,
  deep-equals the recorded `claimed_intent`, and its lease has expired.
- `failedInstalledDisposalActiveTx` passes (claim, admission, enrollment,
  installation, recorded runs, zero useful credit).
- The claim run is the returned, acknowledged, failed seven-step run with
  `plan-original-guest=succeeded`, `retire-original-guest=failed` and the other
  five steps `skipped`. The plan is read from the plan step's metadata itself
  (the internal step unmarshals its plan into `result.Metadata`; only adapter
  steps wrap output under `output`, and a wrapped plan is refused). It is
  `mode=retire`, `reason=failed_installed_disposal`, slot 1, and the claimed
  generation, fence, lease owner and preregistration.
- The failed retire step is tied to the admitted retirement by its refusal
  predicate, not by a request id. The internal step's `fail` closure replaces
  the metadata with exactly `{original_guest_refusal_predicate}` and never
  records `request_id`, so production run `0b482d82` has none on that step.
  The step must carry the standard step error and exactly the predicate
  `original-production-retirement-v2-held` (the V2 production retirement
  returned an error). Any other predicate (legacy V1, preflight) or extra
  metadata is refused. Together with the single V2 intent of the
  preregistration, issued under the same generation, fence and lease owner,
  that binds the failed step to `retirement_request_id`.
- `loadGuestRetirementV2Tx(retirement_request_id)` loads the V2 intent and
  joins the preregistration, policy id and checksum, generation, fence, lease
  owner and lease executor. It is the only retirement intent of the
  preregistration, and both its stored and canonical original deadlines have
  passed.
- The journal is exactly `[nonce, possible_start]`: the nonce joins the
  stored preflight (`guestRetirementV2NonceJoin`), and `possible_start` is an
  authentic signed V2 observation with no runtime return, no writer
  quiescence and no poweroff.
- Exactly one caller attempt and one caller return. The return is closed (no
  preflight, do, read, close or context failure), was read completely, closed
  before the original deadline, has status in 400–599 (never 200) and
  `body_persisted=false`.
- No delete binding, no `before_poweroff` authority read, and no 79, 80 or 81
  row for the disposal.
- `failedInstalledZeroUsefulTx` passes.
- At first admission there is no native poweroff read for the intent. On a
  retry, every native read of the intent belongs to this admission.

### 3. Bounded native read, then quiescent in one transaction

Prepare writes the admission (once) and one read challenge in the existing
`capacity_guest_original_native_poweroff_reads` table, in the same schema as
the normal V2 read. The challenge binds the intent id, `GuestRetirementSHA`
of the intent, and, in place of a persisted body, the refused caller return's
`return_sha256`. It is committed BEFORE the provider call, with a budget of at
most 5 seconds. At most 5 challenges per admission, one at a time.

The message controller makes one observe GET through the existing V2 supplier
transport (`productionRetirementSupplierV2` plus the read-only
`failedInstalledLegacyReadonlyCall`: `observe_server` for Hetzner,
`observe_ec2_instance` with the lifecycle join for AWS). The return is always
retained. A plan that does not pass `guestNativePoweroffReadV2Content` (OFF
or stopped, exact tuple and binding) is retained without its plan and grants
nothing; the call answers 409 and can be repeated after the server is off.

Only a timely accepted OFF read qualifies. The qualification transaction
re-derives the whole context, re-runs the shared `guestNativePoweroffV2Tx`
(exact challenge join to the caller return, freshness, OFF content), and then
writes, together:

- the lineage row `qualified` (admission hash, native read id, OFF hash);
- the disposal row `claimed → quiescent` with
  `retirement_request_id` = the refused intent and `native_poweroff_sha256` =
  the OFF read;
- the intent: phase `failed_installed_cleanup_pending`, marker `quiescent`,
  lease owner, executor and expiry cleared.

### 4. Migration 86: immutable admission and lineage

`capacity_guest_v2_refused_nativeoff_quiescences` holds one `admitted` and at
most one `qualified` row per disposal, preregistration and retirement (closed
record, no update or delete). A `qualified` row needs the newest challenge of
the intent, the newest return of the intent, and that challenge to have exactly
one return: the native reads table does not make returns unique per challenge,
so the guard itself keeps an older OFF return from qualifying beside a later
one. Its `BEFORE INSERT` guard takes the scope lock
and re-derives the evidence from the original rows: V2 mode, unchanged
claimed intent with an expired lease, the same epoch on the retirement
intent, a single expired V2 intent, the exact two-row journal, one closed
non-200 caller return without a retained body, no poweroff authority, no
delete binding, no 79/80/81 row. `admitted` requires no native read yet.
`qualified` must preserve the admission and point at the newest complete
return whose plan server status is `off` or `stopped`, whose challenge joins
the refused caller return and was recorded after the admission, and every
native read of the intent must belong to the admission.

A second guard on `capacity_guest_failed_installed_disposals` refuses a
`quiescent` or `terminal` row of a disposal that has an admission here unless
it carries exactly the qualified lineage (retirement, OFF hash, claimed
intent). So quiescent rows from this lane cannot be confused with
Guest-proven quiescence. The existing migration 80 chain guard already allows
`claimed → quiescent` here (no 79/80 recovery requested).

### 5. Terminal is unchanged

The V2 branch of `loadFailedInstalledQuiescentTx` first asks
`v2RefusedNativeOffQualifiedTx`. When the disposal has this lane's qualified
lineage for the quiescent retirement, it re-validates the lineage and the same
refused-retirement evidence instead of `guestQuiescentProofV2Tx`. A disposal
with an admission but no matching qualification is refused. A disposal
without any admission keeps the normal proof. The existing native OFF read
join that follows is unchanged, so `complete` (native absence GET, slot
tombstone, `terminal`) and the external-cause replacement lane work as before.

### Production sequence (after merge, CI and deploy)

1. Owner, outside Core: power off Hetzner server `172592998`.
2. `POST …/v2-refused-native-off` with
   `{preregistration_id: b8076d1e-2e34-4acc-8ce1-14ef4a6adc8a,
   admission_id: 8ef5f76c-aeec-4acb-9469-1eb3cce46f93,
   retirement_request_id: fc853776-491b-4959-87ed-61afca39f8e2}`. If the server
   is not OFF yet, 409 with no state change; retry.
3. Owner, outside Core: delete server `172592998`.
4. `POST …/complete` with the preregistration and admission ids.

### Rejected alternatives

- **Relax `advance`.** Its claim-run, five-row proof and caller-200 checks
  protect the normal path. Weakening them would let a Guest-unproven
  quiescence pass everywhere.
- **Extend 79/80/81 to V2.** Their only output is a successor Guest request,
  which this Guest would refuse again, and their evidence shapes are legacy.
- **Core-side poweroff or destroy.** That needs a new native mutation grant
  and is a larger change.
- **No migration.** The chain guard already allows the transition, but then a
  quiescent row from this lane would be indistinguishable from a Guest-proven
  one. The lineage table makes it explicit.

## Consequences

- Writer quiescence of the dead notify writer is never claimed; the native
  OFF read only proves the server is not running. Business effects of the
  failed Guest stay preserved.
- A refused retirement with a third journal row, a caller 200, a persisted
  body, an active lease, the legacy mode, a poweroff authority read or any
  earlier native read is not admitted.
- Migration 86 is forward-only, and its Down step raises. Schema assertions
  move from 85 to 86.
- Tests (CI only, wired into the disposition Source workflow at schema 86):
  migration 86 guards (exact admission, non-OFF read refused, exact OFF
  qualification, quiescent only with the lineage, immutability, forged facts
  and unqualified histories refused: caller 200, persisted body, transport
  failure, third journal row, writer quiescence, active lease, legacy mode,
  earlier native read, poweroff authority, open deadline, foreign caller
  read); Go refusals before any write; the caller and claim-run predicates;
  HTTP closed body, authentication and summary.
- No end-to-end positive Go path is tested. A validated production Guest
  policy, signed V2 enrollment and journal cannot be fabricated in a test.

## Related

- ADR-0079 (extends: failed-installed Guest disposal)
- ADR-0080, ADR-0081, ADR-0082 (relates-to: the legacy-only 79/80/81 recovery lanes; ADR-0082 is the closest shape, a separate native OFF proof)
- ADR-0091 (relates-to: same disposal `8ef5f76c`; its external-cause
  replacement needs this disposal terminal)
- ADR-0089, ADR-0090 (relates-to: the operator-lane pattern reused here)
