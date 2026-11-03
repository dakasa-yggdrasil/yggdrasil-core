# ADR-0096: Dispose recorded unknown maintenance refreshes without rewriting their return

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity dispatch operator resolution
- **Supersedes:** —
- **Superseded by:** —

## Context

A failed steady original Guest maintenance canary can exceed the original
executor context while returning before its five-minute dispatch lease. Core
honestly records the failed workflow result and return in an `unknown` dispatch,
with no finalization acknowledgment. The active-scope fence then prevents all
later ticks. The abandoned and lost-finalization dispositions require `started`
with no recorded return; applying either would erase a materially different
history. A timeout or process replacement cannot authorize replay.

## Decision

Add a distinct administrative disposition for a recorded, failed, ordinary
maintenance refresh only. Migration 87 introduces
`unknown_maintenance_disposed` and an immutable receipt in
`capacity_dispatch_unknown_maintenance_dispositions`. The job may change only
its terminal state, receipt pointer and update time. Preserve every original
return field, finalization error and NULL acknowledgment; preserve the complete
already-finished workflow row byte for byte. The receipt retains the original
job/run hashes and declares `historical_return=unknown`. It is neither a return
nor an acknowledgment, success, readiness, rollback or replay.

The god-mode and CSRF-gated POST
`/api/v1/ops/capacity/unknown-maintenance-dispatch-dispositions` accepts exactly
nine CAS expectations: job, run, envelope digest, dispatch fencing token, lease
owner, pending wake count, original return time, complete run digest and current
stored member-set digest. GET on the same path with `/{jobId}` reads the receipt
for lost-response recovery. Recheck current operator permission at the commit
boundary. No workflow dispatch or provider call occurs in either handler.

Under the ordinary scope advisory lock, then job and workflow row locks,
retain share locks on exact catalog pins, intent, slots and grants through the
commit (catalog publication does not share the capacity advisory lock), and
require protocol v1, `unknown`, a real `failed` return and result with the fixed
original-deadline error, no acknowledgment or other disposition, and a return
strictly between the original start and lease expiry. The database clock must
be at least 15 minutes past that lease, and the disposing Core process must
have started after it expired. This excludes this process being its former
in-process executor; other replicas and remote accepted requests are not
claimed to be quiescent.

Require the current active policy and workflow to be the exact original pins,
and the same stable, unleased, useful generation/fence. Refuse pending disposal,
installed-reconcile, recovery-only or degraded-floor markers. The complete
seven-step persisted result must show one succeeded ordinary hold plan in
refresh mode, slot zero and no owner/request, one failed maintenance refresh at
`fresh_original_canary` / `nonce_finalize` or `reserve_send`, and every possible
provision/retire/completion step skipped. A changed policy, epoch or mutation
path refuses this lane rather than inferring continuity.

Re-derive current stored members from non-tombstoned resource slots joined
one-to-one to confirmed, undisposed creates, preregistrations, original enrollments
and installations predating the conservative start-minus-30-second window.
Their native tuples must match and their policy/generation/fence must remain
exact. Refuse a current member with any retirement intent. Retain their IDs,
source hashes and slot-revision hashes in the receipt, and bind the caller's
expected member-set digest. This is a stored-membership proof, not a new native
observation or a canary; ordinary next-tick admission must prove those again.

Reuse ADR-0090's complete enumerated effect scan unchanged as a nested base:
every native mutation, grant, lifecycle, original authority, retirement,
intent-event and Notify-window effect remains zero. Its existing row-proved
unleased assessment and observation refresh tolerances remain. Only the four
canary counters gain a distinct tolerance: every affected challenge must be
steady-useful maintenance for the exact current policy/workflow/epoch and one
of the current installed members; all signed deadlines must have expired,
within the former lease, and no associated nonce/send/return may be written
after that lease. Canaries, accepted business effects and original records are
retained. Workflow completion and ordinary audit records are not treated as
native mutation effects or erased.

The receipt insert guard re-derives these facts. A deferred database trigger
requires the receipt and terminal job in the same commit with the original
workflow hash unchanged. The terminal job, receipt and original workflow then
refuse mutation or deletion. The next ordinary tick independently passes
current admission; no original envelope, counters, markers or failed result is
reset.

## Consequences

- Unknown maintenance failures can release their dimension without fabricating
  an acknowledgment or replaying a mutation.
- This lane deliberately refuses provisioning, retirement, other failed stages,
  uncertain absent returns, changed epochs and nonzero native-effect ledgers.
- Expired maintenance canary challenges and their original possible sends remain
  permanent. The scan does not claim provider or business-effect quiescence.
- Migration 87 is forward-only. The PostgreSQL and HTTP gates run only in CI
  against a fully migrated isolated Unix-socket database; declared fixture rows
  do not qualify an actual Guest or provider.

## Related

- ADR-0044 (relates-to: durable original dispatch ownership)
- ADR-0089 (relates-to: separate no-return abandoned disposition)
- ADR-0090 (relates-to: lost finalization and enumerated effect scan)
- ADR-0093 (depends-on: steady maintenance canary authority)
- ADR-0094 (relates-to: policy continuity; this lane remains exact-revision)
