# ADR-0090: Keep an observed capacity dispatch return durable, and dispose a lost finalization

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity dispatch (`capacity_dispatch_prestart_v1`) finalization and operator resolution
- **Supersedes:** —
- **Superseded by:** —

## Context

Production AWS dispatch job `09a9fee8-4f52-4106-907d-c9b5ccc388bc` (dimension
`original_notify_aws_vm_members`) started at 2026-11-02 08:04:09.181Z. Its
lease expired at 08:09:09.077Z. It is still `started` with `returned_at` NULL,
its run `bbb62859` is still `running`, and `pending_wake_count` is 32, so the
dimension stayed blocked until the Core pod was replaced at 09:16Z.

The executor did not hang. It returned at about 08:04:12.3Z. The Brain
PostgreSQL log holds exactly one cancelled Core statement in the window:
`2026-11-02 08:04:17.377 UTC [177447] ERROR: canceling statement due to user
request` on the `UPDATE public.workflow_runs ... finished_at=$5 ...` statement
that only `FinishCapacityDispatch` issues. That function did all of its first
finalization in one transaction under a single 5-second budget, never retried,
and the deferred rollback also undid the job update. Nothing else could record
the return: `RunOne` only folded the error into its result, the addon logged an
opaque line, and `ClaimCapacityDispatch` never adopts a started row. The
response and the actual return time lived only in the memory of the replaced
pod.

Before the lost write, the tick had durably written two bookkeeping rows: the
plan step's `AssessOriginalGuest` hold (`capacity_intents`, 08:04:10.568, phase
`promoted`, decision `hold`, reason `signal_evidence_unavailable`) and the
refresh step's slot observation (`capacity_resource_slots`, AWS slot 1, resource
`i-0e3aba1cf6fe34a50`, revision 281, 08:04:12.206). The ADR-0089 effect scan
therefore reports `intents_updated_since_start=1` and
`resource_slots_updated_since_start=1`, and ADR-0089 refuses the job. Every
other counter is zero: no grant, canary, Notify window, native command or intent
event.

The same investigation found three latent hazards on the owner path: `RunPass`
waited on its four owners without a bound, a panic in the executor left the row
started silently, and the addon closer waited for the worker forever. It also
found that the workflow event-trigger leader lock was a session advisory lock
taken and released through the `*sql.DB` pool, so the unlock could run on a
different connection (`you don't own a lock of type ExclusiveLock` every 5-10 s)
and the lock leaked on an idle pooled connection.

## Decision

### 1. A really observed return is written with a bounded retry

`FinishCapacityDispatch` (and `FinishCapacityDispatchObserved`, which adds a
category observer) runs the first finalization commit in a loop:

- Each attempt is the whole original transaction (job row `FOR UPDATE`, the
  original checks, the job update, the run update, commit) under its own budget
  of 15 s, with `SET LOCAL lock_timeout='10s'` and
  `SET LOCAL statement_timeout='12s'`, so a slow wait fails inside PostgreSQL
  with a classified error instead of a client cancel.
- Only an attempt that rolled back before a confirmed commit, while the row is
  still the same started claim, is retried. The loop backs off 0.5/1/2/4 s and
  stops after at least three attempts once `lease_expires_at + 2 min` has
  passed. Retrying cannot write twice: every failed attempt rolled back whole,
  the job update now also requires `state='started'`, and the run update
  requires `status='running'` and the original `started_at`.
- The honesty rules are unchanged on every attempt: the original context
  failure captured at entry, the live-claim check, the clock check and the
  `final_clock` CASE. A write that lands after the lease therefore records
  `unknown` with the real `returned_at` and `return_status`.
- If the row is no longer this started claim (for example it was disposed), the
  loop stops with `ErrCapacityDispatchClaim` and writes nothing.
- Lost commit acknowledgment: when `Commit` returns an error, or a later attempt
  finds the row no longer started, Core re-reads it. If it is `returned` or
  `unknown` with exactly this process's `returned_at` (captured once at
  microsecond precision), the same claim and no acknowledgment, the commit
  landed. Core never acknowledges it; a `returned` row is downgraded to
  `unknown` through the existing `markCapacityDispatchFinalizationUnknown`.
- Exhaustion returns `ErrCapacityDispatchFinalizationPending`. The row stays
  `started`, an honest hold.

### 2. The owning process keeps a pending return and retries it

`RunOne` puts an exhausted return (job, response, actual return time, run error,
release fence and the original dispatch context) into a bounded in-memory list
(64 entries) on `CapacityDispatchService`. `RunPass` first retries every due
entry with `RetryCapacityDispatchFinalization` (one attempt, the same rules),
then claims new work. A retry after the original deadline records `unknown`. If
the process dies first, the row stays `started` and goes to the operator lane
below, which is exactly the case where no return can be proven by Core.

### 3. The owner is bounded without inventing a return

`RunOne` runs `RunWorkflow` in a `SafeGo` goroutine that reports exactly once on
a channel of size one: the response, the run error and the return time, or a
panic marker. `RunOne` waits for that report or for `lease_expires_at + 30 s`.
On timeout it records `executor_overdue`, returns, and leaves the row
`started`; a detached `SafeGo` waits for the late report and finalizes it
through the same loop (which records `unknown`, or refuses if the row was
disposed). A recovered panic is still not a return: the row stays `started` and
`executor_panicked` is recorded. `RunPass` therefore can no longer stall every
dimension behind one wedged owner, and the addon closer now waits for the worker
only until its own shutdown context ends.

The service records secret-free categories with the job id only
(`finish_write_retry`, `finish_write_exhausted`, `finish_commit_ack_lost`,
`finish_pending_recorded`, `finish_pending_refused`, `finish_pending_retained`,
`finish_pending_dropped`, `executor_overdue`, `executor_panicked`); the addon
drains and logs them. `finish_pending_refused` means a retry wrote nothing
because the row was already disposed or is no longer this started claim. No
envelope, input, response or cause text is logged.

The retry loop also watches the owning process lifecycle, separately from the
original dispatch context that the honesty rules read. On shutdown it stops
waiting between attempts and returns the pending error, so the row stays an
honest `started` hold instead of racing a closing database handle.

We rejected an owner-side `unknown` marker with `returned_at` NULL written at
the timeout. It needs a state-model change to `unknown` (the lifecycle CHECK,
the active-dimension index and admission) and gains nothing that the honest
`started` hold plus the lane below do not already give.

### 4. Workflow event-trigger leadership is pinned to one session

`TryAcquireWorkflowEventTriggerLeadership` now takes the session lock on a
pinned `*sql.Conn` and returns a `WorkflowEventTriggerLeadership`, whose
`Release` unlocks on that same session with a context that a cancelled caller
cannot skip. If the unlock fails or reports the lock was not held, the session
is discarded (`driver.ErrBadConn` through `Conn.Raw`) instead of being pooled
while still holding it.

### 5. Plan-time failed-installed disposal without member coverage

The plan step requires a full reporting-membership proof before it reaches the
failed-installed disposal claim. That disposal exists to remove a Guest that is
often dead, so the proof can never pass (production Hetzner disposal
`8ef5f76c`). Now, only for `capacity.plan_original_guest`, and only when
`collect` failed with `ErrOriginalGuestReportingIncomplete` (the inventory,
snapshot and demand reads already passed) and the current intent carries a
`requested` `failed_installed_disposal`, the step continues to
`OriginalGuestReconcileMembers` and `TryClaimFailedInstalledGuestDisposal`,
which re-proves every fact under the scope lock and never reads the reporting
observation. If members are pending or the claim is not eligible, the step
fails at `source_assessment` with the original coverage error. This refusal is
not write-free: `OriginalGuestReconcileMembers` has already committed the
observation refresh of the exactly enrolled live slots (`observed_at`,
`receipt_ref`, `revision + 1`), the same refresh a covered plan commits. It
adopts nothing and moves no intent, lease or fence. The routing gate itself
(`FailedInstalledGuestDisposalRequested`) writes nothing: it runs the Source
proof in a writable transaction under the scope lock, because the proof's
`FOR SHARE` reads are refused in a read-only one, and always rolls it back. A
gate that cannot answer fails the step at `source_assessment` with its own
cause. Resume and ordinary assessment never run without coverage, and every
other operation keeps the strict gate.

### 6. Operator disposition of a lost finalization (migration 84)

A new terminal state, `finalization_lost_disposed`, and an immutable receipt,
`capacity_dispatch_finalization_lost_dispositions`, close a started job whose
return was observed outside Core but never recorded. The routes are
`POST /api/v1/ops/capacity/finalization-lost-dispatch-dispositions` and
`GET .../{jobId}`, behind the same god-mode, CSRF and commit-boundary operator
recheck as ADR-0089. The closed body has the six ADR-0089 compare-and-swap
fields plus `finalization_evidence`: opaque UTF-8 text of at most 8 KiB (no
control characters other than tab, CR and LF), for example the PostgreSQL log
lines of the cancelled finalization. Core stores it verbatim with its SHA-256
and never treats it as authority; reads export only its hash and size.

Preconditions are those of ADR-0089: protocol v1, `started`, no return, no
acknowledgment, no finalization error, no disposition pointer, the CAS, the
lease expired at least 15 minutes ago by the database clock, the original run
`running` and untouched, a lock-safe scope name, and the executor barrier (the
disposing Core process started after the lease expired). The effect scan
`finalization_lost_dispatch_effect_scan_v1` is the ADR-0089 scan plus two
counters, and every ADR-0089 counter must be zero except:

- `intents_updated_since_start` may be 0 or 1, and must equal
  `pure_assessment_intent_updates`. The counter's name is narrower than its
  proof: it counts an unleased hold rewrite that moved no generation, fence or
  phase. It does not compare the intent's other fields
  (`failed_installed_disposal`, `installed_guest_reconcile`, `floor_degraded`,
  `recovery_only`), because no pre-window copy of the intent exists to compare
  against; an operator request that set a `requested` disposal marker in the
  window would also be counted. The receipt records exactly this predicate, not
  a proof that the rewrite came from the assessment path. Such a rewrite has no
  lease (owner,
  executor and expiry empty), decision `hold` without execution permission, was
  written before the original lease expired, and its
  `(generation, fencing_token, phase)` equals the newest intent event of the
  scope, which predates the window (no intent event since start). The main
  intent writer appends an event whenever generation, fence or phase change, so
  this proves the phase did not move. If the scope has no intent event at all,
  the phase cannot be proved and the lane refuses.
- `resource_slots_updated_since_start` must equal
  `observation_refresh_slot_updates`. An observation refresh is an existing
  slot (`revision >= 2`), not a tombstone, without `authority_kind`, whose
  `resource_id` column equals its record, written before the lease expired,
  whose record `observed_at` is a timestamp inside the window (and at most 30 s
  after the write), and whose `resource_created_at`, when it is a timestamp,
  predates the window. Slots have no history table, so "same resource_id as
  before" is proved indirectly: a new resource would need a create grant, and
  grants since start must be zero.

The database enforces the rule on its own: the receipt CHECK calls
`finalization_lost_dispatch_effect_scan_tolerable`, the insert guard re-derives
every fact from the locked rows and reruns the scan, a deferred constraint
trigger requires the job terminal and the run close in the same commit, the job
guard (the migration-83 function with one new branch first) allows only
`started` to `finalization_lost_disposed` with every other column unchanged and
makes the terminal immutable, direct inserts in the terminal state are refused,
and the receipt refuses UPDATE and DELETE. The run is closed administratively as
`failed` with the fixed error
`finalization_lost_disposed: return observed but not recorded; historical
outcome unknown` and `finished_at` equal to the disposal time; `result`,
`returned_at`, `return_status` and the acknowledgment stay NULL.

**Why a new state rather than `abandoned_disposed` with a distinct reason.**
`abandoned_disposed` means "no return was observed and the scan is zero"; its
receipt CHECKs fix the reason and the zero scan, and its link and transition
functions are bound to that receipt. Reusing it would mean relaxing ADR-0089's
CHECKs and guards, so that one state carried two different evidence models.
A separate state keeps each terminal's meaning and its database proof closed,
and the active-state lists (Enqueue, the active-scope index, the claim index,
`failedInstalledZeroUsefulTx` and the migration 73/76/82 checks) already treat
any new state as inactive because they name the active states.

## Consequences

- A slow PostgreSQL can no longer turn a returned executor into a permanently
  started job while the owning process lives: the return is recorded as
  `returned` before the lease, or as `unknown` with real data after it.
- A process that dies with a pending return still leaves `started`; the
  finalization-lost lane closes it only with operator evidence of the return and
  only when the tick's durable effects are the two proved bookkeeping kinds.
- The barrier is local, as in ADR-0089: other Core replicas and requests already
  accepted by an adapter or provider are not excluded
  (`other_core_replicas_excluded=false`, `provider_quiescence_proved=false`).
- The plan-time coverage exception can claim a requested failed-installed
  disposal whose Guest reports nothing; the claim itself, retirement and every
  later step keep their existing proofs.
- Migration 84 is forward-only; its Down step raises.
- The Postgres tests for the retry loop, the lost acknowledgment, the disposed
  row, the leader lock and the new lane, and the HTTP and owner tests, are wired
  into the disposition Source workflow (schema 84) and run only in CI.

## Related

- ADR-0044 (extends: durable pre-start ownership; finalization is now bounded and retried)
- ADR-0089 (relates-to: the zero-effect sibling lane; its scan is reused unchanged)
- ADR-0079 (relates-to: the failed-installed disposal claim reached at plan time)
