# ADR-0089: Dispose an abandoned started capacity dispatch without fabricating its return

- **Status:** Accepted
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity dispatch (`capacity_dispatch_prestart_v1`) operator resolution
- **Supersedes:** —
- **Superseded by:** —

## Context

ADR-0044 makes a started job (`state='started'`) an explicit hold. Core writes
the possible-start marker and the run's `running` status before it calls
`RunWorkflow`. Only the original in-process owner can write the actual return.
Expiry, a new tick and the stale-run cleaner never release or replay the job.
Started or unknown jobs "require observation/operator resolution". Until now
Core had no operator resolution for a started job. The existing lanes
(failed-original, enrolled-failed, native-denied) need an unknown job with a
recorded `returned_at`, and the prestart rejection needs a queued job.

In production, Hetzner dispatch job `54136edb-daef-4aae-b29b-87bf84996e1f`
started at 2026-11-01T08:00:19Z. Its lease expired at 08:05:13Z. `returned_at`
and the acknowledgment are NULL, and its run `447458d4` is still `running`. The
Core pod that owned it no longer exists: a new single-replica Deployment
replaced it on 2026-11-02 at 06:19:42Z. Nothing can now move the job. Thirty-two
ticks were folded into it, so `pending_wake_count` sits at
`MaxCapacityDispatchPendingWakes` and every later Enqueue returns
`ErrCapacityDispatchSaturated`. The failed-installed lane counts every started
job in the dimension, so it refuses as well. The dimension
`original_notify_hetzner_vm_members` is blocked for good.

The design note `HETZNER-STARTED-UNKNOWN-PROTOCOL-DESIGN-20261102` sets the
limits. Lease expiry, elapsed time, an empty inventory or a human approval do
not prove that the old executor sent nothing, or that a remote effect it began
has finished. Any resolution must keep the unknown visible. It must not invent
a return, an acknowledgment or a "no send". It must also be tied, in one
transaction, to the state of an executor barrier.

## Decision

Add one administrative terminal state, `abandoned_disposed`. Only an exact
`started` job may enter it, and it can never leave it. It is not a return:
`returned_at`, `return_status`, `return_error` and `finalization_ack_at` stay
NULL forever. Migration 83 relaxes the lifecycle CHECK for this one state only.
Every earlier state keeps its migration-76 predicate.

`POST /api/v1/ops/capacity/abandoned-dispatch-dispositions` records the
decision, and `GET .../{jobId}` reads it back. Both use the existing
disposition gate: an authenticated collaborator with god mode, CSRF, and the
current operator rechecked at the commit boundary. The closed JSON body has
exactly six compare-and-swap fields: `job_id`, `expected_run_id`,
`expected_envelope_sha256`, `expected_fencing_token`, `expected_lease_owner`
and `expected_pending_wake_count`. No field carries a fact or an authority.

`repository.DisposeAbandonedStartedDispatch` runs one transaction. It takes the
scope advisory lock first (same key and order as Enqueue), then locks the job
`FOR UPDATE`, then the run `FOR UPDATE`. It refuses unless all of these hold:

- The job uses protocol v1 and is `started`. `returned_at`, the return
  columns, the acknowledgment and all four disposition pointers are NULL. The
  CAS matches.
- The lease expired at least 15 minutes ago, by the database clock.
- The run matches the envelope (selector, inputs and metadata hashes), is
  `running` with the job's `started_at`, and has no `finished_at`, result or
  error.
- In the job's scope, the enumerated Core ledgers record nothing since
  `started_at`. The SQL function `abandoned_started_dispatch_effect_scan`
  (schema `abandoned_started_dispatch_effect_scan_v2`) counts, for the scope
  and for the preregistrations, retirement intents and grants that belong to
  it:
  - grants created or updated, and grants still open and undisposed
    (`issued`, `redeemed`, `compensating`);
  - preregistrations, create witnesses, enrollments, installations,
    qualification probe challenges and native source returns, source-recovery
    cleanup challenges and effect permits, partial native-off reconciliations
    and reads, and pre-journal and pre-send recoveries;
  - retirement intents, retirement contexts, original retirement returns,
    delete bindings and native readbacks;
  - caller possible-sends and caller returns, runtime snapshot challenges and
    returns, authority reads, authority returns and transport returns, and
    native power-off reads;
  - canary challenges, nonces, possible-sends and returns;
  - `capacity_intents` writes, intent events, native commands, native
    lifetimes and lifetime archives, pod checkpoints, executor activity and
    resource-slot writes;
  - with no time bound, any `capacity_intents.intent->'original_notify_window'`
    marker whose `dispatch_job_id` is this job. `BeginOriginalNotifyWindow` and
    `RecordOriginalNotifyWindowReturns` write that marker with a raw intent
    UPDATE and append no intent event, and every later generation carries it.
    A job that durably recorded a possible Notify control window is never
    disposed by this lane.

  Every count must be zero. The scan covers exactly these ledgers, not every
  Core table: the host-factory ledgers belong to other capabilities and are
  not read. Many of the compared columns carry application clock values
  (witnesses, enrollments, installations, canary and caller records, grant
  `created_at`), while `started_at` is the database clock. The window therefore
  opens a fixed 30 seconds before `started_at`, and the scan records that as
  `clock_skew_margin_seconds=30`. The margin is far above the node clock skew of
  the Core hosts, and below the gap between the minute ticks of a dimension,
  whose earlier jobs returned and were acknowledged. A larger margin would count
  those known returns and refuse without cause. The scan's two fixed members,
  `provider_read_performed=false` and `provider_quiescence_proved=false`, say
  what it is not.
- The four scope names are printable ASCII without `<`, `>` or `&`. Go's
  `json.Marshal` builds the scope advisory-lock key for Enqueue, grant
  mutation and this lane, and HTML-escapes those three characters (and
  U+2028/U+2029). The receipt guard builds the key with `array_to_json`, which
  does not. For the allowed names both encodings are byte-identical, so the
  database-level lock serializes against the Go writers. The Go lane and the
  receipt guard both refuse any other scope name.
- Executor barrier: the disposing Core process started after the original
  `lease_expires_at`. That process cannot be the original in-process owner of
  this claim. The receipt records its start time, hostname, PID and build
  source.

The transaction writes the immutable receipt
`capacity_dispatch_abandoned_dispositions` first. The receipt holds the job, run
and scope identities, the envelope hash, the fence, the lease owner, the lease
expiry, `started_at`, the wake count, the SHA-256 of the original job and run
rows, the barrier facts, `minimum_lease_age_seconds=900`, `recorded_at`, the
issuer, the fixed reason, `historical_return='unknown'` and the effect scan.
Then the job moves to `abandoned_disposed` and links the receipt.

The database enforces all of this on its own. The receipt's insert guard
re-derives every fact from the locked rows, reruns the effect scan and requires
it to be all zero. A deferred constraint trigger refuses a commit unless the
job terminal and the run close are in the same transaction. The job guard
allows only `started` to `abandoned_disposed`, with every other column
unchanged, and makes the terminal immutable. Inserting a job directly in the
terminal state is refused. UPDATE and DELETE on the receipt are refused. A new
row-level DELETE guard on `capacity_mutation_grants` keeps future grant history
complete, so the next "no grant since start" scan cannot miss a deleted row.

**Run status.** `workflow_runs.status` allows only pending, running,
succeeded, failed and cancelled. The run is set to `failed` with the fixed error
`abandoned_started_dispatch_disposed: historical outcome unknown`, and its
`finished_at` is set to the disposal `recorded_at`. This is an administrative
close, not the original return. Leaving the run `running` would keep a
non-terminal row that nothing can ever finish. `cancelled` would claim that
someone stopped the execution, which nobody knows. `failed` matches how Core
already maps an uncertain outcome: `FinishCapacityDispatch` writes `failed` for
the `unknown` state. The fixed error text and the receipt mark the outcome as
unknown, and `result` stays NULL. After this one transition the run is
immutable, so abort, replay and retry cannot rewrite it. The queries that look
for an earlier failed run require `j.state='returned'` and an acknowledgment, so
they never treat this run as an original failed return.

The lane never re-dispatches, never claims or starts a job, never writes a
return and never moves an intent fence. It writes no intent event. The receipt
closes the job and the run, not a grant or an intent generation. Moving the
fence would also invalidate fence-bound evidence that a later lane (for example
the failed-installed disposal) must still match. The next ordinary tick has to
pass current admission and create a new job and run.

The existing state lists already treat the new state as inactive, because they
name the active states: Enqueue's active check, the `capacity_dispatch_active_scope_idx`
predicate, the claim index, `failedInstalledZeroUsefulTx` and the
migration-73/76/82 SQL checks. No list had to change, and every replay and
immutability guard continues to refuse leaving a terminal state.

`failedInstalledZeroUsefulTx` (and its SQL copies in migrations 73, 76 and 82)
keeps `unknown` jobs blocking, because their effects are retained and
unresolved. An `abandoned_disposed` job also has an unknown historical outcome,
yet it does not block. That is safe only because of the effect scan: a job is
disposed only when the enumerated ledgers, including its own Notify-window
marker, record nothing in its window. The failed-installed lane relies on that
scan. If a ledger that can carry an effect of a started job is added later, it
must join the scan, or this exclusion is no longer sound.

**Generic abort.** `POST /api/v1/ops/workflows/{runId}/abort` refuses with 409
any run that a `capacity_dispatch_jobs` row references, in any state, and its
UPDATE carries the same `NOT EXISTS` exclusion as the stale-run cleaner. It
also returns 409 when no row changed, instead of reporting `aborted`. Before a
disposal, a cancelled original run would leave the job `started` while this
lane requires the run to be `running`, and the dimension would be stranded
again. After a disposal, the run is immutable. The original run of a started
job must therefore never be aborted before disposal; this lane is its only
resolution.

## Consequences

- The blocked dimension can be released without hand-written SQL, without a
  forged `returned_at` and without deleting the job. The original start,
  ownership, fence, 32 wakes and envelope remain. The 32 wakes were folded,
  not dropped, and stay attached to the original job.
- The barrier is local. It excludes the original in-process owner, because
  that process is gone. It does not exclude another Core replica, and it does
  not undo a request the adapter or the provider had already accepted. The
  receipt and the response say so (`other_core_replicas_excluded=false`,
  `provider_quiescence_proved=false`). Before the call, the operator must
  collect provider truth separately: a read of the server, a label-selector
  listing and the action history. That evidence is outside Core and is not
  stored as proof.
- A late return from a surviving executor would now be refused, because the job
  is no longer `started`, and it would not be recorded. This is accepted
  because the barrier requires the original process to be gone. A future
  late-observation ledger would need its own ADR.
- Before calling the endpoint in production, the operator runs the same
  `abandoned_started_dispatch_effect_scan` read-only for the job, and reads
  `capacity_intents` for the dimension to confirm that no Notify-window marker
  references the job.
- The effect scan reads Core's ledgers, which were not all append-only in the
  past. Grants had no DELETE guard before migration 83, and the opt-in event
  retention can delete old intent events. A clean scan is therefore evidence,
  not proof, of no recorded activity.
- Migration 83 is forward-only. Its Down step raises, like migration 76,
  because the terminal is a permanent no-replay boundary.
- The CI census for the disposition Source workflow covers this lane:
  Postgres-backed lifecycle, refusal, stale-CAS and migration-guard tests, plus
  HTTP closed-body and authorization tests. Those tests do not run locally.

## Related

- ADR-0044 (extends: adds the operator resolution for a started job that it
  left open, without automatic expiry release or replay)
- ADR-0071 (relates-to: prestart rejection, the queued-job counterpart)
- ADR-0073, ADR-0074, ADR-0077, ADR-0083 (relates-to: disposition lanes for unknown jobs
  with a recorded return)
- ADR-0079 (depends-on this to unblock: failed-installed disposal counts
  started jobs)
- scratch: `docs/superpowers/elastic-resume-20261101/HETZNER-STARTED-UNKNOWN-PROTOCOL-DESIGN-20261102.md`
