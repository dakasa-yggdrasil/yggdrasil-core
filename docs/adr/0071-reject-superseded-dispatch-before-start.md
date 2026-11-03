# ADR-0071: Reject superseded dispatch before start

- **Status:** Proposed
- **Date:** 2026-10-22
- **Deciders:** Core maintainers and production operator; review pending
- **Scope:** yggdrasil-core / administrative pre-start capacity dispatch disposition
- **Supersedes:** —
- **Superseded by:** —

## Context

A durable capacity dispatch retains the exact policy, workflow, authorization,
inputs and source tick admitted with its original pending run. Replacing the
policy can make that queued job permanently unclaimable while it still owns the
logical dimension. A new tick cannot replace its envelope or infer that an old
invocation never started. Lease expiry alone also cannot release started,
unknown or unacknowledged returned work.

An explicit administrative disposition can close a superseded job only when
Core proves the original pre-start boundary still holds. This needs a separate
terminal state and audit record, without manufacturing an execution return,
acknowledgment or native capacity result.

## Decision

Expose an explicit owning administrative operation at
`POST /api/v1/ops/capacity/dispatch-prestart-rejections`, with readback at
`GET /api/v1/ops/capacity/dispatch-prestart-rejections/{jobId}`. The production
operator invokes it only after the installed Core rollout has independently
completed its required 600-second qualification. Installing the route or schema
does not satisfy that qualification or authorize invocation. Keep rejection out
of `EnqueueCapacityDispatch`, cron, demand consumption and automatic recovery.
The operation neither enqueues a replacement nor invokes a workflow.

Require the existing operations permission gate, authenticated collaborator
identity and current GodMode RBAC permission. Derive the recorded issuer as
`collaborator:<canonical UUID>` from that authenticated identity. Recheck current
operator permission and protected workflow authorization before and after the
transactional change. A machine delegation alone cannot invoke this operation.

Accept a closed, bounded compare-and-swap request containing only `job_id`,
`expected_run_id`, `expected_envelope_sha256`, `expected_fencing_token`,
`expected_superseding_policy_id`, `expected_superseding_policy_version` and
`expected_superseding_policy_checksum`. Require canonical UUIDs, lowercase
SHA256 digests and bounded integral version/fence values. Reject duplicate,
missing, null, unknown or trailing fields. These values are expectations to
compare with Core's records; they cannot assert absence, expiry, policy
activity, authorization, issuer or successful admission.

Core resolves the current policy and workflow itself, parses and validates the
policy, and prepares the current protected scheduled admission through
`CapacityDispatchService.PrepareScheduledTick`. Require its policy pin and
realm/environment/domain/dimension to match the expected replacement and the
original logical scope. This preparation supplies no new tick, run, claim or
execution. Revalidate the current protected delegation around the database
change; do not accept a caller-supplied replacement envelope or receipt.

Serialize the administrative transaction with a bounded `SHARE` lock on the
manifest catalog before other catalog/job/run locks. This excludes a later
inactive-version insertion as well as activity changes until commit. Retain
context cancellation and the original request deadline through lock acquisition,
admission checks and commit; failure or uncertainty cannot become authorization
for a retry with a new execution identity.

Allow the transition only from an original `capacity_dispatch_prestart_v1`
queued job with no start, return or finalization markers and with its lease
absent or expired according to PostgreSQL time. Lock its original run and require
pending status with no start, finish, result or error markers, preserving its
workflow selector, inputs and metadata. Verify the byte-exact original envelope,
hash and identity. The complete original policy pin must name an inactive
manifest. The replacement must be active, have the same logical policy identity
and scope, have a greater version, and be the latest version even when a later
version is inactive. Changed pins, a live claim or ambiguous state refuse the
entire transaction.

Atomically set the job to terminal `prestart_rejected`, record
`policy_superseded_before_start`, the database rejection time, authenticated
issuer and exact old/new policy IDs and checksums, and append the matching
`capacity_dispatch_prestart_rejections` record. In the same transaction cancel
its original pending workflow with no start or result, using the rejection time
as `finished_at` and the closed reason as its error. Preserve job/run IDs,
envelope bytes and hash, original lease owner, fence, source tick and wakes.
Leave all native grants, settlements and lifetimes unchanged. The record is a
truthful administrative pre-start rejection; it is not an actual workflow
return, finalization acknowledgment, provider rejection or useful-capacity proof.

Make the rejected job and its audit record immutable to updates, and prevent the
cancelled workflow from acquiring start/result markers or being revived. Keep
original wake keys and history; add no application deletion or rebasing path.
Started, unknown and unacknowledged returned jobs retain their existing holds
and cannot use this disposition. A subsequent ordinary tick requires independent
current admission and its own original identity; it cannot replay the rejected
job or reuse its original claim.

Expose the readback as a typed projection joined from the immutable rejection
ledger, original job, original workflow run and retained policy pin. Include the
old job/run IDs and exact envelope hash; terminal job state `prestart_rejected`;
workflow state `cancelled`, NULL start and absent result; NULL job start, return,
return-cause, finalization and acknowledgment markers; the retained original
lease owner, fencing token and absent or elapsed lease deadline; and the full
old policy pin (ID, namespace, name, version and checksum), alongside the exact
successor pin, issuer, reason and rejection time. Derive the never-started and
terminal facts from that owning join, not caller assertions or the word
`cancelled` alone. Reject a missing or inconsistent join. A generic cancelled
workflow from floor history cannot stand in for this typed administrative
pre-start disposition or acquire its no-replay boundary.

## Consequences

The active-scope and claim indexes continue to use their original predicates;
only the explicitly rejected pre-start job ceases to occupy the dimension.
Acknowledgment, lease ownership, start and actual-return guards remain unchanged.
The new terminal state must stay excluded from claim and execution in compatible
application versions, including application rollback.

The administrative response exposes the retained disposition as
`capacity_dispatch_prestart_rejection_v1`. A lost or uncertain response is
reconciled through its owning readback, rather than assuming that no change
committed. Rejection does not automatically permit policy activation, provider
creation, cleanup, native retries or history removal.

The catalog lock can briefly block unrelated manifest writes; the request
deadline bounds that cost and any wait fails closed. Migration 00072 retains the
terminal schema through application rollback and refuses destructive Down.
Removing or transforming retained dispositions requires a separately reviewed
forward migration. No production qualification follows from this architectural
proposal or from local source tests.

## Related

- [ADR-0044](0044-durable-pre-start-capacity-dispatch.md): refines durable dispatch resolution while preserving original ownership and non-replay rules.
- [ADR-0027](0027-require-authenticated-actor-channels-for-authorized-workflows.md): requires authenticated actor channels for protected workflow admission.
- [Migration 00072](../../db/migrations/00072_capacity_dispatch_prestart_rejection.sql): terminal schema, SQL guards, audit append and atomic workflow cancellation.
- [Administrative route](../../controllers/httpapi/ops_capacity_dispatch_prestart_rejection.go): closed expectations, server-derived issuer and current protected admission.
