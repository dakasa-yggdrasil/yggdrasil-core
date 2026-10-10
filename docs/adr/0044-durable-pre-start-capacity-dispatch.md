# ADR-0044: Admit capacity schedules through durable pre-start ownership

- **Status:** Proposed
- **Date:** 2026-10-10
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / protected reserved Pod capacity dispatch
- **Supersedes:** —
- **Superseded by:** —

## Context

A schedule records its tick in PostgreSQL before starting a goroutine. A process
failure in that gap loses the invocation. Replaying arbitrary pending or running
workflow rows cannot close the gap safely: an old pending row with no start time
does not establish that the original call never happened. Protected capacity
workflows also require an authenticated operator delegation; a cron or an alert
is demand and cannot supply that authority.

The fixed native HPA executor already owns measurement, hysteresis, native
command redemption, lifetime admission and controller-selected retirement. The
missing component is an installed consumer that admits scheduled demand into that
original executor without restoring caller-supplied proofs or replaying uncertain
effects.

## Decision

Use an independently default-off `capacity_dispatch_prestart_v1` protocol for a
scheduled, single-step `capacity.execute_bound` workflow. Its persisted capacity
policy declares `controller_binding` with an exact machine principal and a finite
5–90 second invocation budget. It requires one reserved Pod profile and the
existing bound assessment and HPA lifetime executor; it does not authorize native
VM mutations. The process switch is `YGGDRASIL_CAPACITY_DISPATCH_ENABLED=true`.
Existing execution and admission switches remain separate gates.

Register one private in-process service in the existing HTTP server. Both the
scheduler and the owned worker delegate to this service. It resolves the persisted
binding and the existing loaded machine inventory, and calls the same
`authorizeWorkflowDispatch` kernel used by machine HTTP dispatch: current
allowlist, expiry, rotation fingerprint, RBAC, optional authorization policy and
emergency lock. ADR-0022 still defines inventory lifetime; this does not introduce
an external live credential refresh. No public route, alert body or workflow input
can install the private service, actor, source pin, lease or native transport
policy. Typed graphs containing a normalized `yggdrasil` `capacity.*` operation
require this owner even when a current policy binding is absent, removed,
tombstoned or purged. The same classifier serves admission and the missing-owner
cron path; it supplies refusal, never delegation. A process switch, missing
inventory or denied RBAC cannot restore actorless fallback by removing the
binding. Unrelated workflows retain their existing path.

The original schedule transaction commits the tick, original redacted pending
`workflow_runs` row and dispatch job together. Store exact logical dimension,
source tick, workflow/policy/RBAC/authorization pins, closed policy-selector
inputs, server metadata hashes and a principal/binding fingerprint. Do not store
a bearer, credential digest, source measurements, product payload, recipients or
caller authorization. At most 32 distinct tick keys coalesce into an active job;
saturation rolls back the tick instead of dropping it or changing the first
invocation's pins. These records reference the original run and are private
control records, never native grants or useful-capacity receipts.

Only a newly admitted v1 queued job with no possible-start marker and an original
pending run is claimable. A database lease and monotonically increasing fence
identify its owner. An elapsed pre-start claim can be reclaimed; legacy rows are
never adopted. Persist the possible-start marker and original running status
before crossing the original `RunWorkflow` call. A crash after that marker,
including the gap before invocation, remains an explicit hold. Neither expiry,
a new tick nor the generic stale-run cleaner releases or replays it. Existing
native step recovery remains read-only observation of the original attempt; the
worker does not resume a started workflow.

Copy the original claim deadline once, shorten it by the operator budget and
principal expiry, and never renew it. Recheck original run/envelope/catalog,
claim fence and the same current authorization before and after native reads and
writes, as well as before invocation and after its actual return. Execute the
original fixed source readers and native command/lifetime ledgers. The resolved
execute entry point explicitly consumes the private native transport policy for
both reads and mutators: original child/parent context and fixed deadlines,
bounded response Read, observed body Close, fixed catalog endpoint and refusal
of redirects. Installing the context alone is insufficient because that entry
point bypasses the ordinary transport `Call` method. Unrelated calls without the
private dispatch keep their original transport behavior. An old alert or
assessment is never evidence for a new decision.

Keep original source errors in the private invocation and return their opaque
chain from the actual owning `RunWorkflow` into `RunOne`. Preserve `errors.Is`
and `errors.As`, including a source deadline that expires while the parent
remains live. Workflow step DTOs, persisted results, events and formatted/JSON
errors retain generic categories without source URL, hydrated credential or raw
cause. The public typed failure remains failed. Child cancellation/deadline is
uncertain and cannot release the original dimension or authorize a replay.

Finalization distinguishes three facts. The original Go function actually
returns; the first PostgreSQL finalization transaction actually returns to the
owner; the owner records its observed first acknowledgment under the original
deadline and current authorization. `returned` with no `finalization_ack_at`
continues to occupy the unique dimension index and admission lookup. It cannot
admit a second invocation during a held or uncertain first Commit response.
Cancellation, late return, changed pins, typed unknown or a failed release fence
keeps the dimension blocked, preserving a factual original return separately.

A second transaction records the already observed first acknowledgment. A late
or lost response to that recording transaction is not evidence of worker return
or product SDK return, and is not rewritten as an unobserved first acknowledgment.
Its native readback may show the prior fact. A job's succeeded status, PostgreSQL
Commit or worker context cancellation never certifies product completion,
provider quiescence or fully drained external resources. Unknown downgrade CAS
failure cannot be reported as a successful downgrade; the unacknowledged returned
row itself remains active until a truthful source-owned acknowledgment exists.

## Consequences

The worker has a bounded catalog roster (64 realm/environment scopes) and four
owned calls. Cancellation joins those calls; it does not impersonate their
return. More scopes, invalid pins and missing broker availability fail closed.
This cut closes durable scheduled admission and original HPA executor consumption.
Heimdall alerts can subsequently wake the same consumer but cannot become actors
or native evidence. No alert consumer is claimed by this decision.

Started or unknown jobs intentionally require observation/operator resolution;
this protocol offers no blind resume, uncertain replay, automatic expiry release
or history deletion. Exact tick dedup keys remain retained. Any future retention
or resolution policy must preserve the immutable original pins and actual-return
facts. State remains distinct from existing native command, grant and lifetime
ledgers, whose own uncertainty and terminal gates still apply.

CI combines native PostgreSQL cases exercising the original addon cron with a
native KinD case exercising the same real private service, worker, original Core
executor, adapter main and pinned SDK fixtures. Both paths use production
migrations and preserve the existing case censuses. Actual dispatched TLS cases
exercise the original bound execute through its Read/Close, 307/308 refusal,
2 MiB byte cap and original 35 second source timeout before the 90 second owner
deadline. The same remote cron covers absent/removed/tombstoned delegation with
a live broker plus process-off, absent inventory and denied RBAC; an unrelated
legacy control exercises its unchanged path. They do not claim that cron,
HTTP and KinD ran in one whole-Core-main process. Dockerfile qualification remains
a separate existing gate. Source cases are not evidence until remote CI passes.

Reserved Pod envelope is still a reservation unit. Guest/bootstrap/warm capacity,
continuous original business canary, product SDK caller return, real routing,
full provider drain/quiescence, native economical provider lifecycle and billing
remain independent requirements. This decision cannot be used to report elastic
production, useful VM capacity or implementation completeness across all services.

## Related

- ADR-0015: original workflow input preparation and redaction.
- ADR-0017 and ADR-0022: machine actor scope and loaded credential ownership.
- ADR-0027: protected dispatch requires an authenticated actor channel.
- ADR-0034 and ADR-0036: capacity leases and single-use native mutations.
- ADR-0038, ADR-0040 and ADR-0041: fixed measurements, lifetimes and birth guards.
- ADR-0042 and ADR-0043: diagnostic native membership and original business reads.
