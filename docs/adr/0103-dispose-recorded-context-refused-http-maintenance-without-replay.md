# ADR-0103: Dispose recorded context-refused HTTP maintenance without replay

- **Status:** Proposed
- **Date:** 2026-11-03
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / recorded failed maintenance dispatch accounting
- **Supersedes:** — (extends ADR-0096 with a distinct class; its Decision remains unchanged)
- **Superseded by:** —

## Context

An ordinary single-member maintenance publication can return a failed workflow
before its dispatch lease expires while its original caller context has been
canceled. Its persisted seven-step result records a capacity-boundary refresh
and an original HTTP-or-return refusal. The possible send, nonce and held return
remain historical originals; a held return with no Guest wire proves neither
business success nor absence of a business effect. A policy republish can also
leave the installed member preregistered under an older continuous policy while
the current canary pins the current version, as admitted by ADR-0094.

ADR-0096 deliberately accepts a different deadline-only, exact-policy case. Its
false guards cannot become true by reclassifying the error, copying policy IDs,
fabricating an ACK, replaying a publication, or restarting Core solely to create
a process barrier. The database and repository must distinguish this additional
accounting decision from the old one.

## Decision

Add a separate immutable `capacity_dispatch_http_maintenance_dispositions`
receipt and `http_maintenance_disposed` terminal under migration91. Add no job
column: the full original job PG JSONB shape stays unchanged. A receipt binds
its original job/run SHA, original updated_at and return time, exact current
stored member-set digest, closed effect scan, issuer and server-owned later
Core process identity. Only the job state and updated_at may change; all six
old disposition pointers remain NULL, the original finalization ACK remains
NULL, and all original errors, workflow and canary rows stay byte-identical.
Use UTC consistently for PG whole-row hashes and reconstruct the original job
with the receipt's retained updated_at when verifying historical readback.

The separate named-human/GodMode/CSRF-gated POST/GET route uses the same strict
nine CAS expectations as ADR-0096. Under scope, job, workflow, catalog, intent,
slot and grant locks, require a genuine UNKNOWN recorded failed return before
its original lease, the same exact context-refused error in return/finalization/
workflow, and the exact seven-step ordinary refresh shape: capacity_boundary,
slot zero with no owner/request, fresh_original_canary/original_HTTP_or_return,
and no provision/retire/completion execution. Require the same stable unleased
current epoch and original active catalog pins. No in-flight disposal, forward,
reconcile, recovery or degraded marker is admitted.

Admit only one installed slot1 member and one complete steady-useful publish
challenge with its nonce, possible send and held NULL-wire return. Original
window/deadline limits remain strict; all effects outside this closed canary
class remain zero under the existing enumerated scanner. The member's tuple,
workflow, generation, fence, undisposed confirmed create, enrollment and install
must match. Only policy revision may differ: require complete ADR-0094 continuity
through every still-stored intermediate version. SQL independently derives a
stricter raw complete-contract projection and row lineage; Go must run
the existing complete typed validator in the same transaction. The SQL raw
projection/equality and structural gates are not a second implementation of
all Go validators, typed hashes, bootstrap checks or registry admission. Missing, ambiguous, malformed or discontinuous contracts
refuse. No caller-supplied boolean or digest asserts continuity.

Keep the database age of at least900seconds after the old lease and require a
real disposing Core process that started after expiry. The insert guard and
null-safe deferred receipt/job link require the one atomic transition; the
terminal, receipt and whole original workflow then become immutable. State
alone is never sufficient terminal evidence. The existing active-job predicates
may release the dimension only after this exact receipt exists.

If a qualified product upgrade is necessary to supply the new route, its own
separately reviewed operational admission may retain an exact old UNKNOWN as
HELD. Such admission reports total/held/unrelated counts honestly, rechecks the
immutable original and all other activity, and permits only migration/network/
image maintenance. It is neither a terminal receipt nor steady/no-busy proof;
it cannot authorize a policy publish, workload replay or provider/Guest action.
A later qualified process must satisfy every actual disposition guard anew.

## Consequences

- Migration87, its table, functions, route and criteria retain their meaning.
- This class refuses arbitrary workflow failures, other canary stages, accepted
  or late effects, multiple members/candidates, changed epochs and pending native
  authority. It does not confer usefulness or quiescence.
- Lost response recovery is GET-only. Every POST is a new once-controlled action;
  the old Guest publication, nonce, send, return and ACK are never reissued.
- The next ordinary tick must independently satisfy current admission and all
  permanent publication budgets. Final scaling proofs remain separate.
- Schema91 is forward-only. Tests use isolated real PostgreSQL16/17 and declared
  storage histories; they provide no native Guest/provider qualification.

## Related

- ADR-0094 (depends-on: complete installed-member policy continuity)
- ADR-0096 (extends-with-separate-class: preserves its exact failed-refresh lane)
- ADR-0090 (depends-on: enumerated effect scanner)
- ADR-0101 (relates-to: pending forward authority remains a separate boundary)
