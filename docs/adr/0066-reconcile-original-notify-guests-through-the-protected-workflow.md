# ADR-0066: Reconcile original Notify Guests through the protected workflow

- **Status:** Proposed
- **Date:** 2026-10-21
- **Scope:** Core scheduled original AWS/Hetzner Guest capacity

## Context

The durable capacity dispatcher accepts the reserved-Pod HPA graph. Original
Guest provisioning, Notify creation canaries and retirement have independent
source-owned protocols, but no complete scheduled workflow connects them.
Reusing an HPA step or accepting an assessment, healthy flag or provider tuple
from schedule inputs would create a second authority for these originals.

## Decision

Add an explicit optional `guest_notify_reconcile_binding` outside the protected
ProfileManifest. Admit only its exact seven-step graph through the existing
durable pre-start dispatcher and generic authenticated workflow runner. Add the
literal `capacity.plan_original_guest` and `capacity.complete_original_guest`
operations to the owning workflow validator and executor. Preserve the existing
original provision, retirement and finish operations as visible graph steps.

The planner reads exact bound metric evidence and the complete native VM slot
inventory. It joins only already-recorded original tuples, enrollment and
installation. It may select one missing slot or one unprotected retiring slot
within a separate provider's floor 1, ceiling 8, step 1. Native presence cannot
adopt a tuple. Missing demand remains unknown; the existing explicit floor
repair branch alone may create the first member from a complete empty native
inventory. Promotion and ordinary capacity changes keep strict real metrics.
Require a separate fixed reporting-member metric binding outside demand rules.
Its complete window's value/minimum/maximum must equal the current native member
count. Partial reporter aggregates cannot drive capacity or retirement. Missing
coverage is permitted only with independently complete native membership zero.

Completion has no caller assessment, healthy, inflight or proof input. Recheck
the current policy/workflow, original generation/fence/executor/lease, native
membership and fresh signed Notify publication/consumer returns. Retirement
also requires the stored V2 quiescence chain, original HTTP acknowledgement,
confirmed destroy grant and original native absence readback. Stable epochs
use the existing separate one-use Notify maintenance ledger, without a VM
lease or provider grant.

Use the dispatcher's existing maximum five-minute claim only for this distinct
Guest graph; retain its 90-second HPA default. Clip shorter binding budgets to
the original claim. After the capacity claim, subtract the whole original PG
transaction round trip from its remaining lease and capture one private local
monotonic deadline for the actual workflow invocation. Every later original
Guest step inherits it; no step, lease renewal, 420-second provisioning cap,
five-second canary or retirement call can restart the original deadline.

Keep unknown, in-flight and unresolved originals in HOLD. Later scheduling may
read them but cannot replay, adopt, delete, infer cancellation or acquire a new
epoch from elapsed time. Existing explicit recovery protocols remain separate.

## Consequences

The same scheduler can run two independently fenced provider workflows without
converting HPA authority into VM authority. Default compiled production
approvals remain empty until independently supplied. This source change does
not populate a registry, create a policy, install metrics or activate a fleet.
The protected ProfileManifest and its approval digest remain byte-identical.

Metrics, current native inventories, useful membership and retirement evidence
remain distinct. A fresh scrape does not replace a fresh original business
return. A first creation may remain held until real demand coverage is complete;
no zero or caller readiness is substituted. Owning Linux/PostgreSQL and complete
production source approval are separate release requirements.

## Related

- ADR-0044: durable pre-start capacity dispatch
- ADR-0060: original provider lifetime per workflow invocation
- ADR-0063: fresh original Notify canaries
- ADR-0064: separate production retirement clock owners
- ADR-0065: original provisioning clock transfer
