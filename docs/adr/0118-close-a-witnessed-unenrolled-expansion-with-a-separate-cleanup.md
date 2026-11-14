# ADR-0118: Close a witnessed unenrolled expansion with a separate cleanup

**Status:** Proposed
- Date: 2026-11-14

## Context

An owned HZN expansion can retain a fully accepted, settled original CREATE and signed create witness while its protected provisioning workflow reaches the original deadline before enrollment or installation. The dispatch remains UNKNOWN with a real failed return and no finalization ACK. A protected enrolled S1 can remain healthy at floor one while the un-enrolled S2 is still billable. The original unwitnessed AWS cleanup and read-only maintenance dispositions intentionally refuse this different case.

## Decision

Add a separate closed witnessed-unenrolled cleanup admission, immutable event ledger and private fenced owner. Preserve the original migration94/95 lane and all its predicates. Admission names only the original grant and job; every physical tuple, source, epoch, deadline, settlement, witness and survivor comes from locked original records. Initially admit only the HZN slot-two expansion with a protected floor-one survivor, an actual predicate29 failed UNKNOWN return, both original windows expired, a complete accepted CREATE settlement, and no enrollment, installation, retirement or target slot membership. This admission does not identify a bootstrap cause.

Freeze only that expired preregistration against later enrollment or installation under the existing scope lock. A callback committed before admission prevents admission; admission committed first rejects the late callback. Preserve missing-parent foreign-key failures. No callback, provisioning, original workflow, lease, clock, nonce or finalization ACK is replayed or synthesized.

Use the existing scheduled workflow and its retire/finish/complete operations. A new canonical cleanup dispatch carries an optional top-level witnessed-unenrolled admission marker. The original UNKNOWN envelope and row stay unchanged. Preserve the legacy active-scope UNIQUE index for every envelope without that marker, including every ordinary UNKNOWN. A separate active-scope UNIQUE index protects marked cleanup jobs. A safe immutable marker-presence decoder includes explicit null and empty values in the marked class; the BEFORE guard refuses those invalid operands before any index exception. No caller may supply the marker to Enqueue: the private repository derives it from the exact current intent, admission, original envelope authority and canonical workflow graph.

A new dispatch guard takes the scope lock and the existing capacity intent row lock before discovering ownership. Admission, claim and terminal transitions update that intent; a separate mutable dispatch ownership row provides an additional write conflict. Repeatable-read transactions with stale pre-admission or pre-terminal snapshots must abort rather than interpret old absence as authority. Only the exact authenticated original and one marked cleanup job can coexist. A marked UNKNOWN cleanup job remains a barrier.

The new owner gets a new finite lease and monotonic fence without extending the original provisioning window. Obtain fresh signed survivor canaries, exact survivor inventory and a native dry-run destroy plan. Issue one new ordinary destroy child with empty compensation_of and a separately authenticated JSON admission link. Commit possible-send before the single native DELETE. Use the existing HZN supplier and native retirement observation operation, action checks, complete original auxiliary inventory and retained read/pending rules. The AWS sibling observer is not used. Uncertain sends, unknown actions, foreign tuples, malformed reads or incomplete auxiliary absence remain HOLD.

After the child is settled, require fresh complete S2 and paid auxiliary absence plus fresh S1 floor evidence. Append an immutable terminal event, confirm the child, close only the parent grant with the distinct witnessed_unenrolled_cleanup_closed state, and close the dispatch with witnessed_unenrolled_expansion_disposed. The exact original SETTLED grant and UNKNOWN dispatch must reconstruct from the frozen preimages; all SDK, witness, preregistration, run, error, return and ACK fields remain unchanged. No nullable column is added to legacy grants or jobs.

Keep the terminal intent unleased and HOLD. A later compatible ordinary policy may adopt the same survivor roster only through fresh read-only reconciliation and current admission. The original desired expansion is historical failure, not a reason to force another CREATE. Historical terminal validation uses retained proof, while each later epoch still requires its own evidence. Down refuses any used new proof and otherwise restores the exact prior catalog and index definitions.

## Consequences

This adds one narrowly authenticated recovery lane rather than broadening UNKNOWN handling or the old unwitnessed cleanup. It creates no new workflow, adapter operation, queue, dependency, process-start barrier or 900-second rule. It does not lengthen the original 300-second window or assert provider quiescence, successful Guest bootstrap, accepted useful S2 reads, savings or a completed cycle.

Required evidence includes both PostgreSQL majors and races within the existing owning root and budgets, real original Finish UNKNOWN behavior, callback/admission races, both repeatable-read orders, the post-parent-terminal active child, spoofed marker refusals, single-send custody, exact original preimages, protected S1 and whole catalog/Down parity. Declared provider and signing fixture operands are labeled; Source fixtures do not substitute for native acceptance.

## Related

- ADR-0094: Guest policy-lineage continuity.
- ADR-0106: accepted unwitnessed expansion cleanup.
- ADR-0117: the separate prepared-only read-only maintenance disposition.
