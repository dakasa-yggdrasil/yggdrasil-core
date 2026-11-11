# ADR-0111: Resume installed readiness after a recorded provision timeout

- **Status:** Proposed
- **Date:** 2026-11-11
- **Deciders:** DaKasa
- **Scope:** Core / automatic dispatch disposition and installed Guest readiness
- **Supersedes:** —
- **Superseded by:** —

## Context

An original one-member Guest expansion can finish its paid provider CREATE,
enrollment and installation, then reach its original dispatch deadline while
collecting the completion assessment. The retained seven-step result records a
successful plan and provision followed by a failed `complete-original-provision`
at `source_assessment`. Finalization correctly preserves the dispatch as
`unknown`, its failed return and a missing final acknowledgement. Its expired
capacity lease does not make that history an acknowledged failure.

The active dispatch prevents another ordinary owner. Existing installed
readiness recovery requires a genuine failed ACK. Unwitnessed and enrolled
absence dispositions describe different physical states, while maintenance
dispositions require a refresh without provisioning effects. None can be
relabelled to cover an installed expansion or to assert that CREATE had no
effect.

## Decision

Admit a separate typed terminal disposition from the existing enqueue
transaction. Select only the exact recorded unknown provision-timeout result,
after natural expiry, with the original policy, intent and full current
installed roster authenticated from retained records. Require the original
confirmed CREATE, witness, enrollment and installation, the exact expansion
baseline, and no unresolved competing authority. Prove the completion refusal
occurred at `source_assessment`; a later Guest publication or ambiguous provider
operation does not satisfy this lane.

Retain an immutable
`unknown_installed_provision_timeout_disposition_v1` record in
`capacity_dispatch_installed_provision_timeout_dispositions`. Under the existing
scope lock, lock the active dispatch and its exact run/current facts before
recording the receipt and moving only that dispatch to
`installed_timeout_disposed`. Link the receipt and terminal transition in the
same transaction before a fresh queued owner can pass active-dispatch admission.
Retain the whole original unknown dispatch, failed workflow result, provider
receipts and NULL ACK as provenance. Do not manufacture an ACK, success,
quiescence, absence or a zero-effects classification.

Carry the distinct origin through the optional
`installed_provision_timeout_disposition_id` on installed readiness provenance.
Authenticate that origin separately; keep the existing ACK-based original-run
query unchanged. Omit the new field from old records. The next actual scheduler
owner receives a fresh finite fence and readiness epoch, with its own current
assessment, inventory, floor and canaries. It does not rerun provisioning,
replay an old Guest request, issue another CREATE or extend the old context,
lease or nonce. Preserve wake and failure history rather than resetting them.

Add Goose migration 98 with a distinct immutable ledger, independent proof
validation and deferred links between its receipt and terminal dispatch. Keep
the prior disposition, installed-resume and retirement contracts unchanged.
Missing new schema is ineligible, not permission to infer a receipt. Down must
fail closed when retained provenance still depends on the new contract.

## Consequences

The automatic recovery uses the existing enqueue and scheduler surface; it adds
no public endpoint or new provider operation. Current readiness remains an
independent proof and may refuse. The new terminal receipt releases a classified
dispatch hold without turning historical unknown work into an acknowledged
return or useful capacity.

All original production deadlines, bounded read limits, protected-floor rules,
mutation bindings and normal clean-cycle clocks remain unchanged. PostgreSQL
guards and the Go admission must agree on exact original bytes and complete
membership; caller assertions cannot replace either. Existing dispositions and
their negative cases remain distinct.

## Related

- ADR-0089 (preserves the separate abandoned-started disposition)
- ADR-0090 (preserves finalization honesty and lost-finalization provenance)
- ADR-0094 (preserves installed membership and ordinary readiness)
- ADR-0095 (preserves failed-installed disposal)
- ADR-0096 (preserves refresh-only maintenance disposition)
- ADR-0103 (preserves recorded HTTP maintenance disposition)
