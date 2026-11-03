# ADR-0100: Preserve G7 network authority before a scheduler-fix Core rollout

Status: Proposed

Date: 2026-11-03

Scope: Owned operational network Guardian G8, inherited authority and separately typed Core rollout.

## Context

A new immutable Core image needs a new pair allowance before its Pod can replace the current image. G7 already authenticates canonical G6 and its cross-boot successor independently. Replacing a historical pair or reusing a prior lifetime's qualification would either reject valid old records or erase their recovery-budget meaning. A later ops commit must also retain the already qualified Core source/image provenance.

The generic control-plane renderer is not a substitute for an exact live Deployment CAS. A successful readiness/readback workflow is not image, migration, host-network or release qualification.

## Decision

Add a separate versioned G8 Source/package and pin the old G7 image/config as history. Derive the next controller configuration from the complete pinned prefix, changing only its image pair and a new Root review. Keep runtime14 and the six other configuration fields unchanged. Canonical G6, boot-v2 and actual G7 source/standing pairs are three distinct closed authority axes, with literal historical field sets independent of the current schema.

Preserve the seven helper modules,31 existing Owner methods, historical standing prefix, all original records/references and the same per-boot recovery budget. Extend only the new head and authority initialization/static validation. Historical full120 remains historical evidence; a new physical controller needs its own original120, its owning Guardian's first15 and an independent current15/all-four observation. Cold/Hub lifetimes and kernel/transport rules remain owned and unchanged.

Keep runtime10 and operational tools4 integrity rosters separate in the21-member network package. Source/ops commit identity, Core release commit, OCI index, selected platform manifest and image config remain distinct. An ops commit binds the previously qualified Core image without rebuilding or retagging it. The package requires exact final CI and fresh reviewed native preimages before stage or cutover.

Use only the bounded one-forward-attempt cutover with original native receipts, exact unit/config CAS, fresh TTL and process identity guards, inherited reference/budget checks and HOLD on uncertainty. Do not add automatic rollback, reset, replay, arbitrary digest selection or a new recovery authority. Cold's successor file is for future boot use and is not executed during the pair swap.

After native G8 acceptance, a separately versioned typed Core CAS outside the network package may replace only the exact live core container image and explicit provenance annotations. It retains full UID/RV/generation/spec preconditions, schema/index and scoped quiet checks, one PATCH and original response custody. The busy-run query preserves both catalog UUID and logical identities and unfinished terminal rows while exposing their existing index paths through a distinct run-ID union. A quiet observation does not claim admission exclusion. Actual rollout, health, E2E and useful-work acceptance remain separate Root gates.

## Consequences

The G7 source, package, helpers, ledger and accepted proofs remain immutable. Each later pair needs concrete immutable release/config inputs and final source/CI review. Operational success cannot be manufactured from a historical receipt, a workflow skip, metadata registration or a PATCH ACK. ADR-0099 remains a separate decision for G7 and is not rewritten by this successor.
