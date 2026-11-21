# ADR-0124: Review quarantines explicitly for a different manual failed-birth abort

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity authority / explicit human never-admitted birth disposition
- **Supersedes:** —
- **Superseded by:** —

## Context

ADR-0123 preserves a redeemed uncertain abort and its original unacknowledged result seed through a separate administrative quarantine. Ordinary work for other UIDs can disregard its validated active blocking effect, but the original manual abort and unredeemed recovery contracts still require zero raw scope uncertainty. A later, different failed and deleting never-admitted Pod can therefore block ordinary reconciliation while its legitimate manual disposition remains unavailable. Neither ignoring that Pod, inventing a successful SDK witness, nor rewriting the old uncertain command is safe.

## Decision

Propose an additive, explicitly selected human-only reviewed-quarantine abort schema and original-return protocol. Keep legacy v1 abort/recovery/quarantine bindings and raw-zero proofs unchanged. A literal one-step manual workflow binds the named human, policy/generation, exact different native target and compiled adapter, a distinct confirmation, and the entire ordered set of reviewed immutable quarantine command IDs, subject UIDs and complete record digests. No policy field or machine permission opts into this operation.

Under the existing scope → intent → global target UID → command/result serialization, revalidate each complete quarantine receipt and original parent/child/result-seed custody, including absent original results and acknowledgements. Require exact equality with every scope receipt, validated external active uncertainty zero, and all six global history counts zero for the new target. Preserve the honest nonzero raw/quarantined counts in the new proof. At redemption revalidate that same exact set and all original custody again; the only newly active command and target history may be the exact current issued command and its one immutable identity. Any added blocker or history, missing/moved/tampered receipt, later original result/ACK, or target equal to a quarantined subject means HOLD.

Retain all existing fresh failed/deleting/terminated/nonzero-exit/no-restart native identity checks, absence of admission/challenge/SDK receipt, exact finalizer ownership rules, TLS, one send, compiled Source identity, independent original adapter result and human caller transport return, fresh readback, confirmation and archive. The receipt never becomes a lane witness, a successful drain, physical capacity credit, or an original callback. No old command, receipt, identity or result seed is modified. This proposal adds no automatic failed-birth recovery and does not extend legacy unredeemed recovery to the new schema.

## Consequences

This requires coordinated Core and dedicated adapter Source qualification, but no new database schema, policy retarget or API-worker SDK change. Production selection and the exact new human binding require a separate approval after the concrete implementation and CI are reviewable. ADR-0123 and its accepted operational decision remain intact; this Proposed ADR does not supersede or activate it.

## Related

- ADR-0121 (separate never-admitted native disposition)
- ADR-0122 (unchanged legacy unredeemed recovery)
- ADR-0123 (preserved uncertain original and separately validated quarantine)
