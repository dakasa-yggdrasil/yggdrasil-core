# ADR-0123: Quarantine one uncertain never-admitted native abort

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity authority / original never-admitted native birth
- **Supersedes:** —
- **Superseded by:** —

## Context

A redeemed sequence-2 abort removed its original Pod, but the original result callback reached a plaintext backend behind a TLS-terminating frontend. Core correctly refused the callback because the original-result protocol requires backend TLS. The original invocation failed; its command remains uncertain, with an unacknowledged result seed. Native absence cannot reconstruct its original HTTP return or SDK joins. Scope-wide uncertainty correctly blocks ordinary future native work, including unrelated new Pod UIDs.

## Decision

Add a separate append-only administrative quarantine receipt for a named-human, synchronous, literal-bound operation. Keep the original sequence-2 command HOT and uncertain, its request/identity/deadlines/attempt and result seed/NULL acknowledgements unchanged. The receipt is not a native result, success, refusal-before-redemption, archive, lane witness, physical-capacity credit or third authority.

Under existing scope → intent → global UID → command/result serialization, require the exact retained parent/child pair, full raw-body custody, expired authority and lease, the expected nonzero redemption, no callback result/ACK, no global lifetime/admission history, no foreign/orphan command identity, and a fresh authenticated GET proving the original name is absent. Refuse a same-name replacement. Store the complete administrative receipt with a canonical digest in a dedicated immutable table. Existing permanent UID identities continue to forbid registration or mutation for the original UID in every generation and scope.

Ordinary work for other UIDs may disregard only the active blocking effect of this separately validated receipt. Preserve the raw ledger and explicitly expose raw-unsettled, active-unsettled and quarantined counts. Revalidate all scope receipts independently of HOT row enumeration: missing/moved/tampered custody, or any later result/ACK, means HOLD. Generic unknown-command, drain, result-confirmation and archive rules remain unchanged. Existing abort/recovery proofs still require zero raw scope-unsettled commands; a future different-UID administrative abort therefore remains HOLD while this raw unknown is retained. This change adds no adapter ABI or future automatic failed-birth recovery.

Require backend TLS before redeeming a nonempty original-return protocol, as well as for its result callback. Forwarding headers never establish backend TLS. A terminating frontend must re-encrypt and verify the actual Core TLS backend; Native CI qualifies that real transport path in addition to direct TLS.

## Consequences

This requires one Goose migration and authority Source qualification, but no adapter ABI change, credential change, API-worker image, policy retarget, fabricated joins or native mutation. The held operational binding is only the reviewed original49/parent/child tuple. Activation is a separate human decision after Source review and CI; this does not authorize a production quarantine, WAL disposition or scope release. There is no automatic quarantine or generic self-healing chain.
