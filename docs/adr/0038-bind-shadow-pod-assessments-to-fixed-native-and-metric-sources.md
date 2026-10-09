# ADR-0038: Bind shadow pod assessments to fixed native and metric sources

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / fixed source assessment for reserved pod envelopes

## Context

Capacity intent validation cannot establish the provenance of arbitrary
workflow-supplied metrics or snapshots. Complete provider VM membership also
cannot be compared with a pod reservation count, readiness or a healthy floor.
Native HPA and metric adapters already expose bounded source observations.

## Decision

Add optional operator-owned assessment bindings to capacity policies. Each
binding pins exact active instance/type UUIDs and checksums. Each declared signal
has one fixed metric binding name and fingerprint; no caller query, provider
selector, sample, readiness flag or assessment enters the bound operations.
The exact protected workflow internally resolves, verifies and calls the actual
adapter catalog through the existing hydration/health/Describe/transport path.

The initial snapshot mode is `native_hpa_minimum_v1`, with explicit unit and policy
dimension `reserved_pod_envelope`. It measures native HPA `minReplicas`, together
with exact HPA/Deployment UIDs, resource versions, owner, tracking and bounds.
Current/desired replica counts are not warm capacity or workload readiness.
Require one fixed profile, every declared metric signal and no VM mutation
bindings. The physical-slot ledger cannot interpret the HPA minimum as VM count.

Expose `capacity.observe_bound_assessment` and `capacity.assess_bound`, accepting
only an active logical policy selector. The former emits the typed diagnostic
assessment; the latter persists a shadow intent through the existing authority
store. Binding/hash/UID/owner/version/schema mismatches refuse the observation;
missing/stale/partial/non-finite metric quality produces a diagnostic hold.
Required data is never synthesized as zero. Native/metric reads remain non-atomic.

Require `execution_enabled:false` for this mode. Existing caller-supplied
assessment/claim/advance/recovery operations cannot reinterpret a bound policy;
only existing intent readback remains available there. A separately implemented
protected fixed executor and real readiness/canary/drain producers must precede
any activation. HPA remains the sole fast loop for replica counts.

## Consequences

Existing unbound policies keep their contract. The new source path is an
incremental gate, not completed elasticity or live qualification. The approved
PromQL binding still needs honest source timestamp semantics and expected roster
guards; collector coverage alone cannot prove every target exists. No provider
cost, stock, native node membership, application readiness, healthy N-1 margin,
canary, drain or provider continuity follows from this assessment.

Remote CI compiles the exact reviewed metric and HPA adapters and exercises their
actual source functions/API decoders through Core's protected transport and real
PostgreSQL. Missing producers and skipped required cases fail the gate. Simulated
native API source integration is distinct from live infrastructure evidence.

## Related

- [ADR-0034](0034-persist-bounded-capacity-intents-under-protected-workflows.md)
- [ADR-0037](0037-produce-native-vm-proofs-through-fixed-protected-observers.md)
- [Bound source assessments](../features/capacity-bound-assessments.md)
