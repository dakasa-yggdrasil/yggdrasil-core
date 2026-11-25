# ADR-0125: Retain permanent native quarantine across logical policy revisions

- **Status:** Proposed
- **Date:** 2026-11-25
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core / immutable native abort quarantine origin and logical policy succession
- **Supersedes:** —
- **Superseded by:** —

## Context

An explicitly approved permanent quarantine keeps one redeemed abort uncertain,
including its original request, deadline, result seed and NULL acknowledgements.
Its active blocking effect is excluded for other native UIDs only after complete
receipt revalidation. Validating that receipt against a later policy revision
incorrectly compares the old immutable binding with new policy and physical
identities, making the permanent decision unusable after a normal migration.

## Decision

Load the immutable original capacity policy identified by the retained quarantine
binding, including an inactive revision, under the existing transaction. Require
its exact checksum and run all existing receipt, binding, original parent/child,
result-seed, identity and lifetime-history validation against that original policy.
Missing or tampered original policy custody remains a refusal.

Permit this validated receipt to exclude its existing active blocker for a current
policy only when the logical policy namespace/name, environment/domain/dimension,
workload namespace/name, HPA name, owner/profile, snapshot mode/unit, normal
workflow and admission logical references, adapter principal, container and native
admission binding/mode remain identical. Physical UIDs, images and catalog pins
may change with the current policy; they never replace the original receipt's
binding or authorize a mutation for its permanently denied UID.

## Consequences

No receipt, command, result, ACK, deadline, schema or authority is rewritten. Raw
uncertainty and the original permanent UID deny remain visible. A different
logical scope cannot borrow the exclusion. Later results, missing bodies, corrupt
custody and additional active unknown commands still stop ordinary work. Existing
one-send and process admission guards continue to govern every new native action.
This compatibility does not settle an old command, close an Owner WAL, admit a
process, recreate quarantine, or grant execution by itself.

## Related

- [ADR-0123](0123-quarantine-one-uncertain-never-admitted-native-abort.md): preserves the permanent administrative decision and all original custody rules.
- [ADR-0124](0124-review-quarantines-explicitly-for-a-different-manual-failed-birth-abort.md): preserves explicit review requirements for a different manual abort.
