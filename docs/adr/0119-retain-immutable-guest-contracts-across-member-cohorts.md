# ADR-0119: Retain immutable Guest contracts across member cohorts

- **Status:** Proposed
- **Date:** 2026-11-14
- **Deciders:** Giomaster
- **Scope:** Core / explicit Guest contract succession and logical membership across immutable provider instances
- **Supersedes:** —
- **Superseded by:** —

## Context

A provider profile is a complete physical contract. Its image, bootstrap roster, instance identity and scope are pinned in the original create witness and Guest enrollment. Replacing a global profile can invalidate an existing protected member even when only a future slot needs a new Guest build. Treating an old instance's absence from the new binding as an empty logical slot could also authorize duplicate creation.

## Decision

Require explicit `guest_contract_successor` opt-in with schema `guest_contract_successor_v1` and immutable `retained_policy_contracts` references containing policy ID, policy checksum and complete production-contract SHA-256. Resolve those references from older stored versions of the same logical policy. Every contract must satisfy the compiled Source approval, preserve the logical owner, scope, provider, profile, workflow and slot bounds, and have its own immutable physical target. References do not become additional caller-selectable `mutation_bindings`.

Keep the current policy's scheduling, identity, clocks and fences. Derive an existing member's effective physical and Guest binding privately from its sealed preregistration, create witness, enrollment, installation and full physical tuple. Preserve that exact contract through every stored intermediate policy version. Never rewrite a Manifest spec while retaining its checksum, mutate an original enrollment or accept a workflow-supplied cohort selector. Retained contracts manage their existing members; only the current default contract can create into a logical slot proven empty across the complete authorized set under the ordinary scope lock.

Retain each original typed provider inventory separately. Validate it against its own complete contract with the existing native validator, then derive one internal logical membership snapshot. Require the whole configured set, preserve each receipt's provenance and age, count the global floor once, and refuse duplicate logical slots or physical identities, extra/unknown ownership, partial or stale returns and ambiguous stored membership. The aggregate is not a provider response or an atomic observation. Original deadlines, lease windows, mutation grants, one-send rules and native absence requirements remain in force.

A different immutable provider instance/configuration may use the same stateless adapter type and service. Keep the old instance active and unchanged for old members; use a distinct native name prefix and a qualified new image/configuration for future members. This decision introduces no adapter operation, workflow operation, provider delete shortcut, acknowledgement conversion or counter reset.

Freeze the six-contract compatibility map before appending any separately qualified approval. Retain the exact historical two-, four- and six-contract maps for their original signed authority issues. A declared successor, contract digest or new Guest build is not production approval. Source, ELF/image, instance and policy qualification remain prerequisites to activation.

## Consequences

Policies without the optional successor retain their prior path and wire shape. Existing AWS policies and provider contracts need no retarget. Member-specific canary, useful/floor proof and retirement use the member's original profile and transport references while the active policy/workflow/epoch remain current. New creation uses the current contract and cannot hide an old member behind a different instance key.

The controller must read every retained physical cohort within its original invocation budget. Missing or conflicting evidence holds the whole decision. Historical contracts cannot be dropped across a live member's policy lineage. Closed maintenance-disposition SQL contracts remain unchanged; this decision does not broaden their eligibility or imply quiescence, provider absence, cycle completion or billing reconciliation.

## Related

- ADR-0094: policy continuity for immutable installed Guest members.
- ADR-0118: witnessed-unenrolled cleanup retains the original failed expansion independently.
