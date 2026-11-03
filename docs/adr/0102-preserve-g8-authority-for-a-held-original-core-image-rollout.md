# ADR-0102: Preserve G8 authority for a held-original Core image rollout

**Status:** Proposed

Date: 2026-11-03

Scope: Owned operational network Guardian G9, inherited authority and a separately typed held-original Core image CAS.

## Context

A Core successor that implements ADR-0101 needs an exact new image allowance before it can replace the running Core. The existing G8 Guardian authenticates canonical G6, its boot-v2 successor and G7 as distinct historical authorities. G8 now also has original lifetime qualifications and spent recovery-budget records that a successor must preserve under their original source and standing identities.

The existing typed Core rollout admits steady, unleased capacity intents. A previously useful tail may instead remain in a draining epoch after its original retirement lost the caller return while the native VM powered off. Clearing that lease, relabelling the intent as steady or replaying the original operation would change the evidence the new Core must authenticate. An image rollout therefore needs a separate, exact admission for that held original; it does not need authority to finish its retirement.

## Decision

Add a separate G9 Source and future units. Freeze the G8 image pair and controller configuration as historical inputs, and append only the next pair to the complete pinned controller prefix. Its new member must be the actual qualified platform manifest. Change only the image pair and a new Root review in the public controller configuration; retain runtime14 and its other fields.

Keep all three existing historical authority axes and their literal field sets unchanged. Add a fourth dedicated G8 source/standing axis with a literal 25-field historical roster; the G9 standing authority has 27 fields. Authenticate G8's source, complete raw standing bytes, original unit pins, controller configuration and shared ancestry, Hub and reference fields. Never reconstruct an older schema by subtracting fields from the current one or relabel its original records.

Preserve the seven helper modules and 31 non-wiring Owner methods byte for byte. Extend only head constants, authority readers and initialization/static validation. Retain the standing prefix, original proofs, actual reference set, spent per-boot budget, controller/runtime integrity and Cold/Hub lifetimes. A new controller still needs its own full120, its owning Guardian's first15 and an independent current15/all-four observation. Historical measurements do not assert current health. Keep the bounded six-effect cutover, durable possible-send receipts and HOLD on any uncertainty; add no retry, reset, rollback or new Cold/Hub execution.

Keep the typed Core image CAS outside the network package. Preserve its existing steady admission. Add a separate closed admission for one Root-reviewed held original only: exact preregistration, retirement and uniquely joined failed run; returned and finalization-ACKed dispatch; current generation, fence, phase, native tuple and whole intent-wire hash; original policy, workflow, catalog, credential-reference and complete nonce, journal, caller, authority and transport pins. Preserve the failed original frame, including its authentic optional fourth journal record, without inventing caller200, filtering unfavorable extras or rewriting history. Require its deadlines and lease to have expired and no forward marker to exist. Every other intent retains the steady admission, and any other held frame refuses.

The qualified helper fixes that immutable original identity in Source. Supply later history, catalog, slot snapshots and native observation references through one separately Root-reviewed private admission file with an explicit expected SHA. Require a stable root-owned, single-link regular file with mode0600, bounded complete bytes, closed JSON and exact equality to the fixed original identity. Load and validate it before any API client, retain its original bytes before the first API call and pass the same object explicitly through the database and possible-send/readback checks. Fresh observations are not compiled into the qualified logic, and the late file cannot choose another original, replace a validator or act as a runtime proof setter.

Before this CAS, require the exact applied schema/history, valid index, no unresolved native mutation authority or runnable/unacknowledged dispatch, current network qualification and the exact old singleton Core. Require a fresh complete native profile observation of the exact target OFF and both surviving members running, with their original ownership, births and profile pins. Join the survivors' retained authenticated historical useful-work provenance without relabelling it as current health or requiring a new canary in the held epoch for this image-only admission. ADR-0101 separately requires new fresh business canaries before DELETE. Quiet checks retain both historical catalog UUID and logical workflow identities, deduplicate overlapping matches and reject unfinished terminal rows; their readback does not claim exclusion of external admissions. Recheck the entire held frame at possible-send and after readback; drift is HOLD. Retain one exact UID/RV/generation/spec image-and-provenance PATCH, original response custody and no retry on uncertainty.

This admission grants only that image change. It cannot call a Guest or provider, dispose a member, mutate the catalog, renew a lease or admit a retirement forward claim. The held intent and all original records remain unchanged at rollout acceptance. Only the new running Core may subsequently handle the separately authorized ADR-0101 path.

Keep Source review, exact-head CI, image/ECR provenance, schema compatibility, network qualification, Core rollout, fresh E2Es, actual forward retirement and operational A/B acceptance separate. Unknown image/configuration bindings are explicit null values in an inert proposal, with a fail-closed guard before effects. No package, approval, operational result or adoption claim follows from those proposal bytes.

## Consequences

The accepted G8 package and ADR-0100 remain immutable. A G9 package can be bound only after actual qualified release/configuration inputs exist, in acyclic order from controller configuration to Guardian Source, future units, standing and manifest. Binary Source, operational package commit, OCI index, platform manifest and image configuration remain distinct facts.

The held-original CAS is deliberately narrower than general capacity recovery. A changed or ambiguous original requires a new reviewed plan rather than a relaxed steady-state guard. ADR-0101 alone defines forward-retirement proof and authority; image or network success cannot substitute for it or for successful A/B completion.

## Related

- [ADR-0099](0099-retain-canonical-and-boot-v2-guardian-authorities-across-a-new-core-pair.md): canonical and boot-v2 authority inheritance.
- [ADR-0100](0100-preserve-g7-network-authority-before-a-scheduler-fix-core-rollout.md): immutable G8 pair and separately typed steady Core rollout.
- [ADR-0101](0101-finish-an-authenticated-partial-poweroff-with-a-separate-native-forward-proof.md): separate useful-tail forward-retirement authority.
