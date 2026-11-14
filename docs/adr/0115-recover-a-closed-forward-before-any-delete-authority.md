# ADR-0115: Recover a closed forward before any DELETE authority

- **Status:** Proposed
- **Date:** 2026-11-12
- **Deciders:** DaKasa maintainers
- **Scope:** Core / automatic Original Guest retirement before first native DELETE
- **Supersedes:** —
- **Superseded by:** —

## Context

A live partial retirement may observe its exact native target powered off and then fail during inventory or survivor qualification before issuing DELETE. The settled-absence continuation deliberately requires an already accepted DELETE; normal-finish recovery deliberately requires a successful original Guest caller. Historical partial recovery instead requires a replacement Core process after the original clocks. None of those authorities describes an automatic retry of a closed live forward which never acquired DELETE.

Absence of a retirement DELETE binding alone is insufficient. A committed grant in another state or realm can still represent native authority. A failed workflow ACK alone also does not fence a delayed old caller.

## Decision

Add a distinct internal `pre_destroy_recovery` child admission. Under the existing capacity scope and global native-profile/slot locks, authenticate the exact failed parent run and dispatch ACK, naturally expired root context/request clocks and current parent lease, absolute latest complete positive OFF, immutable root/parent/caller evidence, current policy/workflow and full typed quiet scope. Prove that no DELETE authority exists for the current physical tuple across any grant state, epoch or realm. Preserve known different physical incarnations as history.

Append a requested child with an exact intent CAS and use ordinary claim to increment the fence and obtain its own lease. The grant writer uses those same locks and lease/fence checks: a permission committed first is visible and blocks this admission; a delayed old writer cannot obtain authority after the new claim. Keep the historical process barrier and normal/settled admission meanings unchanged.

The new owner must obtain its own fresh read-only OFF, exact inventory and survivor publications under the existing floor, useful-coverage and gap rules before its first once-only DELETE. Old OFF is lineage evidence, not fresh mutation eligibility. Preserve the pre-DELETE proof when a later accepted DELETE enters the existing read/confirm-only continuation.

## Consequences

A repeat failure after the child's own successful OFF can append another independently fenced child. A later failed or open OFF remains HOLD rather than selecting an older favorable observation. Any existing current-tuple DELETE authority closes this path; it is never disposed, expired, adopted or replayed by this admission.

PostgreSQL constraints and a closed proof validator supplement the Source-owned constructor. Existing timers, provider capabilities, public APIs and immutable original records remain unchanged. Downgrade refuses while any record carries the new proof, including a settled-absence descendant.

Same-process recovery, old-writer/new-claim races, concurrent request coalescing, all-state and cross-realm authority rejection, fresh floor prerequisites and post-DELETE continuation require owning CI coverage on both supported PostgreSQL majors. The design creates no operational qualification by itself.

## Related

- ADR-0108 (read-only continuation before its first absence read)
- ADR-0110 (separate normal successful-caller finish recovery)
- ADR-0114 (authentic closed failed absence read)
- scratch: `docs/superpowers/2026-11-12-pre-delete-automatic-recovery-design-review.md`
