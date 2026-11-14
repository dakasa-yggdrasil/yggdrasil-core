# ADR-0117: Dispose an expired prepared-only maintenance nonce failure

**Status:** Proposed
- Date: 2026-11-14

## Context

A real original maintenance dispatch can prepare one signed publication challenge, fail while acquiring the Guest nonce, and retain a failed deadline-exceeded workflow with UNKNOWN dispatch state and no finalization ACK. The original may contain no persisted Guest nonce, possible-send or return. This differs from the migration87 signal-evidence failure, migration91 recorded HTTP context refusal and migration104 superseded-policy PUB/READ pair. Those earlier predicates must continue refusing their unsupported operands.

The current nine-field unknown-maintenance administrative operator already preserves the original failure, enforces a genuine later Core process and 900 seconds after lease expiry, and records an immutable 17-column receipt. Its Go scan decoder accepts the existing common ABI. A new runtime, terminal state or operator route is unnecessary for a separately proved SQL subtype.

## Decision

Admit only a new closed prepared-only nonce-acquire proof through the existing migration87 administrative operator. Preserve its nine-field CAS request, scan schema, receipt reason, terminal state, 17 receipt columns and all old Go/SQL entry points. Add a Goose105 companion that selects this strict subtype before the byte-identical legacy87 scan fallback. Keep the original result/member predicates and every historical migration file unchanged.

The subtype requires the exact seven-step failed refresh result: capacity_boundary, no mutation step executed, fresh_original_canary/nonce_acquire, HTTP status zero, and matching original job/run deadline-exceeded errors. It requires one authentic signed prepared PUB for the stored S1 incarnation and current stable epoch, its atomically recorded authority issue, and zero Guest nonce, possible-send and return rows. Retain the nonempty Core preflight nonce hash; it is not a Guest nonce or an accepted publication. All provider/mutator authority remains refused; only the existing row-proved assessment and observation-refresh bookkeeping is tolerated.

Authenticate S1 through its own confirmed CREATE, preregistration, enrollment, installation and exact physical tuple. Apply ADR-0094 policy continuity from its birth policy to the exact unique latest active original dispatch policy. Policy version is not generation: birth generation/fence is checked against its CREATE, not forced equal to a later current epoch. Preserve all workflow, authorization, current intent, scope, lease and effect-scan barriers.

Archive a closed subtype proof containing original dispatch/run/policy/intent, the five membership rows, original prepared challenge, authority issue and complete policy lineage. Its pure validator reads only retained JSON preimages and immutable policy projection logic. Receipt bindings, original run hashes and finalization uncertainty remain immutable. Historical GETs do not re-evaluate a future catalog or membership.

Serialize receipt admission and late nonce/send/return inserts using the existing canonical capacity scope advisory lock. A used archived challenge permanently refuses those later local rows. Keep missing-parent foreign-key behavior. The original fresh-process and 900-second rules remain unchanged; this does not prove exclusion of every Core replica or remote nonce issuance.

A companion migration must deliver file105 explicitly. The unchanged Goose v3.27.0 entrypoint can then start against DB105 with local files through104 without downgrading; exact CI must demonstrate this ABI before operative use. Down refuses any used subtype and otherwise restores the exact schema104 function/catalog boundary.

## Consequences

No original workflow, return, ACK, nonce, deadline, clock or provider write is replayed, reset or fabricated. This is an administrative terminal, not Guest success, provider quiescence, useful-capacity or a completed cycle. A subsequent ordinary tick must satisfy fresh current admission. Existing migration87/91/104 fixtures and negatives remain required. Current Source and declared mature-history regression evidence are separate; a declared fixture is not a live 900-second journey or native acceptance.

The running Core15 Go/API and Ops host pair need no replacement solely for this SQL change. A qualified Source/companion, both PostgreSQL majors, races, complete catalog/history and actual whole native proof remain necessary. Counts alone do not establish native eligibility.

## Related

- ADR-0094: preserve Guest policy-lineage continuity.
- ADR-0096: original unknown-maintenance disposition.
- ADR-0103: recorded HTTP-maintenance disposition.
- ADR-0116: superseded equivalent-policy maintenance disposition.
