# ADR-0079: Dispose failed installed Guests through original retirement

- **Status:** Proposed
- **Date:** 2026-10-25
- **Deciders:** Capacity platform maintainers
- **Scope:** Core / original Notify Guest lifecycle
- **Supersedes:** —
- **Superseded by:** —

## Context

An original native Guest can be installed and have acknowledged failed readiness attempts, including publications with real business effects, without ever earning useful capacity. The normal retirement floor correctly protects useful members. The enrolled-but-uninstalled failure lane cannot represent this state.

## Decision

Require an explicit administrative request identifying the immutable preregistration and its last acknowledged failed run. The backend admits only a single installed first native, with the same original policy, enrollment and lifetime, an expired lease, no useful accepted read or promoted generation, no other member and no other active epoch. Keep admission, scheduled claim, quiescence and terminal records append-only in a separate ledger.

The existing scheduled workflow consumes the admission and takes a new fence and original lease. Reuse its original retirement protocol, writer withdrawal/drain and actual poweroff. Normal production uses V2. An explicit backend-derived `legacy_guest548_original_v1` mode is restricted to Guest548 and the two complete historical contracts authenticated by compatibility map557; no workflow or HTTP input selects it. Those installed binaries expose genuine flat V1 DTOs but their closed decoder refuses anonymous V2 intents. V1 retains its signed four-record journal, actual source caller200 and bounded30s UTC authority/snapshot checks. The actual new Core issuer remains in its immutable context and audit77; stable48888 remains only the enrollment wire authority. Neither V2 kernel clock nor V2 quiescence is claimed for this legacy mode. A separately authorized operator then performs exact-lifetime native cleanup; Core calls the existing closed GET-only native inventory transport to prove complete native and auxiliary absence. Normal provider protected-slot destroy guards are unchanged. A protected-slot exception is derived inside these transactions from the exact admitted zero-useful-capacity state; a caller cannot supply a reduced floor. Disposition neither asserts zero effects nor changes prior creates, installations, workflow failures, ACKs or canaries.

Close through a distinct disposed-failed-installed terminal after the actual native and auxiliary absence is authenticated and the exact single native slot is tombstoned. Keep the original generation unpromoted. Block both a new assessment and native creation until a different Guest Source and profile are approved by the current compiled complete contract and the disposal is terminal. The normal protected floor remains unchanged for all other paths.

## Consequences

This narrow lane does not dispose a previously useful, mixed or multi-member fleet. Unknown retirements remain held and cannot be replayed. After either real versioned retirement, an acknowledged failed finish can advance only through a new bounded5s provider poweroff GET; no new Guest nonce, publication, retirement or renewal is issued. The administrative request itself never grants a provider mutation. Schema78 is required; historical schemas and signatures remain unchanged. Native lifecycle qualification and production execution remain separate from local storage tests.

## Related

- ADR-0066 (scheduled original Guest reconciliation)
- ADR-0077 (distinct enrolled but uninstalled failure accounting)
- ADR-0078 (stable protocol authority and actual issuer provenance)
