# ADR-0055: Observe an uncertain original create and reissue its unused cleanup child

**Status:** Proposed
- Date: 2026-10-18
- Scope: compiled `nativequalification` / `guestretirementqualification` Source fixture only

## Context

An empty original creator reply proves no accepted response. The current producer retains the zero-byte EOF, its independent original QEMU observation and an `uncertain` settlement, then correctly refuses the ordinary accepted-create witness. Without actual protected enrollment and an authenticated failed payload there is no complete failed-action history; the old lost-reply cases remain negative.

A cleanup child that expires while still unredeemed cannot own effects. Reusing its attempt, restamping its failure proof or attributing prior physical cleanup to a new child would violate the original ledger.

## Decision

The two closed postloss Source cases add an explicit optional `source_observation` to the existing Core-signed witness. A distinct repository method verifies the same original pre-Start request/nonce, original grant/attempt/settlement, independently observed native tuple and exact empty owning reply. It retains immutable originals. The witness explicitly says `uncertain` and `SOURCE_ONLY_OBSERVED_SAME_CREATE_NOT_ACCEPTED_TRANSPORT`; it is neither a fabricated accepted response nor production authority. The ordinary accepted witness method is unchanged. Default binaries reject this extension. Actual bootstrap, enrollment and pre-Start payload-action preparation still run through the existing owner; an actual signed exit 1 / Wait / both EOF and Close / journal / census supplies the second action after successful original native Start.

These new namespaces opt into compensation before baseline creation. Their original policy stays active; no old policy or production default is silently enabled. The original settlement remains uncertain with empty transport identity, while separate native readback and complete actual action history identify the one lifetime.

The first generic child is issued but not redeemed. The caller waits the actual database expiry, and the original redemption API returns read-only. Its attempt/token/settlement/proof stay empty. Immutable raw rows before/after differ only in `grant.state`; no signed child effect authority exists. A database-recorded fresh nonce challenge is prepared after that expiry. The same original QEMU reader and authenticated Guest refusal endpoint perform new read-only native and full protected-cgroup observations. The historical failed payload is not rerun or restamped. The challenge, signed current census and exact old failure hash are appended in an immutable eligibility revision, retaining the initial signed wire and old child.

Generic Issue creates a distinct second child from that fresh eligibility and a genuinely refreshed baseline probe/membership. Only its new actual Redeem and trusted signed pre-effect authority may own the original kill/Wait/EOF/unlink/absence. Generic Settle and Confirm close the ledger. The physical cutoff is still the minimum of absolute original provisioning420, outer600, original cleanup150, current original lease and second child60. The first child60 is a historical permission lifetime, not a new global budget or a renewed provisioning clock.

## Consequences and limits

No new controller, workflow, transport, adapter capability or API endpoint is created. A closed read challenge on the existing Source-only refusal endpoint never starts, signals, withdraws or adopts anything. Public exports contain typed safe projections, hashes and read custody; raw private grants/leases/signatures remain private. No old Source result gains credit. Actual compiler/default-build, unit/remote Source cases, runtime-fit under unchanged limits and independent custody remain necessary. Production source support, registration, complete production roster and deployment authority are out of this proposal; default registry stays disabled.

## Validation proposal

Author-only regression tests: `repository.TestPostlossEmptyOriginalReplyNeverBecomesAccepted`, `TestPostlossChildReissueRequiresRealExpiredNeverRedeemedChild`, `TestPostlossSelectorsDoNotRequalifyOldUnknownLostReply`. No tests or compiler were run during authoring. Execute only through the original approved remote validation flow after review, including both new cases and default-build rejection of observed Source certificates.
