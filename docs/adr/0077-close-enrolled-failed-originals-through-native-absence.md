# ADR-0077: Close enrolled failed originals through a separate native-absence ledger

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** DaKasa maintainers
- **Scope:** Production capacity provisioning failure accounting
- **Supersedes:** —
- **Superseded by:** —

## Context

An original provider create can succeed and its Guest can register a signed enrollment while the enclosing scheduled workflow fails before installation confirmation. The accepted provider return, original enrollment and failed workflow are independently meaningful facts. Existing unadmitted, witnessed-but-unenrolled and authorization-denied disposition contracts deliberately do not admit this combination. Retrying the workflow, erasing enrollment, inventing an acknowledgment or treating the create as denied would misrepresent the original operations.

## Decision

Record a distinct enrolled-failed terminal disposition only after authenticating the immutable accepted settlement, exact preregistration, signed create witness, signed registration and issuer enrollment, original profile and failed scheduled run. Require the original deadline and leases to be closed, the dispatch to remain unknown with its original NULL acknowledgment, and no installation, serving membership, retirement, compensation, factory association or competing live work. The authenticated provider observer must independently read complete fresh native absence for the exact original lifetime and its owned auxiliary inventory. The operator supplies only grant and job identities.

Append the ledger, matching grant and dispatch pointers, and the next intent fence in one locked transaction. Preserve the original settlement, witness, registration, receipt, workflow result, return cause and acknowledgment. Mark the old intent as a degraded failed floor with no execution permission or lease. Subsequent creation requires a fresh assessment, decision, generation, fence and single-use grant.

Native absence is physical fencing and accounting closure. It is not Guest withdrawal, drain, quiescence, successful installation, business readiness or savings evidence. This lane performs no provider mutation. Cleanup is a separately authorized exact-resource operation.

## Consequences

Existing disposition APIs and migrations retain their semantics. The new forward-only migration adds an independent state and immutable ledger, prevents late ownership and includes this terminal in the existing reservation exclusions and successor fence.

A complete original auxiliary inventory is checked by exact identity. For the reviewed AWS creator whose original accepted return omitted that inventory, the distinct observer derives the original network interface and root snapshot lineage through the authenticated original create request. Its conservative snapshot-descendant absence proof can remain held when another same-snapshot volume survives. Unrelated resources must not be deleted to satisfy the proof, and an empty tag-filtered query is not a substitute. Future producer contracts should return the complete owned inventory durably before reporting an accepted create. A new creator or observer source requires explicit review and binding.

## Related

- ADR-0069 (relates to expired unadmitted create dispositions)
- ADR-0073 (refines terminal failed witnessed originals with a distinct enrolled lane)
- ADR-0075 (preserves the distinction between unknown and observed acknowledgments)
- ADR-0076 (depends on isolated read-only observation)
