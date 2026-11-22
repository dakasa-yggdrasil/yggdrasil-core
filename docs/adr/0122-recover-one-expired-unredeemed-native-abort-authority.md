# ADR-0122: Recover one expired unredeemed native abort authority

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity authority / private Kubernetes abort protocol
- **Supersedes:** —
- **Superseded by:** —

## Context

A private request can be refused before redemption after Core has durably issued its one-use command. The retained command then remains uncertain and its permanent UID identity correctly blocks new authority. Expiry alone neither proves a Kubernetes outcome nor supplies the original failed birth with an SDK lifetime or termination receipt. Reissuing an all-zero-history proof would conceal real retained history.

## Decision

Provide a separate single-step, synchronous, named-human operation for one exactly bound expired unredeemed predecessor. Revalidate complete retained custody and all global history under the existing scope/UID locks, reserve a fresh lease and read the current native witness. Atomically discharge only the proven unredeemed authority to refused_no_redemption, archive it unchanged apart from that administrative state/timestamp and issue one fresh sequence-2 child. Commit the exact predecessor linkage and real history in a distinct closed proof schema. Existing immutable identity uniqueness supplies the one-child fence; no new schema migration or automatic chain is introduced.

Keep the original v1 zero-history contract and successful-drain authority separate. The child still requires authenticated redemption, the original UID/resourceVersion finalizer-only send, independent native result and Core caller return, fresh readback and durable archival. Neither the parent's administrative disposition nor the child's physical absence fabricates an SDK lane witness or useful-capacity credit.

## Consequences

Core and the adapter qualify the additive proof together before activation. The original failed invocation, canonical parent request, token hash, identity, expired deadline and source remain auditable. A crash before issuance leaves the parent uncertain; a transaction failure rolls discharge and issuance back together; an unknown child outcome remains held with no third command. Private custody hashes stay server-owned. This explicit repair does not enable general automatic recovery of future failed births or retarget a capacity policy.

## Related

- ADR-0121 separates never-registered failed births from successful SDK drain.
- ADR-0120 separates authority from API worker lifetimes.
