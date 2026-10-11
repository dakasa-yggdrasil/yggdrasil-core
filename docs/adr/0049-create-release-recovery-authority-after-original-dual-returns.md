# ADR-0049: Create release recovery authority after both original returns

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / native retained Pod finalizer release
- **Supersedes:** None
- **Superseded by:** None

## Context

A final native API conflict does not by itself prove that an earlier hidden write was absent. A committed adapter result also does not prove that Core observed the original SDK HTTP return. Losing either acknowledgement must retain the original permission and prevent another write.

## Decision

Enable release recovery only through the optional operator-approved `release_recovery` binding and `native_release_result_v1`, bound to the exact compiled adapter Git source. Original native HTTP uses the existing operator TLS/auth, one non-replayable HTTP/1.1 PUT, bounded Read and actual Close under the copied original deadline. Historical commands are never upgraded to this protocol.

Retain the adapter's complete canonical409 through an authenticated fixed callback with a server-generated one-use return nonce. Separately acknowledge Core's original Do/Read/Close in the private owning invocation. Only both acknowledgements can mark that command `rejected_no_effect`. Row visibility and callback Commit cannot substitute for Core's return.

Create a separate durable server-authored release-only subdecision after fresh full inventory, HPA, current native witness, catalog and original actor/RBAC authorization. Give it a new decision/fence/command/token/attempt and retain its parent command/attempt. Keep the earliest original invocation/permission deadline, never renew it, and count all permanent identities toward the four-command history. Do not reuse the original unredeemed-token retry loop.

Keep rejected parent records and receipts intact, including terminal archive and immutable tombstones. Logical release needs exactly one independently confirmed new native release. Deadline, lease, source/policy/RBAC change, missing ACK, old protocol and ambiguous response require HOLD and GET-only recovery. A later invocation cannot automatically reuse the old permission.

## Consequences

Absent binding preserves ordinary behavior. The new protocol requires compiled source provenance and verified TLS for its callback; missing runtime enrollment remains HOLD. No new principal grant, provider resource, VM authority, routing authority or physical-quiescence assertion is introduced. Mandatory PostgreSQL, original TLS and real KinD gates qualify their own scopes separately.

## Related

- ADR-0040 (retained lifetime ledger and immutable terminal archive)
- ADR-0044 (durable original dispatch and current authorization)
