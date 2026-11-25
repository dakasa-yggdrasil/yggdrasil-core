# ADR-0126: Retire a migrated native origin administratively

- **Status:** Proposed
- **Date:** 2026-11-25
- **Deciders:** Giomaster
- **Scope:** Core / exact obsolete native lifetime after a realm migration
- **Supersedes:** —
- **Superseded by:** —

## Context

A native lifetime can remain the admitted floor of a permanently retired source
realm. Its original protect and admission commands may both be confirmed, while
no original SDK termination witness or native protection-release result exists.
A copied ledger must retain that truth. Ordinary execution correctly refuses a
foreign admitted checkpoint; ignoring all old policy revisions would also hide
real pending obligations. The released-lifetime archive cannot represent this
case because it requires the genuine SDK witness and confirmed release.

## Decision

Use a separate, one-step, manual synchronous named-human operation
`capacity.retire_migrated_native_origin`. Its registered binding is literal and
includes the exact immutable origin policy, checkpoint and two confirmed
protect/admit command digests, the current compatible Target policy and physical
realm, and the operator's fresh measured Source fence and complete absence
report. Source facts are explicitly an administrative attestation by that named
operator. They are never described as server-owned native observations or a
graceful SDK exit. The handler independently reads the current Target birth
guard, HPA and complete admission candidates through the existing pinned native
adapter. Unknown, incomplete, stale or same-physical-realm evidence refuses.

Append one immutable administrative retirement record under the existing scope
and subject locks, with no active lease and exact expected intent generation and
fencing token. Preserve the admitted checkpoint, every original command and
identity, intent and any separate uncertain-abort quarantine. Validate each
historical SDK admission ACK at its own original observation time; a later
same-process checkpoint ACK need not equal the original command ACK.

Exclude only a fully validated retired foreign origin from current logical-scope
active lifetime obligations. Preserve the original policy and retained history
bodies as the validation authority. Permanently deny the retired UID for new
registration, commands and redemption, including when a retained administrative
record is malformed. Malformed or missing custody cannot become an empty active
ledger. Count the original rows toward retained-history bounds.

## Consequences

This records administrative retirement after a measured realm migration. It
does not change the original checkpoint to released, create a native termination
receipt, settle uncertainty, declare an original command succeeded, or grant
useful, warm, drained or physically released capacity. A new Target process still
requires ordinary admission, and ordinary pressure execution keeps its existing
metrics, leases, native observations and one-use command guards. An exercised
receipt prevents schema rollback; the original UID remains denied permanently.

## Related

- [ADR-0123](0123-quarantine-one-uncertain-never-admitted-native-abort.md): separate administrative classification from an unknown original outcome.
- [ADR-0125](0125-retain-permanent-native-quarantine-across-logical-policy-revisions.md): immutable origin validation across exact logical policy revisions.
- [ADR-0120](0120-separate-core-control-authority-from-api-worker-lifetimes.md): process lifetime authority remains distinct from the control plane.
