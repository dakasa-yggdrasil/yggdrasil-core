# ADR-0121: Dispose native failed births before registration separately

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / native pre-registration abort authority
- **Supersedes:** —
- **Superseded by:** —

## Context

A native API process can fail and be deleted before its first immutable lifetime registration. Its birth finalizer still protects the object. The successful lifetime protocol deliberately requires a real SDK origin and complete lane witness; absence of registration cannot manufacture either. Replaying the failed controller run or removing the finalizer generically would bypass durable authority.

## Decision

Keep successful admission, drain, witness and release unchanged. Use a distinct closed pre-registration-abort proof and one-use command. A protected human workflow pins the original policy/checksum/generation and native target plus a separately reviewed immutable adapter revision. It does not retarget the original policy or silently enable automatic cleanup.

Under the existing scope then global native-UID locks, the Authority proves zero global lifetime/checkpoint/archive/command history, including permanent identities and orphan HOT rows, and no unsettled scope command. Its new immutable command identity permanently denies subsequent registration or ordinary commands for the UID. Canonical request bytes retain the server-authored proof under the permanent request digest. Existing HOT and immutable command archive tables suffice; do not invent a lifetime archive or a schema migration.

Only the original failed, deleting, terminated native container with exact owner chain, reviewed spec/image, birth annotation and absent challenge/owner projection can lose the existing capacity finalizer. The independently validating adapter redeems a fresh fenced command, rereads, and sends one original UID/resourceVersion-bound finalizer-only update over verified TLS. Unknown outcomes retain HOLD. A true returned no-effect does not grant retry. Original caller return, adapter callback, native readback and mutation event are distinct retained facts.

## Consequences

A new Authority and separately advertised adapter protocol are needed, but existing API-worker binaries, admitted lifetime origins, policy identity, protected floor and AMI remain intact. Old enabled Authority writers must be gone before the new disposition is activated. The first fixed human repair is not a claim of fully automatic recovery of future failed births. That requires a separate explicitly reviewed binding. No pre-registration disposition asserts SDK joins, successful drain, useful capacity or physical release.

## Related

- ADR-0039 and ADR-0040: native witnesses and lifetime origins remain unchanged.
- ADR-0049: original transport return is separate from native readback.
- ADR-0120: the sole control Authority can evolve without replacing API workers.
