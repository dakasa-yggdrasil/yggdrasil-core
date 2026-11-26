# ADR-0127: Recover one proven unredeemed native protect separately

- **Status:** Proposed
- **Date:** 2026-11-25
- **Deciders:** Giomaster
- **Scope:** Core / explicit planned-lifetime protect recovery
- **Supersedes:** —
- **Superseded by:** —

## Context

Ordinary native admission permits at most four protect permissions for one Pod
UID across all generations. A callback configuration error can exhaust all four
without any redemption. Atomic revocation proves that those exact tokens cannot
be used later. It does not prove that the Pod lacks birth protection, nor does
it authorize a fifth ordinary attempt. A planned registered lifetime cannot use
the zero-history failed-birth abort, the uncertain-abort quarantine, or the
witnessed released-lifetime archive.

## Decision

Add the separate named-human operation
`capacity.recover_unredeemed_native_protect`. Require a stored active manual
synchronous workflow with exactly one literal recovery binding, a 90-second
step, one attempt, existing protected workflow authorization, and the actual
server-authenticated creator. Both execution and admission process gates must
be enabled. A machine session, caller-selected observation, dynamic binding,
adapter permission, or changed policy does not confer this authority.

Bind the exact current policy checksum, planned checkpoint checksum, Pod UID,
expected intent generation and fence, and four ordered immutable command IDs
and canonical record checksums. Require their original sequences 1 through 4,
same ordinary workflow/lease/executor, protect operation, and atomic
`refused_no_redemption` state with no attempt, redeemer or native result. Count
all identities, hot commands, archived bodies including orphaned references,
legacy checkpoints and lifetime archives. Unknown or extra history holds.

Before issuing authority, obtain a real private adapter RPC for the same live
SDK `waiting_projection` process. Require the current UID, container ID, start,
restart count, image, process nonce, full lane roster and nonempty Pod resource
version, with fresh observations and no projection, roots, receipt or terminal
residue. The checkpoint, original challenge and original four rows remain
unchanged. No human-provided readiness or SDK claim is accepted.

Under the existing dimension and global UID locks, atomically retain exactly one
separately identified child protect command and its permanent identity, advance
the generation and fencing token, and create a fresh bounded lease. The child
uses sequence 1 of that new generation, preserving the database sequence limit
of four. Its command record retains the server-authored proof, human workflow
identity/version/checksum and fresh SDK observation. Do not serialize the opaque
permission into the retained request or public workflow result.

The callback retains its ordinary machine principal, instance/type, policy,
token, request digest and live lease checks. Only this typed child uses its
exact registered human workflow instead of the ordinary admission workflow.
Revalidate the four original records and whole UID history before redemption
and settlement. Invoke the unchanged adapter wire once. An unused token is
atomically revoked; a redeemed or uncertain token is never resent and requires
real native readback. Confirm only protection of the same lifetime.

The fifth permanent identity makes a second recovery ineligible, including if
its body is later archived or lost. A different generation, workflow or human
does not reset this rule. Keep the ordinary lifetime protect limit at four.

## Consequences

Successful recovery produces a protected planned-origin lifetime, not admitted
capacity, an SDK shutdown witness or physical release. Continue with the normal
admission workflow, real immutable projection acknowledgement, roots opening
and native readiness. The existing worker and adapter protocol do not change.

An unresolved child or failed second opportunity remains held. Operators must
repair the measured callback/configuration cause before using this one-use
operation. It is not a retry policy or an exemption for unknown effects.

CI qualifies real PostgreSQL serialization, immutable history, rejection of
unsafe input, and actual HTTP/TLS protocol integration. These fixtures do not
claim a physical Kubernetes/SDK production qualification. Production adoption
and real admission remain separately received operational actions.

## Related

- [ADR-0039](0039-bind-native-hpa-commands-to-retained-local-lifetime-witnesses.md)
- [ADR-0040](0040-separate-native-process-lifetimes-from-reservation-decisions.md)
- [ADR-0121](0121-dispose-native-failed-births-before-registration-separately.md)
- [ADR-0123](0123-quarantine-one-uncertain-never-admitted-native-abort.md)
- [ADR-0126](0126-retire-a-migrated-native-origin-administratively.md)
