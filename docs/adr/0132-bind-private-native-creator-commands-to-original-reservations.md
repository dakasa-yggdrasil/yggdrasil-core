# ADR-0132: Bind private Native creator commands to original reservations

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giovanni Martins
- **Scope:** Core / Native disposable worker creator protocol
- **Supersedes:** —
- **Superseded by:** —

## Context

A provider actor cannot choose the controller executor, workflow, policy or
original send authority that created its reserved child. A consumed send may
return private provider data after its parent lease or policy closes. Repeating
creation after a lost response would exceed the reservation and lose custody.
The execution adapter's compiled revision is independent from Core's revision
and the worker bootstrap revision.

## Decision

Persist a private immutable command context in the same transaction as the
reserved attempt. It pins the original controller executor/workflow, generation,
fence, execution adapter, binding, scope, SDK Source and deadline. Keep these
controller identities outside the public Attempt and command read projection.

Expose only the three fixed protected `attempts/read`, `attempts/redeem` and
`attempts/receive` routes. Authenticate the active hashed machine credential,
exact execution instance/capability and compiled SDK Source before bounded body
reads, then resolve the exact private attempt and binding. Require TLS and the
compiled Core response Source; there is no human/session fallback.

Read never returns a launch or permission. Redeem delegates to the original
single-commit `send_started` store path, restoring authority from private DB
custody. Only its successful commit returns the closed private launch permit.
Progress renewal cannot extend that original command deadline. SDK actors must
compare `execution_scope_sha256` with the hash of their actual complete protected
binding file before any provider API call; a metric or expected hash echo is not
that proof.

Receive accepts only bounded original transport bytes, completeness and a closed
error class. Commit the private first original before decoding or independent SDK
qualification. A repeated callback can preserve only identical original truth.
Late custody and historical ACK/unknown qualification do not grant another send,
registry update, admission or useful-capacity credit. Raw bytes and their digest
never enter workflow metadata, public reads or typed birth hashes.

## Consequences

The protocol remains disabled without protected runtime composition and Source
bindings. It does not implement the provider sender, WireGuard peer authorization,
Node registration or a live production actor. Independent GET-only qualification
continues through the protected runtime; its failure retains original custody.
Legacy Guest/slot authority and existing callbacks remain separate.

The complete Source census keeps its existing finite bound and every fact.
Co-locate Native phase DTOs with lifecycle DTOs and Native market ledger/birth
helpers with attempts, preserving their semantics. New protocol files replace
those source-file boundaries; no fact is dropped to fit the census.

CI executes strict wire/authentication and actual PostgreSQL migration,
immutable-context, concurrent redemption and custody-before-SDK cases. No local
or paid provider/load test is part of this Source change.

## Related

- [ADR-0131](0131-record-native-worker-attempts-under-fenced-parent-reservations.md).
- [Native worker lifecycle](../features/native-worker-lifecycle.md).
