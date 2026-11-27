# ADR-0133: Materialize private Native bootstrap before the original create grant

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giovanni Martins
- **Scope:** Core / protected Native worker private bootstrap preflight
- **Supersedes:** —
- **Superseded by:** —

## Context

The private creator protocol preserves one original provider send, but an actor
also needs actual bounded cloud-init before consuming that send right. A public
plan, workflow input, expected hash echo or caller-provided script cannot supply
the agent credential, per-attempt network key or operator download capability.
Rendering must not hold the reservation transaction while reading private files,
signing an artifact capability or waiting for a pinned executable.

## Decision

Add one fixed machine-only GET at
`/internal/capacity/native-workers/attempts/bootstrap`. Accept only the existing
binding name and canonical attempt UUID. Preserve hashed machine authentication,
TLS, compiled SDK/Core Source and immutable execution context checks. API workers
and human sessions cannot authorize this endpoint.

Install the private factory only through explicit protected Go composition.
Its absence refuses preflight; a process flag or manifest cannot create it.
The store validates the original reserved launch against the attempt and checks
current parent, owner, epoch, budget, qualification and original command expiry.
Release every SQL connection and lock before invoking the factory, then repeat
the authoritative read before returning private bytes. Concurrent redemption,
policy closure, expiry or cancellation refuses the private response.

Return the closed `native_worker_private_bootstrap_v1` wire only through an
explicit private serialization port. Ordinary JSON and formatting remain opaque.
Cloud-init and its digest are private operands, never workflow metadata or
public evidence. Bound raw cloud-init to16KiB, retain the exact original public
Launch bytes and clear temporary private buffers after serialization or refusal.

The factory contract has no create, redemption, registration or admission port.
Its concrete implementation must bind the real protected material, canonical
System Launch, pinned clean executable and exact-version operator capability.
It must prepare public launch operands without I/O inside reservation transactions
and materialize private data outside them. The sender still requires a later
successful original `send_started` commit before its one provider request.

## Consequences

- A missing or failing bootstrap does not consume the provider creation right.
- A private preflight cannot turn an uncertain previous send into another send.
- Source/API delivery alone establishes neither installed factory material nor a
  running, network-qualified or useful worker.
- Actual PG16/17 tests cover one-connection rendering, unchanged reserved state,
  concurrent redemption/policy closure, cancelled or invalid private output and
  matching later grant operands. All tests and builds remain in CI.
- There is no paid cloud operation, Hetzner load test, legacy Guest recovery or
  production activation in this Source change.

## Related

- [ADR-0132](0132-bind-private-native-creator-commands-to-original-reservations.md).
- [Native worker lifecycle](../features/native-worker-lifecycle.md).

