# ADR-0065: Transfer original provisioning time between clock domains

- **Status:** Proposed
- **Date:** 2026-10-21
- **Scope:** Original production Guest provisioning and installation

## Context

Core PostgreSQL, Guest wall time and the Guest boot clock are independent.
Comparing a Guest bootstrap, enrollment or installation time with a Core
deadline rejects legitimate originals when their clocks differ. Reading a
profile again must not restart the original provisioning budget.

## Decision

Use an explicit production profile authority V2 alongside unchanged
qualification V1. The fixed private GET requires the existing scoped provisioner
credential/native selector plus one canonical boot ID and random request nonce
digest. Resolve the existing Core signing key and sign the exact immutable
preregistration, witness and profile under the same current PostgreSQL
transaction. Its PG observation and remaining original deadline are signed.
Pending creation remains the existing closed nonauthority 425 response.

The Guest captures the original acquisition and GET start before I/O using
Linux CLOCK_BOOTTIME, including suspend. After the same complete response,
Read/EOF/Close and signature checks within five seconds, its accepted expiration
is the minimum of the original acquisition expiration and request start plus
the signed remaining interval. Check arithmetic overflow and every original
effect/join against this same boot expiration. No wall-clock offset, tolerance,
later GET or environment claim can renew it.

The explicit provisioning result V2 signs the authority, boot clock and original
bootstrap owner PID/start ticks. Bootstrap/placement/census chronology stays in
the Guest domain. Core independently checks its current PG deadline, policy,
workflow, generation/fence, source, executor and lease. Enrollment signs the
exact clock digest; its issued time is Guest content rather than a PG timestamp.
Installation V2 signs the original receipt exchange and same-boot sequence.
Core joins the exact stored registration wire, result digest, enrollment and
receipt before accepting an installation. The registration digest and nested
result digest remain distinct objects.

Keep new fields optional at the end of the existing JSON structures. Production
AWS/Hetzner registration requires V2; legacy qualification wire and its existing
clock rules remain unchanged. Do not add database authority, migration DDL or a
compiled production approval through this clock contract.

## Consequences

Independent clocks no longer prevent a valid original from being checked.
Expired, foreign, ambiguous, incomplete or uncertain originals remain HOLD.
Pure signed fixtures verify wire compatibility and clock arithmetic; they do
not qualify a provider, process, database enrollment or useful production
capacity. Owning Linux/native and complete production approval remain separate.
