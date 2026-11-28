# ADR-0139: Compose Native worker runtime from protected original ports

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giomaster
- **Scope:** Core / private Native worker runtime composition
- **Supersedes:** —
- **Superseded by:** —

## Context

The Native child ledger, immutable creator command, private System factory,
independent physical qualifier and protected adapter transports have separate
contracts. Installing the ledger alone cannot prepare a real launch, obtain
current registry authority or qualify the original provider acknowledgement.
Combining them must preserve the original private custody and ownership fences.

## Decision

Compose those existing implementations through explicit protected Go ports.
Bind one copied stored policy to its database, exact per-profile factories,
independent mTLS physical readers and a separate real Kubernetes phase reader.
Obtain Core Source from native build metadata. Transfer factory/client handle
ownership only after successful construction; retain their existing shared
Close fences, and keep database ownership with the caller.

Keep preparation pure. Render private bootstrap through the selected existing
factory outside SQL locks. Capture only original bytes already committed to the
immutable database archive; absent, failed or corrupt archive reads remain
pending, including a concurrent Close. They cannot manufacture an empty capture.
Join the archived original, private digest and exact current Attempt with the
immutable stored launch before invoking the independent physical qualifier.
Use the distinct sealed reobservation API without replacing lifecycle state.

Keep provider mutation, provider read, Kubernetes writer, pool read and phase
read as separate closed mTLS principal groups. Select the phase reader only by
its Source-owned binding name. A complete phase authority header is not a
useful-worker roster; no missing roster becomes zero ready workers. Forward phase
preparation and GET-only receiving through that same real reader under the copied
policy, registry epoch, exact writer inventory and shared Close fence. With no
independent readiness port, registration observation cannot authorize admission
or quarantine release. An expired permit may still receive original GET truth.

Limit this runtime's preparation and qualification to AWS until an independently
typed HCloud qualifier is paired. Install worker/bootstrap/phase ports together
only by an explicit Go option; clear all three on a refused replacement; retain default-disabled process gates. Do not install a
controller, creation sender, network writer, admission or readiness substitute.

## Consequences

- A missing certificate, factory, archive, Source or independent observation
  causes a hold before the corresponding next action.
- Successful Source construction or a public health read proves no live
  deployment, useful capacity, network readiness or bill closure.
- Real Kubernetes/provider reads occur outside database transactions. Pure
  preparation alone is callable within the existing reservation transaction.
- Failed constructors leave caller-owned handles open. Successful constructors
  require the process owner to close the copied runtime handle.
- CI qualifies archive behavior on PostgreSQL 16/17, actual mTLS role boundaries
  and factory composition against the existing immutable published System CLI.
  Local tests and paid provider/load tests are outside this work.

## Related

- ADR-0131: child reservations and private original custody
- ADR-0133: real private factory and immutable bootstrap operands
- ADR-0137: independent physical acknowledgement qualification
- ADR-0138: protected Native mTLS clients
