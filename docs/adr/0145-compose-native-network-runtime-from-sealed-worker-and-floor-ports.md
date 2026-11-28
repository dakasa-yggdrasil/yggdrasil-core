# ADR-0145: Compose Native network runtime from sealed worker and floor ports

- **Status:** Proposed
- **Date:** 2026-11-27
- **Scope:** Core / private Native network runtime composition

## Context

The network permission store owns one-use grants, private original custody and
compensating removal. The independently qualified worker runtime retains the
original provider return and exact immutable launch. Separate protected floor
reader and writer clients exist, but their constructor handles alone do not
connect those boundaries to the network store.

## Decision

Compose a private Go runtime with an exact database and policy, a borrowed
concrete worker runtime, and two owned floor RPC clients. Match the compiled
Core Source and the whole protected reader/writer bindings at construction and
at each operation. Failed construction takes no ownership. Copies share Close;
closing the network runtime closes its clients without closing the borrowed
worker runtime or database. Closing the borrowed runtime fences further use.

Project only the five fixed floor reader selectors from the exact stored
launch. Before any independent read, load the private original archive and
compare the complete current attempt and original launch. Installation uses
one sealed independent provider read, retaining the transport endpoint and
freshness from that same response, followed by the independent floor reader.

Removal uses the sealed physical birth and current complete floor observation
without asking a deleted provider to appear present. The existing store alone
selects the endpoint from its immutable, previously exposed install grant.
Receiving is GET-only and can inspect the retained target after permission or
policy expiry. Neither a mutation RPC disposition nor a floor observation is a
guest witness, warmup, Node admission or useful-capacity proof.

Expose a private method that dispatches one closed install/remove action and a
real retained permit UUID. It sends only binding_name and permit_id through the
protected writer. It does not redeem, capture a replacement original, infer
success, retry an uncertain send, or bypass the store's custody protocol.
Readiness remains the existing nil port until the protected guest path and
independent end-to-end qualification are implemented.

## Consequences

This composition is Source-only and opt-in. It changes no server defaults,
provider allocator, floor configuration, data floor, legacy protocol, registry
writer or admission criteria. A separate protected process must still provide
qualified configuration and activate the existing server option.

CI retains the previous three published-factory roots unchanged. A dedicated
runner fixture receives a fixed normally published System artifact, constructs
the real factory and concrete worker runtime, uses real PostgreSQL attempts and
immutable archives, and reaches the public mTLS floor clients over one owned
private alias. Provider and floor facts in this fixture are explicitly
synthetic; they do not qualify production network, LUKS, provider actions or
admission. The separate System kernel qualification remains independent.
