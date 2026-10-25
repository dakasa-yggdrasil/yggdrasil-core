# ADR-0041: Reobserve installed birth guards before native HPA authority

- **Status:** Proposed
- **Date:** 2026-10-09
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / native HPA lifetime executor
- **Supersedes:** —
- **Superseded by:** —

## Context

A complete Pod census does not protect a new controller-created Pod between
that census and a reserved-minimum HPA update. A rendered webhook manifest is
also insufficient: the currently installed selector, failure policy, service,
configuration and process identities may differ.

## Decision

Require enabled schema-two lifetime policies to pin an operator-owned birth
guard binding and its checksum. Obtain `observe_current_birth_guard` internally
from the exact approved adapter instance/type catalog before issuing HPA command
authority. The native actuator repeats the installed graph observation before
one-use redemption and immediately before its native HPA CAS. Closed workflow
inputs cannot supply installation facts.

The observation binds exact CREATE/UPDATE/DELETE webhook semantics, namespace,
immutable configuration bytes/mount, CA/service routing and a complete census of
at least two current guard processes. It explicitly reports
`atomic_snapshot=false`, `runtime_config_self_attested=false` and
`business_readiness_known=false`. Installation is a prerequisite, not a useful
capacity certificate. Disabled policies and legacy reservation-only mode retain
their existing contracts.

## Consequences

Missing, stale or drifted installed authority refuses mutation. Kubernetes has
no transaction spanning webhooks, Pods and HPA; operator changes after the final
read and invisible ABA remain a bounded cross-object gap. Neither Core nor the
adapter invents a native fence or mounted-config acknowledgement. Protected
runtime origin/join checks remain mandatory and independent.

The remote gate imports a pinned real guard renderer/image into an isolated
KinD realm and exercises actual Core callbacks with PostgreSQL. It preserves
the original baseline census before any candidate mutation. This source
qualification does not authorize production installation or certify all product
functions, provider continuity or physical N-1 capacity.

## Related

- ADR-0040 (refines the independent process lifetime contract)
- [Bound execution contract](../CAPACITY-BOUND-EXECUTION.md)
