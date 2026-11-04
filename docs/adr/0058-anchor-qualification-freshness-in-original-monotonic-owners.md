# ADR-0058: Anchor qualification freshness in original monotonic owners

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Pending contract approval
- **Scope:** Original native Guest qualification serving probe
- **Supersedes:** —
- **Superseded by:** —

## Context

A signed timestamp establishes who issued a value, not clock agreement. Comparing a Core issue time with Guest wall time can refuse a fresh authenticated probe when their clocks differ. Finite-error synchronization does not guarantee these strict comparisons. Starting a new TTL when an old challenge arrives would instead permit delayed first use and is not an adequate replacement.

## Decision

Use an authenticated preflight and a fresh nonce owned by the original Guest runtime. Bind the final Core signature to that nonce, the exact preflight and enrolled actor/runtime/writer identity. Atomically consume the nonce before any original writer effect. Duplicate or delayed preflights must not renew it; state and work are bounded for the original runtime lifetime. Reboot or replacement cannot resume an enrollment or nonce.

The Core starts its single monotonic operation budget, at most five seconds, before preflight. Every subsequent transport, reservation, result validation and persistence uses that same context. It accepts no result after expiration or cancellation. The Guest retains a local monotonic expiry from nonce creation and passes the remaining local budget through its original socket and writer owners. It never derives freshness from an unsynchronized Core wall timestamp or grants a fresh five seconds at each hop.

Keep cryptographic identity, authority, signature, native provenance, one-use effect and same-Guest causal-order checks. Reject incompatible protocol versions; do not fall back to the old wall-clock protocol. Retain wall timestamps as diagnostics where appropriate, not as cross-machine freshness evidence.

## Consequences

This is an explicit temporal contract change requiring coordinated Core/Guest activation. Core acceptance remains bounded by its original five seconds. Guest authorization has a separate bounded local interval: if its nonce lifetime is five seconds, a fresh authenticated effect may start after Core expiration, but its nonce expires less than five additional seconds after it. Native writes, cancellation, process termination and cleanup joins are not proven to complete physically within that interval. Core refusal does not assert that a remote effect never happened. Lost cancellation does not authorize replay, renewal or a second effect. There is no guarantee of physically simultaneous stopping across machines.

These guarantees do not require synchronized wall clocks. External UTC validity claims and other lifecycle protocols that still compare absolute timestamps remain separate concerns. This decision does not modify destructive retirement authorization, production rollout or network/time configuration.

## Related

- ADR-0057 (original local installation remains required before qualification)
- ADR-0053 (qualification recovery authority remains separate)
