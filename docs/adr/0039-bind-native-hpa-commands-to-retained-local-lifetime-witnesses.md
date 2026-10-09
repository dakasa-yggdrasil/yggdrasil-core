# ADR-0039: Bind native HPA commands to retained local lifetime witnesses

- **Status:** Superseded by 0040
- **Date:** 2026-10-08
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / protected native HPA reservation and process lifetimes
- **Supersedes:** —
- **Superseded by:** ADR-0040 (independent lifetime ledger); source qualification remains separate.

## Context

A reserved HPA minimum is not useful stock or a VM floor. Closed HTTP metrics and
cancelled work cannot establish the lifetime of a removed native Pod. A caller
receipt or boolean cannot authorize the private mutation executor.

## Decision

Add an optional fixed bound executor under the exact active protected workflow.
Persist one-use full-request permissions under PostgreSQL dimension and native UID
ownership fences. Preserve pending outcomes across invocation and process restart;
observe exact native effects before another phase, with no blind resend.

Record the complete native baseline and selected Pod checkpoints atomically. Bind
current Pod UID/generation, container ID/start/restart count, immutable image,
workload UID, private challenge nonce, Core intent generation and full local lane
roster. Retain the native Pod through a finalizer until current successful native
Terminated status and its exact bounded producer receipt are durably confirmed.
Issue finalizer acknowledgement separately from termination and dependency joins.

Use the native timestamp representation interval only when Kubernetes omits
nanoseconds. Preserve exact comparisons for precise native timestamps. Missing,
Failed, partial, replaced or uncertain lifetimes retain the pending boundary.

Keep HPA reservation generation separate from Core intent generation, useful
replicas, warm/canary readiness, provider intents, business uncertainty and VM floors.
No source change activates production or certifies a whole fleet as quiescent.

## Consequences

The fixed workflow has no caller target, proof, lease or permission input. The
native adapter remains standalone and independently qualified. Missing projection
or lost responses can retain a Pod and pending generation until exact evidence is
available. Controller removals outside the witnessed baseline subset block completion.
