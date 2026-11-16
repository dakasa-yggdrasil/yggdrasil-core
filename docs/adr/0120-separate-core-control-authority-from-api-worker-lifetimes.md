# ADR-0120: Separate Core control authority from API worker lifetimes

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** Giomaster
- **Scope:** yggdrasil-core / process roles, ordinary workflow ownership and native lifetime adoption
- **Supersedes:** —
- **Superseded by:** —

## Context

Core API state and several dispatch claims are durable in PostgreSQL, but an
original workflow invocation and its private canary bearer belong to a process.
An arbitrary replica cannot replace that origin or reconstruct its permission.
Other Core addons own consumers, schedulers, discovery, projection and credential
maintenance; a counter around one HTTP goroutine cannot certify all their returns.

## Decision

Keep the default authority role and its existing control floor. Introduce an
explicit, fail-closed api_worker role with a closed startup allowlist. Its fixed
`/app/yggdrasil-api-worker` command is a new image-only symlink to the same ELF;
startup rejects a role/path mismatch and predecessor images fail before addons. It has no
inbound broker consumers or authority background workers. Authentication
ceremonies, the logical login limiter, protected callbacks, secret/control writes
and webhooks stay at the existing authority origin. Misrouted requests are refused
without forwarding credentials, reissuing work or transferring a bearer.

Ordinary workers retain shared PostgreSQL sessions and active signing-key reads,
with required existing HMAC/MFA material supplied through exact shared references.
They create no per-pod signing key or secret fallback. They execute ordinary
integration workflows only; resolved in-process control, product, capacity and
nested dispatch work remains authority-owned.

Reuse the existing process_v2 admission/termination protocol with seven actual
worker lanes: broker_session, dependencies, listeners, request_audits, requests,
signal and workflow_originals. Seal external admission before shutdown and keep
original listeners, broker and database dependencies alive until their users
return. A native receipt requires every actual join and no failed lane. An
expired context, panic, socket closure or absent callback is not completion.
The worker shutdown budget covers the existing thirty-minute original-work
maximum plus ten seconds for dependency close; deployment and consolidation
grace must cover it. The authority retains its prior budget and is not certified
by the worker roster.

Recover committed control-plane ConfigMap projections through the existing
versioned catalog sweep on the actual authority. A local notification is not
durable delivery across processes, and projection does not apply a Deployment.

## Consequences

The same feature image can run a protected authority and separately controlled
ordinary workers. Deployment routes, shared Secret references, placement and a
single owner of API replicas must be qualified before enabling autoscaling.
Neither source implementation nor a worker process receipt grants HPA/provider
authority or proves useful capacity, node elasticity or stateful failover.
Existing native UID/nonce/finalizer guards and accepted authentication decisions
are unchanged. No existing Accepted Decision is superseded or rewritten.
