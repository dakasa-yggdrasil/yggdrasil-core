# ADR-0013: Scope adapter mutation-event credentials to event publishing

- **Status:** Superseded by 0016
- **Date:** 2026-09-01
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / adapter authentication
- **Supersedes:** —
- **Superseded by:** ADR-0016

## Context

Integration adapters emit a canonical event after each successful external
mutation. The HTTP emitter historically used the shared workflow-run token,
which also authorizes broader control-plane APIs. Giving that credential to
every adapter increases the blast radius of a compromised pod beyond its need
to publish mutation events.

Existing adapters must keep working while deployments migrate to a narrower
credential.

## Decision

Accept `YGGDRASIL_EVENT_PUBLISH_TOKEN` only on `POST /api/v1/events`. Adapter
pods receive that value through their existing `YGGDRASIL_RUN_TOKEN` client
environment variable, but the core never accepts it on workflow, manifest,
catalog, secret, or administrative routes.

Continue accepting `YGGDRASIL_WORKFLOW_RUN_TOKEN` on the event endpoint for
backward compatibility. If the dedicated event token is configured, anonymous
event publishing fails closed even when no legacy workflow token exists.

In production, require at least the dedicated event token or the legacy
workflow token during the compatibility window. When the dedicated token is
configured, fail boot if it equals a legacy/scoped workflow token,
`YGGDRASIL_DEPLOY_TOKEN`, or `YGGDRASIL_AUTH_ADMIN_TOKEN`; credential reuse
would collapse the route-level scope even if the event middleware itself is
correct.

## Consequences

- Newly deployed adapters can retain required mutation events without holding
  a general workflow credential.
- Existing adapters remain compatible during migration.
- Production cannot boot with anonymous event publishing or a dedicated token
  that is also valid on a broader static-token surface.
- Operators must provision the same dedicated token into the core and each
  authorized adapter without placing it in manifests or command output.
- Token rotation requires updating both ends; overlapping rotation needs a
  future multi-token extension or a coordinated rollout.

## Related

- ADR-0001 (event stream persistence)
- ADR-0012 (sensitive integration output boundary)
