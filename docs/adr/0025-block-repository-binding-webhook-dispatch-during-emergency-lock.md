# ADR-0025: Block repository-binding webhook dispatch during the emergency lock

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / GitHub webhook repository bindings and emergency workflow dispatch
- **Supersedes:** [ADR-0023](0023-gate-emergency-workflow-dispatch-with-an-exact-process-wide-allowlist.md)
- **Superseded by:** none

## Context

ADR-0023 made the emergency workflow allowlist an additional restriction rather
than an authority grant. GitHub push dispatch did not satisfy that contract. A
valid webhook selected a stored workflow through a `repository_binding`, checked
that workflow against the emergency allowlist, and called the in-process
executor without authenticating a workflow-run principal or evaluating the
workflow's caller authorization.

The webhook HMAC authenticates the delivery source. It does not identify a
Yggdrasil collaborator or machine principal and cannot satisfy named-human RBAC.
Consequently, an active repository binding to an allowlisted recovery or unlock
workflow could turn an ordinary repository push into an emergency control-plane
dispatch. Freezing manifest mutation prevents new bindings, but it does not make
every binding already present at activation trusted.

## Decision

Retain the emergency lock contract in ADR-0023 with a stricter rule for GitHub
repository-binding ingress.

1. While `YGGDRASIL_WORKFLOW_DISPATCH_LOCK_JSON` is in `mode: enforce`, every
   GitHub push dispatch through a `repository_binding` is refused. A workflow's
   presence in `allowed_workflows` does not exempt this ingress.
2. Invalid configured lock JSON fails this ingress closed, consistent with the
   other emergency-lock surfaces.
3. The push handler checks the repository-binding gate before parsing the push
   payload or querying binding state and returns HTTP `503` with stable code
   `workflow.dispatch_locked`.
4. The asynchronous repository-binding dispatch wrapper checks the same gate
   again before it invokes the executor that can insert a `workflow_runs` row.
   This keeps the no-create and no-execute contract at the persistence boundary.
5. An unset lock or explicit `mode: off` preserves existing webhook behavior.
   Ping and ignored GitHub event types remain non-dispatching responses and do
   not need an emergency-lock refusal.
6. During enforcement, operators start allowlisted recovery workflows through
   an independently authenticated and authorized workflow-run route or a
   reviewed trusted in-process caller. A repository binding is never that
   authority.

The remaining parser, allowlist, queue, trigger, manifest-mutation,
control-plane, rollout, and drain decisions from ADR-0023 remain in force.

## Consequences

- A pre-existing repository binding cannot trigger an allowlisted recovery or
  unlock workflow during an emergency window.
- Locked GitHub push deliveries receive a retriable `503`; operators should
  expect GitHub to retry them after the lock is disabled.
- Normal repository-driven deployment continues unchanged while the lock is off.
- Scheduler, event-trigger, Heimdall, and other explicitly trusted in-process
  sources retain ADR-0023's exact allowlist behavior. Their trigger authority is
  separate from repository-binding ingress and must be reviewed when selecting
  emergency allowlisted workflows.

## Related

- ADR-0017 (scopes authenticated machine principals by exact workflow)
- ADR-0022 (requires explicit non-development credential surfaces)
- ADR-0023 (defines the emergency lock contract superseded here)
