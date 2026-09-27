# ADR-0027: Require authenticated actor channels for authorized workflows

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow dispatch channel authorization
- **Supersedes:** none
- **Superseded by:** none

## Context

A workflow with `spec.authorization` names the RBAC manifest and optional policy
that must approve its caller. The authenticated HTTP workflow-run route carries
a Core actor and evaluates that contract. Two older dispatch paths do not:

1. `yggdrasil-core.workflow.run` accepts an AMQP request body but has no
   authenticated Core actor tied to the delivery.
2. A GitHub push can select a workflow through a `repository_binding`. The
   webhook signature authenticates GitHub as the delivery source, not a
   collaborator or workflow machine principal that RBAC can evaluate.

Both paths previously called the general workflow executor. Checking a
workflow in one lookup and resolving it again for execution would still be
unsafe because the active version could change between those operations.

## Decision

Reject every workflow that declares `spec.authorization` when dispatch comes
from `yggdrasil-core.workflow.run` or a GitHub `repository_binding`.

The AMQP handler returns the stable RPC error code
`workflow_authenticated_actor_required`. The repository-binding path refuses
the workflow before it inserts a `workflow_runs` row. Both paths resolve and
validate the active workflow once, inspect that parsed spec, and pass the exact
same manifest and spec objects to execution. They do not perform a second
logical-name lookup after the channel check.

Continue to execute existing workflows that omit `spec.authorization` through
these channels. Protected workflows must use the authenticated HTTP
`POST /api/v1/workflow-runs` route or a separately reviewed trusted in-process
source with an explicit authority contract.

## Consequences

- An AMQP publisher cannot claim a caller identity in request fields and use it
  to bypass workflow RBAC or policy.
- A valid GitHub webhook and repository binding cannot start a protected
  workflow.
- A concurrent active-version change cannot replace the checked spec with a
  different spec at the execution boundary.
- Legacy actorless automation remains compatible until its workflow adopts
  `spec.authorization`. That adoption requires moving its dispatcher to an
  authenticated route or defining a reviewed trusted source.
- Repository-binding webhook acknowledgement remains asynchronous. A refused
  dispatch is logged by the background dispatcher and creates no workflow run.

## Related

- ADR-0017 (scopes authenticated machine principals and requires workflow authorization)
- ADR-0022 (defines workflow credential surfaces and the migration bridge)
- ADR-0025 (blocks repository-binding dispatch during the emergency lock)
