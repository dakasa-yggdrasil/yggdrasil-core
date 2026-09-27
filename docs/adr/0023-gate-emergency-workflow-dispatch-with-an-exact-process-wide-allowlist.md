# ADR-0023: Gate emergency workflow dispatch with an exact process-wide allowlist

- **Status:** Accepted
- **Date:** 2026-09-26
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow dispatch, control-plane mutation, manifest mutation, integration execution, reactors, scheduler, event triggers, Heimdall inbox, reconciler, and AMQP queues
- **Supersedes:** none
- **Superseded by:** none

## Context

Workflow authorization answers whether one caller may run one workflow. It does
not provide an incident or maintenance control that restricts every dispatch
source to a small, reviewed set of recovery workflows. Core has several dispatch
sources: human and machine HTTP requests, AMQP workflow runs, the scheduler,
event triggers, the Heimdall inbox, GitHub webhook bindings, and integration
install flows.

A gate only in the HTTP handler would leave internal sources open. A gate only
at workflow execution would prevent provider actions, but the scheduler would
advance `workflow_schedule_state`, event triggers would commit their dedup marker
and advance the shared cursor, and Heimdall would consume retry budget. Those
records must remain replayable after a temporary freeze.

The legacy `yggdrasil-core.workflow.dispatch` queue is a separate risk. Its
payload names a downstream repository workflow and has no unforgeable reference
to the stored Yggdrasil workflow that originated it. Caller supplied metadata
cannot establish that identity.

An exact workflow name is also insufficient while an external writer can create
a new active version with the same name, replace its RBAC, or replace an
integration instance it uses. The generic `integration.execute` queue and the
reactor dispatcher can call adapters without crossing workflow preparation.
Those paths must stop consuming work during the same window.

## Decision

Gate workflow execution with one strict, process-wide policy keyed by exact
workflow namespace and name.

1. `YGGDRASIL_WORKFLOW_DISPATCH_LOCK_JSON` carries one JSON object with `mode`
   and `allowed_workflows`. An unset variable and an explicit `mode: off` preserve
   normal dispatch. `mode: enforce` requires at least one exact namespace and
   name pair. Blank values, unknown fields, trailing JSON, wildcards, duplicates,
   surrounding whitespace, and an empty enforce list are invalid.
2. One pure parser and checker owns these semantics. Invalid configured JSON
   denies dispatch and fails boot validation in every environment, so no process
   can advertise readiness with an ambiguous lock.
3. The canonical execution gate runs in `prepareWorkflowRun`, after Core resolves
   the current active workflow manifest. This prevents a manifest ID or version
   selector from bypassing the logical namespace and name check. Both durable
   preparation and `RunWorkflow` use this function. The execution-time check is
   retained so AMQP `workflow.run` messages and pending goroutines prepared before
   a freeze are checked again before their first step.
4. The scheduler checks before reading or advancing schedule state. The event
   trigger loop checks before writing `workflow.event.matched`; when a matching
   workflow is blocked, it keeps the shared cursor unchanged. Already processed
   allowed matches deduplicate on the next pass. Heimdall checks before claiming
   an inbox row, so the row stays pending and its failure count stays unchanged.
5. While enforcement is active, or when configured JSON is invalid, Core
   registers no consumers for `yggdrasil-core.workflow.dispatch`,
   `yggdrasil-core.workflow.run`, `yggdrasil-core.integration.execute`,
   `yggdrasil-core.catalog.discover`, or the product materialize, reconcile,
   apply, observe, and uninstall queues. Product observe is paused because it
   reconciles before observing. Direct handler
   invocation still fails closed. The exported in-process integration entry
   point is also blocked because it has no stored workflow identity. This stops
   webhook integrations, surface queries, password recovery email, external
   identity resync, and future direct callers from bypassing the lock. Caller
   supplied metadata on the legacy workflow dispatch queue is never accepted as
   allowlist evidence. Steps of an allowed stored workflow call the resolved
   integration dispatcher in process, so they do not depend on these generic
   queues.
6. External manifest mutation is frozen while enforcement is active. HTTP
   manifest create and delete, applied workflow-template instantiation,
   non-dry-run integration install, manual integration-type sync, Guardian
   memory review, Guardian approval decisions, and the AMQP `manifest.create`
   mutation path all fail before persistence. Core registers no
   `manifest.create` consumer. Read and validation consumers remain available.
   An allowlisted workflow cannot use the in-process `apply_manifest` operation
   to change the catalog during the same window.
   Periodic adapter manifest sync does not start. If any first-run bootstrap
   environment variable is configured, locked startup fails explicitly; when
   all bootstrap variables are unset, the first-run addon is a no-op.
7. Direct control-plane mutation is also frozen. Core blocks AWS provisioning,
   managed-secret create, rotate, disable, and revoke, explicit Kubernetes
   secret materialization, third-party provider and identity changes, and
   operator surface actions before reading their request bodies or writing
   state. The AWS provisioner and Kubernetes reconciler do not start, so they
   cannot mutate provider resources, Secrets, or ConfigMaps in the background.
   These paths have no stored workflow identity and cannot use the allowlist.
8. The reactor dispatcher does not start while enforcement is active or the
   configuration is invalid, so it does not claim pending reactions. A GitHub
   webhook checks the selected workflow synchronously and returns the typed lock
   response before acknowledging the webhook or starting a goroutine.
9. The allowlist is an additional restriction. It never grants authentication,
   workflow `spec.authorization`, RBAC, policy, input, or integration authority.
   It is not a global database maintenance mode. Collaborator, team, session,
   ordinary credential, audit, retention, and housekeeping state continue to
   follow their normal contracts. Authorization is evaluated again for every
   dispatch, so an identity or membership change may revoke access during the
   window but never becomes an allowlist grant.
10. Before activation, operators register and read back every fixed workflow,
   RBAC, policy, and integration instance required during the window. The current
   adoption uses two independent lock windows. The AWS adapter window permits
   only `dakasa/bump-integration-aws-sha-d1d632c` and
   `dakasa/unlock-yggdrasil-workflow-dispatch-production`. After unlock, normal
   manifest sync must publish and prove the new adapter capability. A separate
   ECR policy window then permits only
   `dakasa/apply-dakasa-ecr-lifecycle-policies` and the same unlock workflow.
   Each window requires a new activation, rollout, readback, and freeze proof.
   The unlock workflow has a fixed target and writes the complete explicit
   `mode: off` object. It accepts no caller-selected patch and requires
   named-human authorization.
11. Activation is not established until the full Core rollout completes, every
    pod from an older ReplicaSet is terminated, and a read-only attestation shows
    zero pending or running durable workflow runs. The workflow dispatch, workflow
    run, integration execute, catalog discover, and manifest create queues must
    each show zero consumers, ready messages, and unacknowledged messages at
    adoption. The five product mutation queues must also show zero consumers,
    ready messages, and unacknowledged messages. For the current one-replica adoption,
    `yggdrasil-core.product.installation_state.discover` remains enabled as a
    read-only consumer and must show one consumer, zero ready messages, and zero
    unacknowledged messages. The operator drains and observes adapter queues
    because a provider action already delivered outside Core cannot be recalled
    by this lock.
12. At locked startup, Core passively verifies that every paused queue already
    exists as a durable queue. It does not create topology. The current RPC SDK
    publishes with `mandatory=false` and without persistent delivery mode, and an
    RPC reply queue can expire before a held request is consumed. Unlock is
    therefore blocked if any paused queue is nonempty or cannot be inventoried.
    Operators must stop publishers and explicitly purge or quarantine every late
    RPC before applying `mode: off`; held RPCs are never approved for replay by
    the allowlist. Locked startup also fails when `BROKER_URL` is absent or the
    broker cannot be reached, because that state cannot prove the queue contract.

## Consequences

- Every stored workflow path shares one final fail-closed execution check.
- Scheduled ticks, matching events, and Heimdall alerts remain available for
  replay after the freeze. A blocked event trigger can hold the shared event
  cursor and delay unrelated later events until the freeze ends.
- HTTP callers receive retriable `503 Service Unavailable` with stable code
  `workflow.dispatch_locked`. AMQP callers receive
  `workflow_dispatch_locked`.
- Paused ingress queues have no Core consumer during the enforce window.
  Allowlisted emergency workflows must enter through HTTP or a trusted
  in-process caller.
- External manifest versions and periodic adapter sync cannot change catalog
  state during the window. Configured first-run bootstrap input fails locked
  startup instead of being silently skipped.
- The lock freezes provider side effects and the manifest and managed-secret
  inputs used by allowlisted workflows. It does not freeze every Core database
  table or replace ordinary authentication and authorization controls.
- The lock does not interrupt a workflow that already passed preparation and does
  not recall an adapter request already delivered outside Core. The rollout and
  drain invariant is what excludes those older actions from the adopted state.
- Scheduler, event, Heimdall, and reactor records remain available for replay
  after unlock. A blocked event trigger can hold the shared cursor and delay
  later events.
- A late AMQP RPC is not safe replay evidence. The queue may outlive its reply
  destination, and transient publishing can lose it across broker restart.
  Explicit inventory plus purge or quarantine is required before unlock.

## Related

- ADR-0015 (validates workflow input before durable async persistence)
- ADR-0017 (scopes machine principals by exact workflow and run ownership)
- ADR-0022 (loads machine credential surfaces once and closes anonymous production posture)
