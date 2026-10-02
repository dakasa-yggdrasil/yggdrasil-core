# ADR-0029: Pause reactor dispatch by logical integration instance

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / integration reactor dispatch
- **Supersedes:** —
- **Superseded by:** —

## Context

An integration type declares reactors that the adapter and manifest sync keep
in a union. Removing a declaration from the stored type is therefore not a
durable way to pause it. Disabling an integration instance also interrupts
ordinary capabilities such as `observe_*` and its action catalog.

Reactions are materialized against a manifest-version UUID and dispatched
asynchronously. A manifest edit made only to pause reactors would create a
new instance version, while existing reactions and team provisioning records
still reference the previous UUID. Event and manifest retention both cascade
to reactions through foreign keys.

## Decision

1. Store an operator-owned set of exact `paused_event_types` in
   `integration_reactor_dispatch_policies`, keyed by the logical
   `(namespace, name)` of an integration instance. An absent row or empty set
   means dispatch is enabled. Adapter describe and manifest sync do not own
   this table.
2. Expose GET and atomic replacement PUT at
   `/api/v1/ops/integration-instances/{namespace}/{name}/reactor-dispatch`.
   GET requires `yggdrasil:view_integrations`; PUT requires
   `yggdrasil:manage_integrations`, validates exact canonical lifecycle or
   integration mutation event names, and requires an active instance. GET
   returns revision `0` for an unwritten policy. PUT requires both the full
   `paused_event_types` set and its `expected_revision`; a stale revision
   receives `409` and cannot overwrite a concurrent operator's change.
   `[]` resumes every paused event type. The verified console session's
   collaborator ID is the audit actor; the policy replacement and success
   audit row commit in one transaction or neither commits.
3. Continue materializing normal events during a pause. The claim query
   resolves each reaction's historical instance UUID to the currently active
   version of the same logical instance, checks the policy before incrementing
   `attempt`, and locks only reaction rows. If there is no active version,
   nothing is claimed. Dispatch rechecks the policy and active version before
   processing and before the adapter RPC; a newly blocked claim returns to
   its prior pending or failed state without spending an attempt. This is a
   best-effort dispatch boundary, not a strict drain: PUT can commit after
   the final policy check but before the adapter RPC starts. An RPC can
   therefore start or finish after PUT returns.
4. The team reconciler does not treat paused `team.created` pairs as gaps.
   Its synthetic `team.created` events do not materialize reactions for
   paused destinations. On resume, an unresolved gap becomes eligible only
   when no nonterminal ordinary `team.created` reaction already covers it.
5. Periodic event cleanup and manifest-version purge retain source rows that
   have pending, failed, or in-progress reactions. Terminal reactions remain
   subject to normal retention. Operator policy remains across a logical
   manifest delete and name reuse until an authorized PUT replaces it.

## Consequences

- A pause preserves an at-least-once backlog and may need time to drain after
  resume. Observe backlog count, oldest age, database capacity, and adapter
  outcomes before resuming large sets. No live policy is written by the source
  change alone.
- The dispatch worker uses the active instance UUID selected at claim for the
  adapter call, avoiding stale credentials in historical reactions. A version
  change between claim and the pre-RPC check requeues the reaction. The
  existing team provisioning log remains keyed by version UUID; this policy
  does not migrate those records.
- A hard manifest delete remains an explicit destructive operation that can
  cascade to reactions. The periodic cleaners protect replay automatically.
- Policies survive deletion deliberately, so recreating the same logical
  instance inherits its last pause until an authorized operator replaces it.
  GET and PUT require an active instance, so a deleted instance's retained
  policy can be changed only after the logical instance is recreated.

## Related

- ADR-0004 (defines materialization and at-least-once reactor dispatch)
- ADR-0010 (defines team mirror reconciliation)
- ADR-0021 (defines logical integration instance identity)
