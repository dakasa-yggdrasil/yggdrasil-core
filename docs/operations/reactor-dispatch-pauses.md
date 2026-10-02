# Selective reactor dispatch pauses

The operator policy is stored by the integration instance's logical
`namespace/name`. It does not change the instance manifest, integration type,
`observe_*` calls, or action catalog. No pause is active until an authorized
operator writes one after the source is deployed.

## Read and replace

`GET /api/v1/ops/integration-instances/{namespace}/{name}/reactor-dispatch`
returns the exact `paused_event_types` list and `revision` for an active
instance. An unwritten policy returns an empty list and revision `0`; an
empty list means dispatch is enabled. The route requires
`yggdrasil:view_integrations` and returns `404` without an active instance.

`PUT` to the same path replaces the whole set. Read the current revision with
GET, then include it in the request:

```json
{"paused_event_types":["team.created","team.updated"],"expected_revision":0}
```

To resume after that first PUT, send
`{"paused_event_types":[],"expected_revision":1}`. Use the latest revision
from GET or the preceding PUT response. Each successful PUT increments
the revision and returns the new policy. A stale revision returns `409`; read
the policy again before deciding on the replacement. The route requires
`yggdrasil:manage_integrations` and a verified console session with a valid
collaborator ID. The policy change and its success audit record use the same
database transaction; an audit failure aborts the policy change. Names must
be exact canonical lifecycle event names or valid integration mutation event
names; wildcards, duplicates, surrounding whitespace, and more than 128
entries are rejected. Mutation names follow
`<provider>.<resource>.(ensured|destroyed|created)` with lowercase
snake-case provider and resource parts.

The policy remains after a manifest deletion. GET and PUT require an active
instance, so recreating the same logical name inherits the retained pause;
review it and explicitly resume or replace it after recreation.

## Backlog and replay

Normal events continue to create durable reactions while paused. Paused rows
stay pending or failed without consuming another attempt. Reactions claimed
just before a pause are rechecked before processing and before RPC. This is
not a strict drain: PUT can commit between the final recheck and RPC start,
so an adapter call may start or finish after PUT returns. The team reconciler
skips paused `team.created` gaps and does not queue synthetic reactions for
paused destinations. On resume, unresolved gaps become eligible only when
there is no nonterminal ordinary `team.created` reaction for that team and
logical instance.

`/metrics` exposes `yggdrasil_reactor_paused_backlog_reactions`,
`yggdrasil_reactor_paused_backlog_oldest_age_seconds`, and
`yggdrasil_reactor_paused_backlog_refresh_timestamp_seconds`. They are
aggregate gauges without instance identifiers or event payloads, refreshed
by the dispatcher about once a minute. A zero refresh timestamp means no
successful sample has been collected. The count includes pending, failed,
and in-progress reactions whose exact event type is paused.

To inspect one logical instance, query only operational columns:

```sql
SELECT r.event_type, r.status, COUNT(*) AS reactions,
       MIN(r.created_at) AS oldest_created_at
FROM public.integration_event_reactions r
JOIN public.manifests old_ii ON old_ii.id = r.integration_instance_id
WHERE old_ii.kind = 'integration_instance'
  AND old_ii.namespace = $1 AND old_ii.name = $2
  AND r.status IN ('pending', 'failed', 'in_progress')
GROUP BY r.event_type, r.status
ORDER BY r.event_type, r.status;
```

The event cleaner and manifest purge retain rows backing nonterminal
reactions even after their normal TTL. After a reaction reaches a terminal
state, normal retention can remove it. Hard manifest deletion is destructive
and must be reviewed separately. Resuming a large backlog can create an
adapter burst; resume by instance and event type while watching count, age,
dispatch outcomes, and database capacity.
