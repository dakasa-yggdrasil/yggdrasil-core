# Events and audit

Every state change in Yggdrasil emits a typed event into Postgres,
in the same transaction that wrote the state. Event consumers tail
one table — there's no separate event store, no eventual consistency,
no "did the audit log catch up?" question.

## What it is

The `event_log` table holds an append-only outbox of typed events:

```
id              UUID         (event id)
type            TEXT         e.g. "manifest.created"
schema_version  TEXT         e.g. "v1"
aggregate_type  TEXT         e.g. "manifest"
aggregate_id    TEXT         the resource id
actor           JSONB        { type: "collaborator", id: "..." } when known
payload         JSONB        type-specific
created_at      TIMESTAMPTZ
```

Events are emitted via `repository.EmitEvent(ctx, tx, req)` — a Tx
is required, which is what guarantees transactional emission. If the
write rolls back, the event rolls back with it.

## Event types currently emitted

| Type | When |
|---|---|
| `manifest.created` | A new manifest version landed. |
| `manifest.updated` | Reserved for future label/metadata-only updates. |
| `manifest.deleted` | A manifest was tombstoned. |
| `workflow.run.started` | A run was dispatched. |
| `workflow.run.step.succeeded` / `.failed` / `.skipped` | Per-step result. |
| `workflow.run.succeeded` / `.failed` | Final run result. |
| `authorization.evaluated` | RBAC + policy evaluation, allow or deny. |
| `integration.installed` | A `yggdrasil install` quickstart completed. |
| `integration.executed` | An integration RPC completed (success or failure). |
| `secret.rotated` / `.created` / `.revoked` | Managed-secret lifecycle. |
| `session.created` / `.revoked` | Auth lifecycle. |
| `bootstrap.first_admin_created` | First-run bootstrap fired. |

Every payload carries enough context to reconstruct *what happened*
without joining other tables — type + aggregate ids + the resolved
manifest/instance/collaborator references.

## Consumer patterns

### Outbox tail (recommended)

A long-running worker tails `event_log` ordered by `id`, processes,
checkpoints. Standard outbox pattern. Each consumer keeps its own
checkpoint:

```sql
CREATE TABLE consumer_checkpoint (
  consumer_name TEXT PRIMARY KEY,
  last_event_id UUID NOT NULL
);
```

Process loop:

```sql
SELECT * FROM event_log
 WHERE id > $1
 ORDER BY id
 LIMIT 100;
```

After processing the batch, write back the highest id seen.
At-least-once semantics; consumers are responsible for idempotency
(the event id is the natural dedup key).

### Push to a stream (Kafka, NATS, EventBridge)

A simple bridge consumer that publishes each row to your stream of
choice. Most teams put this together in <100 lines.

### Real-time subscription (LISTEN/NOTIFY)

Postgres `LISTEN/NOTIFY` works for low-latency consumers. Less
durable than tailing `event_log` directly — combine with the outbox
pattern (NOTIFY for "new events available", outbox query for actual
read).

## Publishing events from outside

Reactive sources — Grafana webhooks, Kubernetes informers, custom
shell scripts — drop typed events into the stream over the public
publish endpoint:

```http
POST /api/v1/events
Authorization: Bearer <YGGDRASIL_WORKFLOW_RUN_TOKEN>
Content-Type: application/json
```

```bash
curl -X POST https://yggdrasil.example.com/api/v1/events \
  -H "Authorization: Bearer ${YGGDRASIL_WORKFLOW_RUN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "infra.alert.firing",
    "schema_version": "v1",
    "aggregate_type": "alert",
    "aggregate_id": "grafana/abc-123",
    "payload": {
      "alert": { "summary": "node disk over 90%", "severity": "critical" },
      "labels": { "service": "yggdrasil-core" }
    },
    "actor": { "type": "system", "id": "grafana" }
  }'
```

Returns `201 Created` with the generated event id:

```json
{ "event_id": "01935e3d-9c91-7c10-8deb-b6f1abcdef01" }
```

The endpoint is idempotent at the API level only: every successful
call appends a new row. Callers that need at-most-once delivery
should either dedup at the source or pin a stable
`(aggregate_type, aggregate_id)` and let the consumer dedup.

**Validation.** `type`, `aggregate_type`, `aggregate_id` and
`payload` are required. `payload` MUST be a JSON object so workflows
can reference `{{ inputs.event.<field> }}`. `schema_version` defaults
to `"v1"` when omitted. The payload is validated against the JSON
Schema registered for `<type>` in `docs/contracts/events/v1/`; new
event types must register a schema before the API will accept them
(returns `400` with the diagnostic otherwise).

**Auth.** Same shared token as `POST /api/v1/workflow-runs`. Set
`YGGDRASIL_WORKFLOW_RUN_TOKEN` in the deployment env; clients send
it in `Authorization: Bearer …` or `X-Yggdrasil-Workflow-Token`.
When the env var is unset the endpoint is open (dev mode), exactly
like `/api/v1/workflow-runs`.

## Reactive workflows

A workflow declared with `trigger.mode=event` fires automatically
whenever a published event matches its filters. The wiring is
end-to-end inside core: no external worker, no extra component.

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: workflow
metadata:
  name: respond-to-disk-alert
  namespace: ops
spec:
  trigger:
    mode: event
    enabled: true
    event:
      types: ["infra.alert.firing"]
      aggregate_filter:
        aggregate_type: alert
      payload_filters:
        - path: alert.severity
          operator: eq
          value: critical
      default_inputs:
        runbook: drain-and-page
  steps:
    - id: page
      use: { kind: integration, family: pager, operation: page }
      with:
        message: "{{ inputs.event.alert.summary }} ({{ inputs.runbook }})"
```

**Payload templating.** The matched event's payload is exposed under
the input key `event`. Steps reference any field with
`{{ inputs.event.<dotted.path> }}` — in the example above,
`inputs.event.alert.summary` resolves to the `summary` field of the
posted payload.

**`default_inputs` precedence.** Keys declared in
`trigger.event.default_inputs` override the same keys in the
payload-derived inputs. This is a deliberate escape hatch: if an
operator wants to pin a known value over whatever the source posted,
they list the same key in `default_inputs` and it wins. Note that
declaring `event` as a default_inputs key replaces the entire
payload-derived map.

**Idempotency.** The dispatcher uses the
`workflow.event.matched` event in `event_log` as its dedup key —
keyed on `(workflow_manifest_id, payload.matched_event_id)`. Two
leader passes over the same window cannot dispatch the same workflow
twice for the same source event. A crash between the matched-event
commit and the dispatch insert leaves the matched record present, so
the next pass sees it and bails (the source event is dropped — the
workflow does not retry-on-crash by design; rerunning is the
operator's call).

**Disabled triggers.** Workflows with `trigger.enabled=false` (or any
falsy value) are loaded but skipped during the match step, so an
operator can disable a noisy workflow by toggling one field instead
of deleting it.

## Wire shape (read API)

```http
GET /api/v1/events?after=<event_id>&type=manifest.created&limit=100
```

Returns a paginated response:

```json
{
  "events": [
    {
      "id": "01935e3d-...",
      "type": "manifest.created",
      "schema_version": "v1",
      "aggregate_type": "manifest",
      "aggregate_id": "01935...",
      "actor": { "type": "collaborator", "id": "ana" },
      "payload": {
        "manifest_id": "01935...",
        "kind": "workflow",
        "namespace": "global",
        "name": "deploy-service",
        "version": 7,
        "checksum": "sha256:..."
      },
      "created_at": "2026-04-23T..."
    }
  ],
  "next_after": "01935e3d-..."
}
```

## Operate it

**Monitor:**

- `event_log` row growth rate. Sudden spikes usually mean a runaway
  workflow or a reconciler loop.
- Consumer lag. Outbox consumers should expose their distance from
  the head of the table. Lag growing unbounded → scale the consumer
  or fix the bottleneck.
- Failed event emissions. Should be impossible (transactional), but
  if you see them, the DB is in trouble.

**Back up:**

`event_log` is part of the standard Postgres backup. Critically, it
*must* be in the same backup as the state tables — restoring just
state loses the audit, restoring just events loses the source of
truth that explains them.

**Archive:**

`event_log` grows monotonically. For deployments at scale, archive
events older than N days/months to cheap object storage (parquet
files in S3 work well) and drop from the hot table. The
[operations/scaling.md](../operations/scaling.md) guide covers this
with concrete SQL.

## Pitfalls

- **Treating events as the source of truth.** They aren't — the state
  tables are. Events are the audit + downstream notification stream.
  A consumer that reconstructs state from events is doing more work
  than reading the state tables directly.
- **Missing event from a custom integration.** Adapters do not write
  to `event_log` directly; they return a result, and the engine
  emits the event. If you're rolling a custom adapter and want extra
  audit signal, return rich metadata in the execute response — don't
  reach into the core's DB.
- **Ordering across consumers.** `event_log.id` is monotonic per row
  but does not guarantee global ordering across all aggregates. If
  you need strict per-aggregate ordering downstream, partition the
  consumer by `aggregate_id`.
- **Schema evolution.** `schema_version` is part of the row for a
  reason. When a payload shape changes, bump the version and have
  consumers handle both. Never reuse a `type` with a changed shape
  silently.
