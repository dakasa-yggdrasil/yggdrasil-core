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
