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

## Publishing mutation events from outside

Integration adapters publish their successful mutations over the dedicated
machine endpoint:

```http
POST /api/v1/events
Authorization: Bearer <event-publisher bearer>
Content-Type: application/json
```

```bash
curl -X POST https://yggdrasil.example.com/api/v1/events \
  -H "Authorization: Bearer ${YGGDRASIL_EVENT_PUBLISHER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "aws.bucket.ensured",
    "provider": "aws",
    "resource": "bucket",
    "verb": "ensured",
    "resource_id": "assets-prod",
    "instance_id": "aws-primary",
    "idempotency": "ensure-assets-prod-v7",
    "observed": {"region": "sa-east-1"},
    "emitted_at": "2026-09-05T12:00:00Z"
  }'
```

Returns `201 Created` with the generated event id:

```json
{ "event_id": "01935e3d-9c91-7c10-8deb-b6f1abcdef01" }
```

Mutation publication is idempotent on `(event_type, idempotency)` within the
configured retention window. Generic control-plane events are emitted from
trusted in-process paths; hashed publishers, the plaintext migration bridge,
and human console sessions cannot submit that generic shape over this route.

**Mutation validation.** `event_type`, `provider`, `resource`, `verb`,
`resource_id`, `instance_id`, and `idempotency` are required. The denormalized
provider/resource/verb fields must agree with the canonical
`<provider>.<resource>.<ensured|destroyed|created>` event type, and the
authenticated principal must contain the exact provider/instance/event triple.

**Generic local-compatibility validation.** Only when the event auth surface is
entirely unconfigured outside production, the historical generic HTTP shape
remains available for development and tests. In that posture, `type`,
`aggregate_type`, `aggregate_id`, and `payload` are required; `payload` must be
a JSON object and `schema_version` defaults to `"v1"`. The payload is validated
against the registered event JSON Schema. Production machine credentials never
authorize this shape.

**Auth.** Give each event writer a bearer whose SHA-256 digest is configured in
`YGGDRASIL_EVENT_PUBLISHER_PRINCIPALS_JSON` with `principal_id`, lifecycle,
expiry, rotation metadata, and a non-empty `allowed_events` list of exact
`{provider,instance_id,event_type}` mutation triples. The JSON never contains
the raw bearer and cannot contain workflow scopes or wildcards. A machine
publisher cannot submit the generic event shape or another principal's
provider, instance, or event type; the server overwrites its event actor and
reserved publisher metadata from the authenticated identity. Clients send the
bearer in `Authorization: Bearer …` or `X-Yggdrasil-Event-Token`.

`YGGDRASIL_EVENT_PUBLISH_TOKEN` remains only as a plaintext event-route bridge
for existing adapters. It is rejected unless
`YGGDRASIL_EVENT_PUBLISH_LEGACY_ENABLED=true` and
`YGGDRASIL_EVENT_PUBLISH_LEGACY_EXPIRES_AT` is a future RFC3339 timestamp. It is
mutation-only, and the server overwrites any supplied actor with the reserved
`legacy-event-publish-bridge` service identity. Human console sessions and
workflow credentials are never accepted. Production refuses to boot without
an active event principal or that explicit, unexpired bridge and rejects any
collision with workflow, deploy, auth-admin, or hashed event-principal
credentials. The bridge and hashed publishers must use distinct bearers so a
principal cannot fall back to bridge authority after expiry or revocation. When
the event surface is entirely unconfigured outside production, it remains open
for credential-free local development and tests.

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
