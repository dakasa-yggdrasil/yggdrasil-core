# Scaling Yggdrasil

This page covers the concrete numbers and the steps when you outgrow
each one. Yggdrasil scales horizontally on the core and on adapters,
vertically on Postgres, and — when AMQP transport is in use — via
standard broker HA techniques.

## What scales how

| Component | Scale model | Bottleneck signal |
|---|---|---|
| `yggdrasil-core` | Horizontal (stateless replicas behind a service). | CPU pegged on read endpoints, dispatch lag. |
| Postgres | Vertical first (CPU + IOPS), read replicas later for read-heavy surfaces. | Connection saturation, slow queries on `manifest_version` / `event_log`. |
| Message broker *(when `transport: rabbitmq` is used)* | HA cluster or quorum queues; horizontal nodes for throughput. | Queue depth growing on `yggdrasil.adapter.*.execute`. Skip entirely if you only use `transport: http_json`. |
| Adapter pods | Horizontal per integration_type. Scales the same way for HTTP and AMQP transports. | Adapter `execute` reply latency rising. |
| Surface pods | Horizontal, independent of core. | Surface request latency rising. |

The quick rule: scale the layer where the bottleneck shows up, not
the layer that *feels* obvious.

## Core replicas

Core is stateless. Default Helm `replicaCount: 2`; bump up when:

- p95 HTTP latency on read endpoints exceeds your SLO.
- HPA triggers consistently (default targets 80% CPU + memory).

```yaml
# values.yaml
replicaCount: 5
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 70
```

The HPA is conservative on memory because Go's GC plus Postgres
connection pools create memory pressure that's not always linear with
load.

### Connection pool sizing

Each replica opens a Postgres pool. The default pool is small (15) on
the assumption you have 2-3 replicas. With 20 replicas, you have
~300 concurrent DB connections — more than most managed Postgres
defaults allow.

When you scale past 5 replicas, either:

- Bump Postgres `max_connections` proportionally, OR
- Front Postgres with `pgBouncer` in transaction-pooling mode.

The second option is the standard answer past 10 replicas.

## Postgres

The primary state store. Sized for:

- Manifest catalog (modest — 100k manifests is well under 1 GB).
- `event_log` (grows monotonically, archive policy described below).
- `workflow_run` + `workflow_run_step` (one row per step, retain per
  audit policy).

### Vertical sizing

| Daily workflow runs | Recommended Postgres |
|---|---|
| < 1k | 2 vCPU, 4 GiB, 50 GiB SSD |
| 1k–10k | 4 vCPU, 16 GiB, 200 GiB SSD |
| 10k–100k | 8 vCPU, 32 GiB, 500 GiB SSD |
| > 100k | 16+ vCPU, 64+ GiB, 1+ TiB SSD with provisioned IOPS |

These assume you also archive `event_log`. Without archival, double
the disk every 90 days at the higher rates.

### Read replicas

Yggdrasil reads from one Postgres connection pool. When you need
read scaling (heavy console traffic, third-party catalog consumers),
the path is:

1. Provision a read replica.
2. Front read endpoints (`GET /api/v1/manifests`, `GET /api/v1/events`)
   with a separate connection pool pointing at the replica.
3. Keep all writes (and the event-emitting paths) on the primary.

This is not implemented out of the box yet — track the
[issue tracker](https://github.com/dakasa-yggdrasil/yggdrasil-core/issues)
or contribute the read-only DB pool option.

### `event_log` archival

The most aggressive grower. At 100k workflow runs/day with ~5 events
per run, that's 15M events/month. After a year, ~180M rows.

Archive procedure:

```sql
-- 1. Copy events older than 90 days to a staging table.
CREATE TABLE event_log_archive_2026_01 (LIKE event_log INCLUDING ALL);
INSERT INTO event_log_archive_2026_01
  SELECT * FROM event_log
   WHERE created_at < now() - interval '90 days';

-- 2. Export the staging table to object storage (parquet/JSON):
--    pg_dump --table=event_log_archive_2026_01 --data-only ...

-- 3. Delete from hot table.
DELETE FROM event_log WHERE created_at < now() - interval '90 days';
VACUUM (FULL, ANALYZE) event_log;

-- 4. Drop the staging table.
DROP TABLE event_log_archive_2026_01;
```

Run monthly. Automate via a `workflow` that uses the
[integration-database-admin](https://github.com/dakasa-yggdrasil/integration-database-admin)
adapter, gated by an RBAC role only the platform team holds.

## Message broker (AMQP transport only)

Skip this section if none of your integrations declare
`transport: rabbitmq`. For those that do, the broker carries every
`integration.execute` request/reply for that transport.

The guidance below is for RabbitMQ (the AMQP implementation shipped
today). A custom transport plug-in that targets Kafka or NATS will
have its own scaling story — follow the tool's docs.

### Queue throughput

Single-node RabbitMQ handles ~5k messages/sec comfortably. If you're
dispatching > 1k workflow runs/sec (each generating multiple steps),
move to a 3-node cluster.

### HA mode

Two reasonable choices:

- **Quorum queues** (Raft-replicated). Recommended for new deployments.
  Survives node failure; predictable latency.
- **Mirrored classic queues**. Older, less recommended. Use only for
  compatibility with existing tooling.

The bundled bitnami subchart defaults to non-HA — fine for a trial,
not fine for prod. For production, set `rabbitmq.enabled: false` in
the chart and point at a managed RMQ or your own clustered install.

### Per-adapter dedicated queues

For adapters that get hammered (Kubernetes is the usual suspect),
isolate their queue traffic by deploying multiple adapter pods —
each pod is a consumer on the same queue, work is round-robined.

```yaml
# In your kubernetes adapter deployment
spec:
  replicas: 5
```

5 pods, 5 concurrent consumers, 5x the adapter throughput.

## Adapter pods

Each integration adapter is independent. Scale per the load it sees.

| Adapter | Typical replica count |
|---|---|
| `integration-kubernetes` | 3–10 (most loaded — every product apply hits it) |
| `integration-aws` / `integration-gcp` | 1–3 |
| `integration-grafana` | 1–2 |
| `integration-rabbitmq` (topology) | 1 (low call rate) |
| `integration-schema-migrations` | 2–5 (peaks during deploy windows) |
| `integration-secrets-management` | 1–3 |

Auto-scale on CPU; the workload is bursty by nature.

## Surface pods

Surfaces are pure HTTP. Scale on request rate. The console is the
biggest spender (page loads pull lots of catalog data); a custom BFF
can be smaller.

## Multi-cluster / multi-region

Yggdrasil's deployment scope is one core + one Postgres + one RMQ.
For multi-region:

| Pattern | When |
|---|---|
| **One core, multiple regions for adapters** | Different clusters per region; each cluster runs its own adapter pods. The core dispatches to the right region by `integration_instance` selection. |
| **Multiple cores, federated catalog** | Each region has its own core + DB. A separate federation tier (Backstage, custom UI) reads from all cores. Prevent split-brain by having each manifest live in *one* core only. |
| **Multi-region for HA, not throughput** | Active/passive Postgres replication; passive core runs but doesn't accept writes; failover triggers core to take over. |

The first pattern is what most teams need. The second is for
genuinely independent regional ops. The third is a DR play, not a
scaling play.

## Watch list (graphs to keep on a dashboard)

1. Core HTTP request rate, by endpoint family (`/manifests`,
   `/workflow-runs`, `/integration-catalog`).
2. Core p95 + p99 latency, by endpoint family.
3. Postgres: connections in use, transaction commit/rollback rate,
   slow query count.
4. RabbitMQ: queue depth per `yggdrasil.adapter.*.execute`,
   message in/out rate, channel count.
5. Adapter `execute` reply latency p95, by family.
6. `event_log` row count, growth rate.
7. `manifest_version` row count.
8. Workflow run rate, success/failure ratio.
9. RBAC + policy `evaluated` rate, deny ratio.

The set above tells you when, where, and how to scale before users
notice.
