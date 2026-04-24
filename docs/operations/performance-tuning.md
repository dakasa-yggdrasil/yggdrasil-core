# Performance tuning

When Yggdrasil is slow, the answer is almost always one of four
things. This page walks the four in order of likelihood.

## Triage in 5 minutes

Before touching anything, answer:

1. Which endpoint / operation is slow? (Look at access logs +
   `event_log` step latencies.)
2. Is Postgres busy? (Check active connections + slow query count.)
3. Is the broker backed up? (Queue depth on
   `yggdrasil.adapter.*.execute`.)
4. Is the slow step's adapter healthy? (Adapter's `describe` reply
   latency, `integration_instance_runtime_state`.)

The answer to one of those four is almost always the answer.

## 1. Postgres

The biggest latency contributor by far. Symptoms:

- Slow `/api/v1/manifests` reads.
- High `TxRollback` counts (retries piling up).
- Pool exhaustion errors.

### Common fixes

**Missing index.** The usual suspect on a loaded deployment. Check
what query planner is doing:

```sql
EXPLAIN ANALYZE SELECT * FROM manifest_version
  WHERE manifest_id = '...' ORDER BY version DESC LIMIT 1;
```

The shipped migrations cover the default access patterns. If you
added custom ones (custom labels, custom joins), add the matching
index.

**`VACUUM` and `ANALYZE` behind.** After heavy writes the planner
misses. Postgres autovacuum handles this, but `event_log` at scale
can benefit from an explicit schedule:

```sql
VACUUM (VERBOSE, ANALYZE) event_log;
```

Or run it through a workflow using
[integration-database-admin](https://github.com/dakasa-yggdrasil/integration-database-admin).

**Connection pool too small.** Default pool is sized for 2-3 replicas.
At 10 replicas, either increase the pool per replica or use
`pgbouncer` in transaction mode.

**`event_log` hot.** Appending events on every write is a minor
cost; querying `event_log` across a year of history is an enormous
one. Archive per
[scaling.md](./scaling.md#event_log-archival) and keep hot data
under 90 days.

### Postgres tuning knobs worth knowing

| Parameter | Default | Recommendation |
|---|---|---|
| `shared_buffers` | 128 MB | 25% of RAM. |
| `effective_cache_size` | 4 GB | 50-75% of RAM. |
| `work_mem` | 4 MB | 16-64 MB for a workload-heavy install. |
| `maintenance_work_mem` | 64 MB | 256 MB+ for faster VACUUM. |
| `max_connections` | 100 | Match your core-replica × pool size. |
| `autovacuum_vacuum_cost_limit` | 200 | 1000+ if autovacuum is falling behind. |

Managed Postgres providers usually pre-tune these. If you self-host,
the defaults are not good enough past trial scale.

## 2. RabbitMQ

Adapter dispatch traffic is the broker's main load. Symptoms:

- Queue depth on `yggdrasil.adapter.<family>.execute` growing
  faster than draining.
- Workflow steps timing out with "no reply from adapter".
- Broker CPU pinned.

### Common fixes

**Not enough adapter replicas.** Each adapter pod is one AMQP
consumer. If a step family gets hit 1000 times in a minute and the
adapter has 1 replica, steady-state throughput is 1 step at a time.
Scale the adapter — see
[scaling.md](./scaling.md#adapter-pods).

**Adapter blocks on a downstream system.** If the Kubernetes
adapter waits 10s for a server-side apply, one replica handles 6
requests/minute. Increase concurrency: most adapters set
`prefetch_count = 1` by default (safest, least throughput). Bump
to 4-8 if your adapter is stateless per call.

**Classic queues with mirroring.** High overhead at modern
throughput. Migrate to quorum queues.

**Broker CPU starvation.** Unlikely on modest RMQ hosts, but if
you see it: more nodes in the cluster, not bigger nodes. RMQ scales
horizontally better than vertically.

## 3. The adapter itself

Symptoms:

- Per-family `execute` p95 well above what the downstream API's own
  latency would suggest.
- `describe` handshake failures.
- Adapter crashes / restarts visible in pod logs.

### Common fixes

**Stale describe cache.** A container that crashes and is rescheduled
might re-register a describe that drifts from the stored `integration_type`.
Fix: redeploy, let the handshake re-verify, or bump `adapter.version`.

**Downstream rate limit.** The adapter is fine; the AWS/GCP/GitHub
API is throttling. Check the adapter's error metadata — most surface
the upstream error cleanly. Answer: back off at the caller
(`retry.backoff_seconds`), not at the adapter.

**Blocking I/O without parallelism.** Adapter handles one AMQP
message at a time. If the operation does a lot of wait, a per-handler
goroutine pool helps. See
[integration-template/controllers/message](https://github.com/dakasa-yggdrasil/integration-template/tree/main/controllers/message)
for the pattern.

## 4. Workflow authoring

Not always an infrastructure issue — sometimes the workflow itself is
the problem.

### Red flags

- **Chain of N sequential adapter calls that could be parallel.** Use
  `depends_on` minimally; steps with no common predecessor run in
  parallel automatically.
- **Unbounded fan-out.** Spawning 1000 parallel steps to process 1000
  items overwhelms the broker. Batch server-side (one step that
  processes 100 items) or cap parallelism at the workflow level.
- **Template rendering of huge payloads.** Rendering a 10 MB manifest
  string on every step costs more than you think. Split into smaller
  manifests or pass references, not inline blobs.
- **Retries on already-expensive calls.** `retry.max_attempts: 3` on
  a step that itself takes 30s can eat your SLO. Set retries
  minimally on dispatching steps (CI, Argo); rely on the downstream
  tool's own retry.

## Go-specific tuning (core binary)

Rare bottleneck but worth knowing.

- `GOMAXPROCS` matches CPU limits set by the container.
- `GOGC` defaults to 100; 50 lowers memory at the cost of CPU.
  Don't change unless memory is constrained.
- Pool the Postgres + AMQP clients at the package level; don't open
  new ones per request. (The core already does this; custom
  adapters sometimes miss it.)

## HTTP timeouts

Defaults shipped in the chart:

```yaml
http:
  readHeaderTimeoutSeconds: 10
  readTimeoutSeconds: 30
  writeTimeoutSeconds: 30
  idleTimeoutSeconds: 120
```

Bump `writeTimeoutSeconds` if you synchronously dispatch workflows
that take > 30s (via `/api/v1/workflow-runs`). The step-timeout
discussion in [features/workflows.md](../features/workflows.md) is
orthogonal — both limits apply.

## What "good" looks like

A healthy production deployment, on modest hardware:

| Metric | Target |
|---|---|
| `/api/v1/manifests` p95 | < 50 ms |
| `/api/v1/manifests` p99 | < 200 ms |
| Workflow step dispatch p95 | < adapter's own latency + 20 ms |
| Authorization evaluate p95 | < 5 ms |
| Postgres queries/sec | low thousands, well under max_connections |
| RMQ queue depth | ~0 at steady state |
| Adapter `describe` handshake | < 100 ms |

Drift from these targets is a signal, not a crisis. Track them as
SLOs.
