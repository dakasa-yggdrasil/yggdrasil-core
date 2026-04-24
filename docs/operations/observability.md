# Observability

Logs, metrics, traces — and the event stream, which is Yggdrasil's
native audit fabric and effectively a fourth observability pillar.

## Logs

The core and every first-party adapter log as structured JSON to
stdout via zap. Your infrastructure picks them up:

- Kubernetes → cluster logging (fluent-bit, Vector, Loki, Datadog, …).
- Compose → `docker compose logs` or a log-shipping sidecar.
- Bare-metal → journalctl or logrotate into your log agent.

### Log levels

Controlled by env:

```
LOG_LEVEL=info   # default. INFO + WARN + ERROR.
LOG_LEVEL=debug  # INFO plus adapter handshake + evaluator decisions.
```

Leave `info` in prod. Use `debug` locally when reproducing a bug.

### Important log lines to alert on

| Pattern | Meaning | Alert? |
|---|---|---|
| `msg="first_run_bootstrap: ..."` | Bootstrap addon ran on startup. | Informational; alert if it fires on a pod that shouldn't see empty DB. |
| `msg="integration_instance_runtime_state transitioned" status="unreachable"` | Adapter handshake failed. | Yes, page oncall. |
| `msg="authorization denied"` with `reason="policy"` and high rate | Policy change caused mass denials. | Yes — humans took out their permissions. |
| `level=error` on repeated `workflow.dispatch` failures | Engine can't dispatch. Broker / DB issue. | Yes, page. |
| `panic` | Should not happen. Crash loop. | Absolutely. |

## Metrics

Yggdrasil does not expose a Prometheus endpoint on the core binary
today (it's on the roadmap). Until then, you have three first-class
sources:

### 1. `event_log` as a metric source

Every typed event is a time-stamped data point. Run a small
consumer that emits Prometheus counters/histograms from the event
stream — 50 lines of Go or Python, pattern-match the type, bump a
counter.

Essential metrics derivable from events:

- Workflow run count + success/failure ratio (`workflow.run.*`).
- Step latency (computed from `started_at` / `finished_at` fields).
- Authorization deny ratio (`authorization.evaluated` with
  `decision="deny"`).
- Integration execute rate + error rate.
- Secret rotation rate + failures.
- Manifest write rate, per kind.

### 2. HTTP access logs

From your ingress. Gives you request rate, p50/p95/p99 latency, and
error rate per endpoint family. Standard Prometheus/Loki derivations
work fine.

### 3. Process-level metrics

From cAdvisor / node_exporter:

- Container CPU + memory.
- FD count (should stay flat — spikes mean a goroutine leak).
- Open Postgres connections per pod.
- Open AMQP channels per pod *(only when using `transport: rabbitmq`)*.

### Recommended dashboards

Minimum three dashboards for a prod deployment:

1. **Yggdrasil overview.** Request rate, latency, error rate per
   endpoint family + workflow run rate + success ratio + event log
   growth rate.
2. **Integration health.** Per-family `execute` latency (p95/p99),
   error rate, adapter pod replica count. Breaks down which integration
   is sick when things go sideways.
3. **Infra.** Postgres (connections, slow queries, tx commit rate,
   disk usage), message broker when in use (queue depth per queue,
   message rate, channel count), adapter services (HTTP latency + 5xx
   rate for HTTP-transport adapters), core pods (CPU/mem/FD).

Cheap to build. Enormously valuable during incidents.

## Traces

Two interesting sets of spans:

- Per HTTP request on the core.
- Per workflow run step, including the transport round-trip to the
  adapter (HTTP request or AMQP RPC, whichever the integration uses).

Neither is wired out-of-the-box yet. When you wire traces
(OpenTelemetry Go SDK, propagate trace context via HTTP headers or
AMQP headers per transport), these are the spans you want:

- `http.request` — the core's top-level HTTP handler.
- `manifest.persist` — the validate + checksum + tx + emit pipeline.
- `workflow.run` — the full run.
- `workflow.step.render` — template rendering.
- `workflow.step.dispatch` — transport call to adapter (HTTP or AMQP).
- `integration.describe_handshake` — the per-use verification.

A typed span per step is the difference between "a workflow step
was slow" and "the schema-migration-goose-postgres provider's
`apply_migrations_spec` operation took 8s because `connect to
Postgres` took 7s".

## The event stream as an audit trail

Covered in depth in [features/events.md](../features/events.md).
For SRE purposes, the key property: *every transition is durably
recorded*. A postmortem reconstructs the timeline by ordering events
by id.

Typical incident-response SQL:

```sql
-- What happened to this workflow run?
SELECT id, type, payload, created_at
  FROM event_log
 WHERE aggregate_type = 'workflow_run'
   AND aggregate_id = '01935...'
 ORDER BY id;

-- Who denied access in the last hour?
SELECT actor, payload->'resource' AS resource, payload->'policy' AS policy,
       created_at
  FROM event_log
 WHERE type = 'authorization.evaluated'
   AND payload->>'decision' = 'deny'
   AND created_at > now() - interval '1 hour'
 ORDER BY id DESC;
```

## Alerting golden rules

- **Alert on SLO breaches, not raw numbers.** "Availability < 99.5%
  over 5 min" beats "latency > 200ms".
- **Alert on integration handshake drift.** It's the earliest
  indication of broker or adapter rot.
- **Alert on event_log consumer lag.** Your audit pipeline falling
  behind is a compliance risk, not just an engineering one.
- **Don't alert on Postgres connection count alone.** It's a
  secondary symptom; alert on the pool-exhaustion error instead.

## Health endpoints

- `/healthz` — process is alive (cheap, no DB hit). Use for
  liveness probes.
- `/readyz` — process + Postgres reachable + migrations at head.
  Use for readiness probes. `yggdrasil init` waits for this before
  declaring success.
