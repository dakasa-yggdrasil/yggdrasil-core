# yggdrasil-core SLOs

Audit ref: G9 (SLO definitions + dashboards). This doc is the
authoritative SLO contract for the control-plane binary. Surfaces
(console, auth, etc.) carry their own SLO docs.

## Window + targets

| SLI | Target | Window | Source metric |
|---|---|---|---|
| Availability (write API) | 99.9% | 90d rolling | `yggdrasil_workflow_runs_total{status="succeeded"}` / `sum(yggdrasil_workflow_runs_total)` |
| Availability (auth API)  | 99.9% | 90d rolling | `yggdrasil_auth_login_total{outcome="succeeded"}` / `sum(yggdrasil_auth_login_total{outcome!="failed",outcome!="rate_limited"})` |
| Latency (p95 read API)   | < 300ms | 7d rolling | TBD — needs http_request_duration_seconds histogram (G9 followup) |
| Latency (p95 auth login) | < 500ms | 7d rolling | TBD — PBKDF2 dominates; histogram required |
| Error budget (write)     | 0.1% (43m/30d) | 30d rolling | derived from availability SLI |

The auth latency target is deliberately 500ms because the password
verification path is PBKDF2 (200k iterations on the legacy scheme,
Argon2id on the new scheme — both intentionally expensive). Lower
targets cause false-positive burn alerts that train operators to
silence the page.

Async dispatch endpoints (`POST /api/v1/workflow-runs` with
`?mode=async`, `POST /api/v1/events`) are EXCLUDED from the latency
SLI because they queue rather than block; their durability is
captured by `yggdrasil_reactor_dispatches_total` instead.

## Error budget burn alerts

Two-tier alert per the Google SRE workbook pattern:

| Window | Burn rate | Alert severity | Notification path |
|---|---|---|---|
| 1h     | 14.4x (2% of monthly budget burned) | page  | PagerDuty (TODO — Slack first) |
| 6h     | 6x    (5% of monthly budget burned) | ticket | Slack #yggdrasil-ops |

Prometheus rule snippets live in
`monitoring/prometheus/yggdrasil-slo-alerts.yaml` (next to the
existing capability-naming-validator-alerts.yaml).

## Recording rules

Defined in `monitoring/prometheus/yggdrasil-slo-recording-rules.yaml`:

```promql
# availability_ratio_5m: rolling 5-minute success ratio.
record: yggdrasil:workflow_availability_ratio:rate5m
expr: |
  sum(rate(yggdrasil_workflow_runs_total{status="succeeded"}[5m]))
  /
  sum(rate(yggdrasil_workflow_runs_total[5m]))
```

```promql
# auth_success_ratio_5m: login success / non-bot attempts.
# Excludes rate_limited which are bot/abuse.
record: yggdrasil:auth_success_ratio:rate5m
expr: |
  sum(rate(yggdrasil_auth_login_total{outcome="succeeded"}[5m]))
  /
  sum(rate(yggdrasil_auth_login_total{outcome!="rate_limited"}[5m]))
```

## Dashboards

- Grafana: `monitoring/grafana/yggdrasil-slo-dashboard.json` — ship via
  `integration-grafana.ensure_dashboard` workflow.
- Panels:
  1. Availability stat (write API, 30d)
  2. Auth success ratio (5m rolling)
  3. Workflow runs by status (timeseries)
  4. Reactor dispatches by outcome
  5. Auth metric family pivot (login outcome by time)
  6. Error budget remaining (gauge derived from recording rule)

## Open followups

- **Latency histogram instrumentation**: introduce
  `yggdrasil_http_request_duration_seconds{route,method,status_class}`
  via an HTTP middleware in `controllers/httpapi/server.go`. Until
  this lands, the latency SLI rows are TBD.
- **PagerDuty integration**: alerts currently route to Slack
  #yggdrasil-ops. Upgrade to PagerDuty once the on-call rotation
  doc is finalized.
- **Multi-window multi-burn-rate alerts**: tighten to a 4-window
  policy per Google SRE workbook §5.
