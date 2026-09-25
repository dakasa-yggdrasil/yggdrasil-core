# Observability

Logs, metrics, traces, and the event stream, which is Yggdrasil's
native audit fabric and effectively a fourth observability pillar.

## Logs

The core and every first-party adapter log as structured JSON to
stdout via zap. Your infrastructure picks them up:

- Kubernetes: cluster logging (fluent-bit, Vector, Loki, Datadog, ...).
- Compose: `docker compose logs` or a log-shipping sidecar.
- Bare-metal: journalctl or logrotate into your log agent.

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
| `msg="authorization denied"` with `reason="policy"` and high rate | Policy change caused mass denials. | Yes: humans took out their permissions. |
| `level=error` on repeated `workflow.dispatch` failures | Engine can't dispatch. Broker / DB issue. | Yes, page. |
| `panic` | Should not happen. Crash loop. | Absolutely. |

## Metrics

The core binary serves Prometheus text exposition at `GET /metrics`.
The handler is `handleMetrics` in `controllers/httpapi/metrics.go`;
the counters it renders live in that file and in
`internal/metrics/metrics.go`. Everything below is derived from those
two files. When they change, this section must change with them; the
catalog table lists every family `handleMetrics` renders and nothing
else.

### The endpoint

| Property | What the code does |
|---|---|
| Route | `GET /metrics`, registered in `controllers/httpapi/server.go` on the same mux as the API. The Go 1.22 mux also answers `HEAD` for a `GET` pattern; any other method gets `405` from the mux. |
| Auth | None. The path is outside the console-gated prefixes (`requiresAuthenticatedConsoleAPI`), CSRF checks apply only to `POST`/`PUT`/`PATCH`/`DELETE`, and the handler reads no credential. One trap: the directory machine-principal branch is decided before every route, so a scraper that sends the directory header or a directory bearer is refused (`401`/`403`) here as well. Scrape with no credential at all. |
| Content-Type | `text/plain; version=0.0.4; charset=utf-8` |
| Status | Always `200`. The handler touches neither Postgres nor the broker, so it keeps answering while `/readyz` reports `503`. There is no error branch. |
| Body | `# HELP` / `# TYPE` header pairs followed by samples, one family after another, in the order of the catalog below. Closed-set families render every label combination, zero-padded. Open-set families (`pulse`, `integration_type`, `permission`, `name`) render only the rows seen since process start; the `permission` and `name` rows come out of a Go map and are not in a fixed order between scrapes. |
| State | Process-local `sync/atomic` counters and mutex-guarded maps. No `prometheus/client_golang`, no persistence: every replica reports its own numbers and every restart resets them to zero. Use `rate()` / `increase()` and `sum()` across pods; Prometheus handles the counter reset. |
| Not exposed | No histograms (there is no request-latency family; `monitoring/slo.md` lists that as an open follow-up), no `process_*` or `go_*` standard families, no `_created` samples. |
| Logging | Every request, scrapes included, goes through `withLogging` and produces one `info` line `http request served` with `service`, `method`, `path`, `status`, `duration`, written to the rotating log file (see HTTP access logs below), not to stdout. At a 15 s scrape that is one line per pod every 15 s; filter on `path="/metrics"` if it bothers your log budget. |

### Scrape contract

| Item | Value | Where it is proven |
|---|---|---|
| Port | The API listener: `HTTP_ADDR`, else `:$PORT`, else `:9080`. | `addons/http.go` (`httpListenAddr`), `Dockerfile` (`EXPOSE 9080`), `docker-compose*.yml` |
| Path | `/metrics` | `controllers/httpapi/server.go` |
| Interval | The handler comment says adopters scrape on a 15 to 30 s interval. The rule groups the repo ships that set an interval evaluate at `interval: 30s`. | `controllers/httpapi/metrics.go`, `monitoring/prometheus/*.yaml` |
| Credentials | None (see above). | `controllers/httpapi/server.go` |
| Shipped rules | `monitoring/prometheus/capability-naming-validator-alerts.yaml`, `monitoring/prometheus/yggdrasil-slo-recording-rules.yaml`, `monitoring/prometheus/yggdrasil-slo-alerts.yaml`. The validator alerts header spells out an apply path (drop the file into `rule_files:` by hand; `integration-prometheus` has no `ensure_alert_rule` capability) and the recording rules header says to ship them via `integration-prometheus`; the SLO alerts header describes the burn-rate pattern and the targets and says nothing about how to apply the file. | `monitoring/prometheus/` |
| Shipped dashboards | `monitoring/grafana/capability-naming-validator-dashboard.json` (the three `capability_*` families) and `monitoring/grafana/yggdrasil-slo-dashboard.json` (`workflow_runs`, `auth_login`, `auth_mfa_verify`, `auth_sessions_*`, `reactor_dispatches`). | `monitoring/grafana/` |
| Not shipped | No `scrape_config`, `ServiceMonitor`, `PodMonitor` or `prometheus.io/*` pod annotation for the core itself. Wiring the scrape job is the deployer's job, in whatever Prometheus scrapes the core's namespace. | repository tree |

### Catalog

Type is the `# TYPE` line. Labels list the closed set the code spells
out; an open set names its source. "Bumped by" is the production call
site (`file:function`); test-only callers do not count. The last column
carries only an expression that a comment in the two Go files (or a
rule file under `monitoring/prometheus/`) recommends; "none in code"
means neither exists.

| Family | Type | Labels | Bumped by | Expression recommended in code or rules |
|---|---|---|---|---|
| `yggdrasil_workflow_runs_total` | counter | `status` in {`succeeded`, `failed`, `running`} | No production caller. `httpapi.IncWorkflowRun` is called only from `metrics_test.go`, so all three rows stay at 0. | None in code. `monitoring/prometheus/yggdrasil-slo-recording-rules.yaml` builds `yggdrasil:workflow_availability_ratio:rate{5m,1h,6h}` on it (see Known gaps). |
| `yggdrasil_webhook_events_total` | counter | `outcome` in {`accepted`, `skipped`, `failed`} | `controllers/httpapi/github_webhook.go:handlePushEvent`, push events only (`ping` and other `X-GitHub-Event` values answer without bumping). `skipped`: no `repository_binding`, binding without `deploy`, ref outside `branch_filter`, nothing matched `path_filter`. `failed`: binding lookup error, `workflow_kind: github_actions` (`501`), unknown `workflow_kind`. `accepted`: workflow dispatched (`202`). Pushes that bump nothing: the `400` for an unreadable body (before the event switch) or for a push payload `json.Unmarshal` rejects (first thing in `handlePushEvent`), the `401` for a bad `X-Hub-Signature-256` (checked before the event switch, only when `GITHUB_WEBHOOK_SECRET` is set), the `500` for input templating or missing `workflow_ref`, and the `503` broker-degraded answer. So `sum()` under-counts pushes. | None in code. |
| `yggdrasil_manifest_applies_total` | counter | none | `controllers/httpapi/server.go:handleManifestCreate`, once per `201`, reached from `POST /api/v1/manifests?kind=...` and the kind-specific `POST` routes that funnel into it. That is the only bump: every other manifest writer calls `createManifestVersion` or `repository.CreateManifestVersion` directly and bumps nothing. On the HTTP side those are the typed integration-instance create (`handleIntegrationInstanceCreate`), catalog discovery register (`handleCatalogDiscoveryRegister`), workflow template instantiate (`handleWorkflowTemplateInstantiate`), integrations install (`persistCompiledWorkflow`), the two guardian decision handlers (`handleGuardianMemoryReview`, `handleGuardianApprovalDecision`), the remediation-bundle promotion review and integration-type sync (`integration_type_sync.go`); outside HTTP, the `manifest-sync` addon, `internal/bootstrap`, the AMQP `manifest.create` consumer and the workflow `yggdrasil` step `apply_manifest` (`controllers/message/manifest_persist.go`). The counter is a `POST /api/v1/manifests` rate, not a manifest write rate. | None in code. |
| `yggdrasil_manifest_deletes_total` | counter | `mode` in {`hard`, `soft`} | `controllers/httpapi/manifests_delete.go:handleManifestDelete`, once per `DELETE /api/v1/manifests/{id}` that removed or flipped rows. `?soft=<value>` parsed true by `strconv.ParseBool` is `soft`, anything else `hard`. The idempotent `already_absent` `200` bumps nothing. | None in code. |
| `yggdrasil_manifest_purges_total` | counter | none | `addons/manifest_purge.go:runManifestPurge`, by the number of rows removed per sweep, only when it is above 0. Cadence `MANIFEST_PURGE_INTERVAL_SECONDS` (default 24 h; `0` disables), retention `MANIFEST_PURGE_RETENTION_DAYS` (default 30). | The comment asks for `rate(yggdrasil_manifest_purges_total[<window>])` as purge throughput. |
| `yggdrasil_secret_lookups_total` | counter | none | No caller anywhere. `httpapi.IncSecretLookup` is defined and never invoked; the row stays at 0. | None in code. |
| `yggdrasil_uptime_seconds` | gauge | none | Computed at scrape time from a package variable set when the process started (`time.Since(processStartTime)`, rendered with no decimals). | None in code. |
| `yggdrasil_goroutines` | gauge | none | `runtime.NumGoroutine()` at scrape time. | None in code. |
| `yggdrasil_memory_bytes` | gauge | none | `runtime.MemStats.HeapAlloc` at scrape time. Heap in use by Go objects, not RSS, despite the `# HELP` wording. | None in code. |
| `yggdrasil_reactor_evaluations_total` | counter | `outcome` in {`matched`, `skipped`, `error`} | `repository/integration_event_reactions.go:MaterializeReactions`. `skipped` once per event outside the materialisation set (not a canon lifecycle event and not an integration mutation event); `error` once per failed `INSERT`; `matched` by rows affected, so one event that materialises N reactions counts N. | None in code (the comment notes the `matched` rate tracks dispatch fan-out). |
| `yggdrasil_reactor_dispatches_total` | counter | `outcome` in {`succeeded`, `failed`, `dead_lettered`} | `internal/reactors/dispatcher.go:(*Runner).dispatchOne`, once per attempt that reached the adapter RPC (`Caller.Call`). An attempt that fails before it, on `FetchEventForReactor` or `BuildReactorPayload`, is marked failed in the row with a retry backoff and bumps nothing, so `failed` undercounts retriable failures and `sum()` undercounts attempts. `succeeded`: adapter RPC OK (terminal). `failed`: RPC error, still retriable, one per attempt, so a single reaction can bump it many times. `dead_lettered`: RPC error with backoff exhausted (terminal, not also counted as `failed`). | The comment says: read `succeeded` for the success rate, `dead_lettered` for terminal failures, `failed` as retry pressure. `yggdrasil-slo-recording-rules.yaml` records `yggdrasil:reactor_dispatch_success_ratio:rate5m`; `yggdrasil-slo-alerts.yaml` alerts `YggdrasilReactorDispatchFailures` when it is `< 0.95` for 15 m. |
| `yggdrasil_heimdall_flagged_count` | gauge | `pulse`: open set, the workflow name (always prefixed `heimdall-`) | `controllers/message/workflows.go:maybeUpdateHeimdallFlaggedCount`, called from `EmitWorkflowRunCompletedEvent` regardless of run status. Takes the last step whose `output` carries a numeric `flagged_count`; negatives clamp to 0. Absent until the first pulse completes after process start. | None in code. |
| `yggdrasil_capability_warnings` | gauge | `integration_type`: open set, the manifest name | `controllers/httpapi/server.go:handleManifestCreate`, on every `POST` with `kind=integration_type` that passes the write authorization and the body decode, set to the warning count of that run (0 for conformant types too, so a row appears per type posted since process start). The validator runs before `createManifestVersion`, so a `POST` that then fails schema validation or the DB write has already set the gauge. | The comment: read the per-type residual before flipping `YGGDRASIL_VALIDATOR_PHASE=hard-fail`. `capability-naming-validator-alerts.yaml`: `count(yggdrasil_capability_warnings > 0) > 0` (`YggdrasilCapabilityCatalogResidual`, pre-flight gate). |
| `yggdrasil_capability_warnings_total` | counter | none | `controllers/httpapi/server.go:handleManifestCreate`, by the number of warnings of one validator run, only when above 0; same position as the gauge, so it also counts the warnings of a `POST` that then fails schema validation or the DB write. | The comment: `rate()` over a 5 m window for spike detection. `capability-naming-validator-alerts.yaml`: `increase(yggdrasil_capability_warnings_total[5m]) > 10` (`YggdrasilCapabilityWarningsSpike`). |
| `yggdrasil_capability_rejections_total` | counter | none | `controllers/httpapi/server.go:handleManifestCreate`, once per `POST` answered `422` because `YGGDRASIL_VALIDATOR_PHASE=hard-fail` and the run produced warnings. Stays at 0 in warn-only mode. | The comment: use it to confirm hard-fail is live. `capability-naming-validator-alerts.yaml`: `increase(yggdrasil_capability_rejections_total[15m]) > 0` (`YggdrasilCapabilityHardFailRejecting`). |
| `yggdrasil_auth_login_total` | counter | `outcome` in {`succeeded`, `failed`, `rate_limited`, `account_locked`, `mfa_required`} | `controllers/httpapi/auth.go:handleAuthLogin` (`failed` or `account_locked` when password verification fails, `mfa_required` when MFA is enrolled and no TOTP or recovery code came with the request, `succeeded` at the end of the password flow); `controllers/httpapi/mfa.go:handleMFAWebAuthnLoginFinish` (`succeeded` when a passkey login completes); `controllers/httpapi/login_rate_limit.go:loginRateLimit` (`rate_limited` on `429`, wrapped around `/auth/login`, `/auth/passwords/change`, `/auth/mfa/webauthn/login/begin` and `/finish`). So the family covers more than the `# HELP` text's `/api/v1/auth/login`, and less than every attempt: `handleAuthLogin` exits without a bump on a body `decodeJSON` rejects, when MFA is not enrolled (enroll-required answer), on the identity lookup or MFA enforcement errors, when no factor is available (`400`, also for a TOTP code sent to an identity without a TOTP factor), when a recovery code is sent to an identity with none enrolled (`401`, nothing bumps), when a presented TOTP or recovery code fails verification (`401`, only `yggdrasil_auth_mfa_verify_total{outcome="failed"}` bumps), on the envelope (`503`), TOTP-secret or recovery-code store errors, and when `CreateAuthSession` fails. See Known gaps. | The comment: `rate(yggdrasil_auth_login_total[5m])` by outcome; `failed` spikes (brute force), `rate_limited` bursts, `account_locked` above the noise floor, `succeeded` falling to zero. `yggdrasil-slo-recording-rules.yaml` records `yggdrasil:auth_success_ratio:rate{5m,1h}` (excludes `rate_limited` from the denominator); `yggdrasil-slo-alerts.yaml` alerts `YggdrasilAuthAPIErrorBudgetBurnFast` on it. |
| `yggdrasil_auth_mfa_verify_total` | counter | `outcome` in {`succeeded`, `failed`} and `factor` in {`totp`, `recovery_code`, `webauthn`}; all six rows always render | `controllers/httpapi/auth.go:handleAuthLogin` (`totp` and `recovery_code` during password login), `controllers/httpapi/mfa.go:handleMFAWebAuthnLoginFinish` (`webauthn`). | The comment: alert when the `failed` rate per factor crosses a baseline (no literal expression in code). |
| `yggdrasil_auth_sessions_created_total` | counter | none | `controllers/httpapi/auth.go:handleAuthLogin` and `controllers/httpapi/mfa.go:handleMFAWebAuthnLoginFinish`, once each. Sessions created by the third-party login and callback handlers (`handleAuthThirdPartyLogin`, `handleAuthThirdPartyCallback`), by `handleSetupCommit` and by `handlePasswordReset` are not counted, although the `# HELP` text says "login + SSO + admin". | The comment: `rate(revoked) >> rate(created)` after an outage means stuck sessions; the opposite means an orphaned-session pile-up. |
| `yggdrasil_auth_sessions_revoked_total` | counter | none | `controllers/httpapi/auth.go:handleAuthLogout` (once), `controllers/httpapi/me_sessions.go:handleMeSessionsRevoke` (once), `controllers/httpapi/admin_session_revoke.go:handleAdminCollaboratorRevokeSessions` (once per row revoked). Revocations made by `handlePasswordChange`, `handlePasswordReset`, `handleCollaboratorOffboard` and by the per-collaborator session cap inside `repository.createAuthSession` are not counted, although the `# HELP` text says "logout + admin + password rotation + offboard". | Same comment as above. |
| `yggdrasil_csrf_rejected_total` | counter | `outcome` in {`missing_token`, `token_mismatch`, `invalid_session`} and `mode` in {`warn`, `enforce`}; all six rows always render | `controllers/httpapi/csrf.go:csrfFail`, from `csrfMiddleware`, on `POST`/`PUT`/`PATCH`/`DELETE` requests that carry a session, are not path-exempt and are not bearer-authenticated. `mode` comes from `YGGDRASIL_CSRF_ENFORCE`, trimmed and lowercased (`csrfEnforceMode`): only `warn` opts out, anything else is `enforce`. In `warn` the request still proceeds; in `enforce` it gets `403` problem+json. | The comment: `rate(yggdrasil_csrf_rejected_total{mode="warn"}[5m])` to pace the front-end rollout and to check that the flip to `enforce` does not 403-storm legitimate traffic. |
| `yggdrasil_console_rbac_denied_total` | counter | `permission`: one of the `yggdrasil:*` constants in `controllers/httpapi/ops_rbac_catalog.go` (18 at this commit), rows appear after the first denial; `mode` in {`warn`, `enforce`} | `controllers/httpapi/ops_rbac_middleware.go:requireOpsPermission` (and `requireOpsPermissionFunc`, which wraps it), when the collaborator lacks the permission. God mode is matched inside the permission resolution (`collaboratorHasOpsPermission` compares every owned permission with `yggdrasil:*`), so it counts as held and never bumps. Paths that answer without a check and without a bump: requests with no claims (machine callers already authorized for the route) pass straight through; claims with no `collaborator_id` answer `401`; a `collaborator_id` that is not a UUID, and any other permission-lookup error, answer `500`. `mode` comes from `YGGDRASIL_CONSOLE_RBAC_ENFORCE`, trimmed and lowercased (`rbacEnforceMode`), same `warn`-only opt-out. | The comment: `rate(yggdrasil_console_rbac_denied_total{mode="warn"}[5m])` during the observation window; a flat curve means it is safe to flip to `enforce`. |
| `yggdrasil_reconcile_failures_total` | counter | `kind` in {`permission_catalog`, `secret_materialize`, `manifest_apply`}; all three rows always render | `internal/surface/discovery.go:(*Discovery).RefreshOne` with `kind="permission_catalog"` when the permission reconciler fails after a surface manifest refresh. Nothing bumps `secret_materialize` or `manifest_apply` at this commit; those rows stay at 0. | The comment: `rate(yggdrasil_reconcile_failures_total{kind="permission_catalog"}[5m])`, to confirm the rate is shrinking or alert when it grows. |
| `yggdrasil_goroutine_panics_total` | counter | `name`: open set, the call-site name; rows appear after the first recovered panic | `internal/goroutine/safe.go:runSafe` on every panic recovered inside `SafeGo`, plus two direct recovers: `internal/reactors/dispatcher.go:(*Runner).tickOnce` (`reactor_dispatch_one`) and `internal/surface/discovery.go:(*Discovery).runOnce` (`surface_refresh_one`). Names wired at this commit: `audit_emit`, `audit_auth_emit`, `ops_audit_middleware`, `ops_rbac_audit_denied`, `webhook_dispatch`, `backchannel_logout_session`, `backchannel_logout_collaborator`, `workflow_run_async`, `reactor_dispatch_one`, `surface_refresh_one`. | `safe.go`: alert on `rate(yggdrasil_goroutine_panics_total[<window>]) > 0` per call site; `handleMetrics`: any non-zero value must be investigated. |
| `yggdrasil_directory_audit_failures_total` | counter | `reason` in {`store_unconfigured`, `insert_timeout`, `insert_failed`}; all three rows always render | `controllers/httpapi/directory_machine_read.go:(*Server).auditDirectoryMachineOutcome`, once per directory machine-read outcome withheld as `500` "directory audit is unavailable" because the `directory.machine_read` audit row could not be stored (ADR-0019). `store_unconfigured`: no audit writer; `insert_timeout`: the synchronous write deadline fired; `insert_failed`: any other store error. | The comment: `rate(yggdrasil_directory_audit_failures_total[5m])` is the rate at which the directory refuses to answer for lack of a trail; the `reason` says whether the store is missing, slow or rejecting rows. |
| `yggdrasil_workflow_run_legacy_bridge_requests_total` | counter | `route` in {`dispatch`, `poll`}; both rows always render | `controllers/httpapi/workflow_run_legacy_bridge.go`: `(*Server).recordLegacyWorkflowBridgeDispatch` from `handleWorkflowRun` and `(*Server).recordLegacyWorkflowBridgePoll` from `handleWorkflowRunGet`, once per request the plaintext `YGGDRASIL_WORKFLOW_RUN_TOKEN` bridge authenticated (ADR-0022), including a dispatch then answered `503` broker-degraded, `400` for its body or `403` by authorization, and every poll (the log line and the audit row are written once per run id per process, the counter every time). The outer gate never bumps it, so a request counts once. | The comment: `sum(increase(yggdrasil_workflow_run_legacy_bridge_requests_total[7d]))` is the traffic that still depends on the bridge; the durable record is the `workflow_run.legacy_bridge` audit row. |
| `yggdrasil_workflow_run_legacy_bridge_audit_failures_total` | counter | none | Same file, `(*Server).auditLegacyWorkflowBridge`, once per `workflow_run.legacy_bridge` row that could not be stored (no store, insert error, or the 2 second bound fired). The request is still served. | The comment: a non-zero value means the durable legacy-use trail has a gap; read it next to the requests counter. |

### Known gaps the table exposes

These are facts about the code at this commit, not intended behaviour.
They are listed so that nobody builds an alert on a flat line.

- `yggdrasil_workflow_runs_total` and `yggdrasil_secret_lookups_total`
  are rendered but never incremented. The write-API SLI in
  `monitoring/slo.md` and the `yggdrasil:workflow_availability_ratio:*`
  recording rules divide by the first one; with every row at 0 the ratio
  evaluates to 0, so `YggdrasilWriteAPIErrorBudgetBurnFast` and
  `YggdrasilWriteAPIErrorBudgetBurnSustained` fire continuously wherever
  those rules are loaded against a scraped core. Do not load them until
  the counter has a caller.
- The same `clamp_min(sum(rate(...)), 0.001)` denominator sits under
  `yggdrasil:auth_success_ratio:rate{5m,1h}` and
  `yggdrasil:reactor_dispatch_success_ratio:rate5m`. Both families render
  every row zero-padded, so in a window with no traffic `rate()` is 0
  (not absent) and the ratio evaluates to 0. That means
  `YggdrasilAuthAPIErrorBudgetBurnFast` (`severity: page`) fires once
  the 1 h window has held no login for 5 consecutive minutes of
  evaluation, and `YggdrasilReactorDispatchFailures` (`severity: ticket`)
  once the 5 m window has held no dispatch for 15 consecutive minutes:
  an idle cluster pages. Gate them on a minimum denominator (for example
  `and sum(rate(yggdrasil_auth_login_total[1h])) > 0`) or load them only
  where traffic is continuous.
- `sum(yggdrasil_auth_login_total)` is not the attempt count the
  `handleMetrics` comment and the `# HELP` text promise: MFA-verify
  failures during password login and the pre-verification exits listed in
  the table leave `POST /api/v1/auth/login` without a bump.
- `yggdrasil_reconcile_failures_total{kind="secret_materialize"}` and
  `{kind="manifest_apply"}` have no caller.
- The `# HELP` text of the two session counters promises SSO, admin,
  password rotation and offboard coverage that the call sites do not
  provide (see the table).
- `docs/deployment.md` still says metrics come "via a surface"; the
  core serves them itself.

### `event_log` as a supplementary source

The metrics above are process-local and reset on restart. The
`event_log` table (`db/migrations/00012_event_log.sql`) is durable and
typed, so it is the source for anything that must survive a restart or
needs a breakdown the counters do not carry. Event types the core
emits at this commit and the fields worth deriving from:

- `workflow.run.completed` (payload `status`, `started_at`,
  `finished_at`, `step_count`): run count and success ratio that
  survive restarts, run latency (`finished_at` minus `started_at`) and
  step count. The payload carries no per-step entries or timestamps.
- `authorization.evaluated` (payload `decision`): deny ratio.
- `manifest.created` (payload `kind`, `namespace`, `name`, `version`):
  manifests persisted through the message path only, that is the AMQP
  `manifest.create` consumer and the workflow `yggdrasil` step
  `apply_manifest`, both via `controllers/message/manifest_persist.go`.
  `POST /api/v1/manifests` never emits it (`handleManifestCreate` writes
  through `repository.CreateManifestVersion`, which emits no event), and
  the message path never bumps `yggdrasil_manifest_applies_total`, so the
  two measure disjoint populations and neither alone is a total manifest
  write rate. The per-kind view of the HTTP applies is the `audit_events`
  row `handleManifestCreate` records (`action = 'manifest.create'`,
  `resource_kind` = the kind), written fire-and-forget by `recordAudit`.

A small consumer that tails the table and exports counters is still a
valid pattern; it is no longer the only one.

### HTTP access logs

The core emits one `http request served` line per request from
`withLogging` (`controllers/httpapi/server.go`) with `service`,
`method`, `path`, `status` and `duration`. Request rate, latency
percentiles and error rate per endpoint family come from those lines or
from your ingress logs; the core has no request-latency histogram. That
line lands in the rotating JSON file the `observability` addon opens
(`/var/log/yggdrasil-core.log`, or `LOG_FILE`; `monitoring/logger.go`
builds the only logger, through lumberjack), not on stdout, so a cluster
logging pipeline that reads container stdout sees nothing from the core.
The level is `info` unless `ENV_MODE` is `development` or `test`; no
`LOG_LEVEL` variable is read anywhere in the binary.

### Process-level metrics

`yggdrasil_goroutines` and `yggdrasil_memory_bytes` are the only
runtime gauges the core exposes. CPU, RSS, file descriptors, open
Postgres connections and open AMQP channels come from cAdvisor,
node_exporter and the database or broker exporters, not from
`/metrics`.

### Dashboards

The repo ships two Grafana dashboards under `monitoring/grafana/` (the
capability-naming validator and the SLO board; see the scrape table
for which families each charts). Beyond those, a prod deployment
still wants an integration-health board (per-family `execute` latency,
error rate, adapter replica count) and an infra board (Postgres
connections, slow queries, commit rate, disk; broker queue depth and
channel count when in use; core pods CPU/mem/FD). Cheap to build,
enormously valuable during incidents.

## Traces

Two interesting sets of spans:

- Per HTTP request on the core.
- Per workflow run step, including the `rpc.Transport` round-trip to
  the adapter (whichever transport the integration declares).

Neither is wired out-of-the-box yet. When you wire traces
(OpenTelemetry Go SDK, propagate trace context through whichever
transport the integration uses: HTTP headers, AMQP headers, gRPC
metadata, etc.), these are the spans you want:

- `http.request`: the core's top-level HTTP handler.
- `manifest.persist`: the validate + checksum + tx + emit pipeline.
- `workflow.run`: the full run.
- `workflow.step.render`: template rendering.
- `workflow.step.dispatch`: `rpc.Transport` call to adapter.
- `integration.describe_handshake`: the per-use verification.

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

- `/healthz`: process is alive (cheap, no DB hit). Use for
  liveness probes.
- `/readyz`: process + Postgres reachable + migrations at head.
  Use for readiness probes. `yggdrasil init` waits for this before
  declaring success.
