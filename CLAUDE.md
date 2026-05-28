# Claude Code Context: yggdrasil-core

## 🌳 Integration contract (server-side enforcement)

yggdrasil-core is the **enforcement point** for the integration capability convention defined in `/Users/dakasa/projects/yggdrasil/integration-template/INTEGRATION_CONTRACT.md`. When implementing or reviewing manifest validation, registration handlers, or describe-handshake logic in this repo, treat that document as authoritative.

Key invariants the validator enforces (Phase 1 warn-only via `warnings:[...]` in response, Phase 2 hard-fail at registration):

- Capability names in `action_catalog[].name` MUST match `^(ensure|observe|destroy|discover|on)_[a-z][a-z0-9_]*$` OR be on the curated allowlist (pure-function helpers + money-movement actions).
- Reactor capabilities (`category: "reactor"`) are exempt from naming validation regardless of name.
- Resource types declared in `spec.resource_types[]` MUST list their canonical triple in `default_actions`.
- Manifests MUST NOT inline credentials; only `credentials_ref` URI references to operator-chosen secret stores (AWS SM, GCP SM, Vault, K8s Secret, etc — Lego principle).

Convention spec: `docs/superpowers/specs/2026-05-27-yggdrasil-integration-capability-convention.md` in `dakasa-system`. The allowlist + regex live in `config/capability_naming_allowlist.yaml` (TBD by the rollout plan).

## What this repo is

`yggdrasil-core` is the **server / control plane** for Yggdrasil — the
authoritative HTTP API, manifest catalog, workflow engine, RBAC/policy
evaluator, OIDC edge, and embedded scheduler/reconcilers. Everything else
in the ecosystem (the `yggdrasil` CLI, integration adapters, surfaces) is
a client of this binary.

Repo: `github.com/dakasa-yggdrasil/yggdrasil-core` (open source, Apache 2.0).
Image: `ghcr.io/dakasa-yggdrasil/yggdrasil-core` (multi-arch, tags
`sha-<short>`, `edge`, `latest`, `vX.Y.Z`).
Default listen addr: `:9080` (override `HTTP_ADDR`/`PORT`).

## Stack

- Go 1.25 (`go.mod` line 3 — bump with care, Dockerfile pins
  `golang:1.25-bookworm`).
- HTTP: stdlib `net/http` + Go 1.22 `mux.HandleFunc("METHOD /path")`.
- Postgres via `lib/pq`, migrations via `pressly/goose/v3` (embedded
  binary in image at `/app/goose`, migrations in `db/migrations/`).
- AMQP via `rabbitmq/amqp091-go`.
- JSON Schema via `santhosh-tekuri/jsonschema/v6`.
- OIDC via `zitadel/oidc/v3`; SAML via `crewjam/saml`; WebAuthn via
  `go-webauthn/webauthn`; TOTP via `pquerna/otp`.
- k8s client (`k8s.io/client-go`) used by integration-surface-sync.

## Repo layout

```
main.go                      # bootstraps runtime.ServiceApp + addons.Apply
addons/                      # auto-registered subsystems (init() calls Register)
controllers/httpapi/         # ALL HTTP routes (see server.go for the mux)
controllers/console/         # /console SPA + asset embedding
controllers/oidc/            # OIDC provider endpoints
controllers/message/         # AMQP consumer handlers
repository/                  # SQL queries + types (one file per aggregate)
model/                       # Domain types (manifests, workflows, …)
manifest/                    # JSON Schemas (versioned, by kind)
docs/                        # User-facing docs (architecture, catalog, …)
docs/bootstrap/              # Seed manifests baked into the image
db/migrations/               # goose .sql migrations
scripts/                     # standalone helper binaries (bootstrap, goose)
cmd/                         # auxiliary CLIs (operator, validate-manifests, …)
```

## Key concepts (vocabulary)

- **Manifest** — versioned YAML/JSON record in `public.manifests`,
  keyed by `(kind, namespace, name)`. Soft-delete via `deleted_at`.
- **Kind** — one of `workflow`, `integration`, `integration_type`,
  `product`, `surface`, `role`, `policy`, `auth_provider`,
  `repository_binding`, `team`, `team_grant`, `team_role_binding`, … (see
  `manifest/`).
- **Workflow run** — instantiated workflow execution; `dispatch_mode`
  is `sync` (response blocks on completion) or `async` (returns 202).
  Default resolved by `manifest spec.dispatch_mode`, overridable per
  request via `?mode=` or `X-Yggdrasil-Dispatch-Mode` header.
- **Integration type** — declares a family/provider, credential schema,
  capability list, transport (`http_json` or `amqp_rpc`). Lives in
  `integration-<provider>` repo and is **synced into the DB** by the
  `manifest-sync` addon.
- **Reactor** — event-driven dispatch: `event_log` rows match
  reactor manifests, which then dispatch workflows. Metrics
  `reactor_*` (commit `ccd6361`).
- **Addon** — auto-registered subsystem booted by `addons.Apply()`. See
  `addons/registry.go`. Ordering via priority (lower runs earlier).
  Active addons: `observability`, `postgres`, `rabbitmq`, `http`,
  `provisioner`, `reconciler`, `integration_surface_sync`, `first_run_bootstrap`,
  `event_log_cleaner`, `collaborator_status_clock`, `external_identity_resync`,
  `external_identity_cleanup`, `password_rotation`, `manifest-sync`,
  `manifest_purge`, `reactor-dispatcher`, `workflow_scheduler`,
  `workflow_event_triggers`, `team-reconcile`, `team_provisioning`,
  `heimdall_inbox_writer`, `heimdall_inbox_dispatcher`, `buildproject_lifecycle`,
  `expired_sessions_cleaner`, `audit_events_retention`,
  `stale_workflow_runs_cleaner`.

## HTTP API (most relevant routes)

Bearer token via `YGGDRASIL_WORKFLOW_RUN_TOKEN` for write routes;
session cookie for console; SCIM tokens for SCIM endpoints.

```
GET    /healthz                                  liveness
GET    /readyz                                   readiness (db + broker)
GET    /metrics                                  Prometheus
GET    /openapi.json                             embedded spec (sync'd by 5d088fa)

GET    /api/v1/manifests?kind=X[&namespace=…]    list manifests
POST   /api/v1/manifests?kind=X                  create/update — body `{namespace, name, spec}`
DELETE /api/v1/manifests/{id}[?soft=true]        hard delete (default) or soft (commit 5cbdecb)

POST   /api/v1/workflow-runs                     dispatch (sync/async — see workflow_runs.go)
GET    /api/v1/workflow-runs/{run_id}            poll status
GET    /api/v1/ops/workflows                     list runs
GET    /api/v1/ops/workflows/{runId}             detail (steps + outputs)
POST   /api/v1/ops/workflows/{runId}/retry       retry
POST   /api/v1/ops/workflows/{runId}/abort       abort
POST   /api/v1/ops/workflows/{runId}/replay      replay

POST   /api/v1/integration-types/{id}/sync       manual forward-drift sync (also auto via manifest-sync addon)
POST   /api/v1/events                            event log publish (drives reactors)
POST   /api/v1/github/webhook                    GitHub webhook receiver
```

**POST manifest body shape** (NOT `apiVersion/kind/metadata` — Kubernetes
style is rejected): `{"namespace": "...", "name": "...", "spec": {...}}`
with `?kind=X` in the query string.

**API listing quirks** observed in production:
- `GET /api/v1/workflows?limit=N` silently caps at 669. Use pagination
  via `offset` / repeated calls if N>669.

## Auth

- `/api/v1/auth/passwords/*` — local password (Argon2id, scheme stored in DB).
- `/api/v1/auth/third-party/{start,callback}/{provider}` — OIDC/SAML
  third-party login. Providers configured via `auth_provider` manifests.
- `/api/v1/auth/session` — current session.
- MFA via TOTP/WebAuthn/recovery codes (`auth/mfa/...`).
- SCIM v2 at `/api/v1/auth/scim/*`.
- Bearer auth via `YGGDRASIL_WORKFLOW_RUN_TOKEN` for workflow dispatch
  routes (POST /api/v1/workflow-runs, POST /api/v1/events, POST
  /api/v1/manifests, integration_type sync). Token comes from
  the cluster secret `yggdrasil-secrets` key `YGGDRASIL_WORKFLOW_RUN_TOKEN`.

## CI / image flow

- `.github/workflows/release.yml` — builds + pushes to GHCR on
  push-to-main and on `v*` tags. Tags emitted: `sha-<short>`,
  `edge` (main), `latest` (release tag), `vX.Y.Z`.
- `.github/workflows/emit-deploy-event.yml` — POSTs a `workflow-runs`
  request to `${YGGDRASIL_CORE_BASE_URL}` so the running cluster
  reconciles the new image. **Soft-skip pattern** (commit `1682b46`):
  if `YGGDRASIL_CORE_BASE_URL` / `YGGDRASIL_WORKFLOW_RUN_TOKEN`
  repo secrets are missing, the job logs `::warning::` and exits 0
  (default-on enable: `vars.YGGDRASIL_DEPLOY_EMIT_ENABLED != 'false'`).
- `.github/workflows/workflow.yml` — go test, golangci-lint, addons
  list smoke.

Dockerfile is multi-stage:
1. Optional `console-build` stage clones private
   `dakasa-yggdrasil/surface-console` if `--secret id=github_token`
   is mounted and `WITH_CONSOLE=true`. Otherwise a placeholder
   `index.html` is shipped (the Go binary still serves it via
   `controllers/console/yggdrasil-console-dist/`).
2. Cross-compile build stage on `$BUILDPLATFORM`.
3. Alpine runtime + `kubectl` installed for integration-surface-sync.

## Recent meaningful commits (last ~10 days)

- `5d088fa` 📝 sync `docs/api-reference/openapi.json` with embedded controllers
- `1682b46` 🐛 ci(emit-deploy): graceful skip when bootstrap secrets missing
- `29bb983` ♻️ Periodic purge of soft-deleted manifests >30d old (`manifest_purge` addon)
- `5cbdecb` ✨ DELETE /api/v1/manifests/{id} handler (soft=true OR hard)
- `0539356` 🐛 forward-drift fast-path + accept `committed` as workflow success
- `75c06b2` ci: inline Emit Deploy Event (drop cross-repo private action dep)
- `b899942` ci: add Emit Deploy Event workflow (default-on gate)
- `ccd6361` Instrument reactor_* and heimdall_flagged_count metrics
- `38bbcf7` 🐛 workflow steps treat not_found/simulated as success (idempotent delete ops)
- `88de3ff` 🐛 fix ops/workflows detail 500 + manifest_sync forward-drift deadlock
- `094a67b` ✨ workflow_runs: per-workflow dispatch_mode field (sync/async)
- `f4b5774` 🐛 workflow/dispatch: enforce minLength on input_schema string fields
- `9d30e34` 🐛 fix(amqp): exit fast when rabbit connection closes — kubelet self-heals

## Validation

```bash
go test ./...
go vet ./...
golangci-lint run --timeout=5m
go run ./scripts/addons list   # smoke test addons registry
```

For HTTP routes touching manifest persistence, always test against a
local postgres (`docker-compose.yml`) — `sqlmock` is fine for unit-level
SQL contracts but workflows depend on JSON Schema validation against
real `manifest/*.json` files.

## Mandatory contracts

- **API stability** — clients in the wild: every `dakasa-yggdrasil/integration-*`
  emit-deploy CI step, the `yggdrasil` CLI, `surface-console`, the
  `yggdrasil-self` reconciler, every DaKasa service repo. Breaking
  `POST /api/v1/workflow-runs` or `POST /api/v1/manifests` ripples
  everywhere. Add fields; rename/remove only with a fallback for at
  least one release.
- **Manifest schemas in `manifest/`** are versioned per kind. The
  forward-drift fast-path (`controllers/httpapi/integration_describe.go`,
  commit `0539356`) compares the spec the adapter reports against the
  DB row before writing — never widen acceptance silently. The
  `committed` status is now treated as a success terminal (was
  previously only `succeeded`).
- **Schema migrations** are append-only; `goose down` is not part
  of the deploy flow. Backfill scripts go in `scripts/`.

## Deploy

- `dakasa-yggdrasil/yggdrasil-core` is the **only deployable source**
  (the `services/yggdrasil-core/` submodule inside the
  `dakasa-yggdrasil/yggdrasil` monorepo is observe-only — see
  `~/.claude/projects/-Users-dakasa-projects/memory/reference_yggdrasil_core_repos.md`).
- Cluster pulls from ECR Pull-Through-Cache of GHCR, not GHCR direct
  (see memory `[Yggdrasil integrations live in GHCR, not ECR]` for the
  inverse note about adapters).
- Rolling new image into the running cluster: dispatch
  `upgrade-yggdrasil-core-edge` workflow against the
  yggdrasil-self instance with `inputs.image=<ECR/PTC sha-tag>`.
