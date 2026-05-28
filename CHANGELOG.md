# Changelog

All notable changes to yggdrasil-core are documented here.

## [2.10.0] - 2026-05-28

### Added
- **A6: SameSite=Strict default for the session cookie.** `writeAuthCookie` and `clearAuthCookie` now emit `SameSite=Strict` by default (was `Lax`). For an admin IDP this kills the broadest CSRF surface — the cookie won't ride any cross-site request, top-level navigations included. Operators can override via `AUTH_SESSION_COOKIE_SAMESITE` (Strict/Lax/None, case-insensitive); the third-party OAuth state cookie keeps Lax intentionally because the IdP callback is a cross-site navigation.
- **A7: Per-session CSRF token defense (warn-only enforce).** Per-session token derived as `base64url(HMAC-SHA256(YGGDRASIL_CSRF_HMAC_SECRET, session.id))` — stateless, deterministic, no migration. Surfaced via a non-HttpOnly `yggdrasil_csrf_token` cookie AND the `csrf_token` field on `GET /auth/session`. New `csrfMiddleware` (wired between session resolution and route dispatch) recomputes the HMAC and rejects mismatched/missing `X-CSRF-Token` headers on POST/PUT/DELETE/PATCH. Mode gated by `YGGDRASIL_CSRF_ENFORCE` (default `warn` so the surface-console rollout can ship its matching client without 403-storming production). New metric family `yggdrasil_csrf_rejected_total{outcome,mode}`.
- **A10: Per-client OIDC AccessTokenLifetime override.** Migration 00048 adds nullable `oidc_clients.access_token_lifetime_seconds` (CHECK bounded to [60, 86400]). NULL = use the global 15-minute default; positive int = use that lifetime in seconds. Admin endpoint `PATCH /api/v1/admin/oidc-clients/{id}` (admin-token auth) lets operators set/clear the override per client; high-trust clients can opt down to 60–300s so a leaked JWT is short-lived. The override flows through `clientView.AccessTokenLifetime()` and is read fresh per request — no clientView caching.

### Fixed
- **A9: hardened OIDC redirect_uri exact-match guarantee.** Pinned the existing protection (zitadel/oidc/v3's `slices.Contains` validator + our clientView NOT implementing `op.HasRedirectGlobs`) with a 7-test suite covering attacker URI families (prefix attacks, host suffix attacks, scheme downgrades, double-slash hijacks, protocol-relative URIs, `javascript:` pseudo-schemes, path/query/fragment append fuzz) plus a sentinel that breaks if a future refactor adds glob support to clientView. Also documented the security rules in `storage.go::RedirectURIs`. No production code change — the protection was already correct; this commit prevents regression.

### Notes
- A7 ships in warn-only mode. The matching `X-CSRF-Token` emission lands in surface-console (separate cycle); after that rolls, flip `YGGDRASIL_CSRF_ENFORCE=enforce` on the Deployment env to start returning 403 + Problem+JSON on missing/invalid tokens.
- A10 admin endpoint is PATCH-only — full OIDC client lifecycle (create/delete) stays out of scope for the audit. Clients are still bootstrapped via manifests / direct `UpsertOIDCClient` calls.

## [2.9.2] - 2026-05-27

### Added
- **Adapter-declared reactors** (`AdapterDescribeResponse.Reactors`). Adapters can now declare their canonical reactor subscriptions in `Describe()` instead of operators having to POST `spec.reactors[]` to the manifest catalog after registration. `integrationTypeSpecFromDescribeResponse` carries `response.Reactors` through to the live spec, and `manifestsync.MergeSpec` adopts them when the current spec has no operator-managed reactors. Operator overrides still win when explicitly set — initial registration / fresh sync seeds from the adapter, post-override the operator's value is preserved verbatim.

### Notes
- Backwards-compatible: adapters that don't emit `reactors[]` continue to work; only adapters that opt in to the new field get auto-seeded reactor subscriptions on registration.

## [2.9.1] - 2026-05-27

### Fixed
- **Workflow status normalization accepts `executed`** (Phase 2C follow-up). The bootstrap workflow `oidc-client-set-backchannel-logout-uri` (database-admin-postgres `execute_sql`) returned cosmetic `failed` even though the SQL UPDATE succeeded (`rows_affected: 1`). `executed` now collapses to the success bucket alongside `committed`/`applied`/`created` in `controllers/message/workflows.go::normalizeWorkflowIntegrationStatus`. Same semantics — the state change landed.

## [2.9.0] - 2026-04-25

### Added
- **Audit trail** (`/api/v1/audit`). New table `audit_events` with fields actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id, created_at. `GET /api/v1/audit?actor=&action=&resource_kind=&resource_id=&tenant=&since=&until=&limit=` queries with AND-combined filters; default limit 100, capped 1000. `manifest.create` now emits an audit event on every POST `/api/v1/manifests` (success and error).
- **Workflow template instantiation** (`POST /api/v1/workflow-templates/{namespace}/{name}/instantiate`). Substitutes `{{ params.<name> }}` placeholders in the template body with caller-supplied `params` (validates required params, applies defaults, rejects unknown placeholders). When `apply=true`, the rendered workflow manifest is created server-side and returned as a manifest record; when `apply=false` (default), the rendered shape is returned without persistence so callers can preview.
- **`yggdrasil_manifest_applies_total` counter** now bumps on every successful manifest create (was wired in v2.4.0 but not actually called).
- **Migration `00017_audit_events`** with btree indexes for the common query patterns (recent first, by actor, by resource, by tenant).

### Notes
- Audit insertion is fire-and-forget in a goroutine; failures are logged via the server logger but never gate the user's request. Audit is observability, not business logic.
- Tracecontext propagation through adapter calls (W3C `traceparent` header forwarding into AdapterExecuteIntegrationRequest) is still v2.9.x — webhook handler and audit table already record the inbound `traceparent` when present.
- TTL reaper goroutine for `ephemeral_environment` and Postgres advisory-lock leader election ship in v2.9.x patches; the data shapes are stable as of v2.2.0 / v2.3.0 respectively.

## [2.8.1] - 2026-04-25

### Fixed
- **Renderer no longer overwrites `Namespace.metadata.labels.app.kubernetes.io/part-of`** (D2). Yggdrasil's renderer used to emit the namespace with `app.kubernetes.io/part-of=yggdrasil`, but the higher-level platform managing the namespace may classify it differently (e.g. `=dakasa` for a DaKasa-style ecosystem). When the platform also installs a NetworkPolicy keyed on its own `part-of` value, the renderer's label silently broke the egress rule on every reconcile. The renderer now emits only `app.kubernetes.io/managed-by=yggdrasil-core` on the Namespace; cluster admins or higher-level platforms own the rest of the namespace's labels.
- **Dockerfile cross-compile support** (D1). Renamed/replaced the build with `BUILDPLATFORM` + `TARGETARCH` ARGs so Go cross-compiles natively on the build host instead of running through qemu. Fixes `go: error obtaining buildID for go tool compile: signal: segmentation fault (core dumped)` when building on Apple Silicon for `linux/amd64`.

### Notes
- D3 (Postgres healthcheck noise: `database "superuser" does not exist`) was a `pg_isready` probe missing `-d postgres` in the StatefulSet pod template. Fixed in the prod cluster's StatefulSet manifest, not in core (Postgres is a cluster-side concern, not Yggdrasil renderer-managed). The renderer-emitted bundled-Postgres profile already passes `-d postgres`; the bug existed only in the legacy hand-rolled StatefulSet predating Phase 14.

## [2.8.0] - 2026-04-25

### Added
- HA roadmap published. Adopter documentation describes the path to multi-replica yggdrasil-core with leader election, idempotent workflow_run creation, and zero-downtime rolling upgrades.

### Notes
- Implementation lands in v2.8.x patches: (1) Postgres advisory-lock-based leader election for the workflow scheduler ticker; (2) idempotency_key honoured on `POST /api/v1/workflow-runs`; (3) k8s deploymentmanifests configurable for replicas≥3 + PDB; (4) benchmark suite for p50/p95/p99 latency on manifest apply, workflow dispatch, webhook → run start.
- v2.8.0 is the **last v2 minor**. v3.0 introduces RBAC enforcement default-on (current opt-in via `YGGDRASIL_TENANCY_ENFORCED`) and OpenAPI generation from handler annotations.

## [2.7.0] - 2026-04-25

### Added
- Console UI roadmap published. The `surface-console` repo gains its first deploy with this minor; the bundled UI surfaces dashboard, manifests browser, workflow run viewer, audit log (when v2.4.x audit ships), ephemeral envs list, and repository_bindings.

### Notes
- The UI itself ships from the **`surface-console` companion repo** with its own release cycle (v0.x.0). The core in v2.7.0 is unchanged from v2.6.0; this version bump signals that the console is officially supported.
- Auth uses the same OIDC flow exposed at `/api/v1/auth/third-party/*`. Multi-tenant aware (filters listings by caller's authorised tenants when `YGGDRASIL_TENANCY_ENFORCED=true`).
- Live updates use SSE in v2.7.0 (WebSocket support is a v3 enhancement).

## [2.6.0] - 2026-04-25

### Added
- New manifest kind `workflow_template`. Declares a parameterised workflow with `display_name`, `description`, `category`, `tags`, `authors`, `params` (typed input declarations: string/integer/number/boolean/array/object), `body` (workflow shape with `{{ params.<name> }}` placeholders), and `version`.
- Validation: display_name + body required; param types must be one of the supported six; a param cannot be both required and have a default (contradictory).
- Normalisation: trims whitespace; defaults `version` to `v0.1.0`.
- Adopters POST templates via the generic `POST /api/v1/manifests?kind=workflow_template`. The companion CLI/console will add discovery and instantiation in v2.6.x.

### Notes
- Template instantiation (substituting `{{ params.* }}` and posting the resulting workflow) is currently adopter-side. v2.6.x adds a server endpoint `POST /api/v1/workflow-templates/{ns}/{name}/instantiate`. The data shape is stable in v2.6.0.

## [2.5.0] - 2026-04-25

### Added
- (none in core) — see companion `yggdrasil/yggdrasil` repo for the v2.5 CLI release. The CLI ships on its own cadence; this version bump in the core simply syncs the major.minor with the v2.x roadmap.

### Notes
- v2.5.0 of the **CLI** ships these adopter-visible changes (handled in the companion repo, not here):
  - Shell completion (`yggdrasil completion bash|zsh|fish`).
  - Friendly error messages on empty results (`yggdrasil get integration-instance` returns "no integration-instance manifests found in namespace X" instead of an empty stdout).
  - `--output yaml|json|table` consistency across all `get` subcommands.
  - `yggdrasil whoami` to show the current auth context.
  - Verb-noun structure cleanup; dropped flags renamed with deprecation aliases for one minor.

### Compatibility
- The HTTP API surface in v2.5.0 of the core is **identical** to v2.4.0. Existing CLI binaries continue to work.

## [2.4.0] - 2026-04-25

### Added
- `GET /metrics` endpoint serving Prometheus text exposition format (no auth, no external deps).
- Counters: `yggdrasil_workflow_runs_total{status}`, `yggdrasil_webhook_events_total{outcome}`, `yggdrasil_manifest_applies_total`, `yggdrasil_secret_lookups_total`.
- Gauges: `yggdrasil_uptime_seconds`, `yggdrasil_goroutines`, `yggdrasil_memory_bytes`.
- Webhook handler instrumented to increment `yggdrasil_webhook_events_total` on every branch (skipped / failed / accepted).

### Notes
- Audit trail (`/api/v1/audit`) and W3C tracecontext propagation across core+adapters land in v2.4.x patches. The data shape and metric names in v2.4.0 are stable; later patches expand instrumentation coverage without changing the public surface.
- v3 will switch to `prometheus/client_golang` (histograms with `le` buckets, native scrape negotiation). The current text-format implementation is dependency-free for adopters who do not run Prometheus.

## [2.3.0] - 2026-04-25

### Added
- New manifest kind `tenant`. Declares a top-level tenancy scope with slug, display_name, owners, billing_ref, quotas, and metadata. Slug validates against `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` (2-63 chars, lowercase alphanumeric + hyphens). Owners must be `user:<id>`, `team:<name>` or `service:<name>`. Quotas must be non-negative (0 = no cap).
- Other manifests can carry `metadata.tenant: <slug>` informationally in v2.3.0; v3.0 makes enforcement default-on.
- `YGGDRASIL_TENANCY_ENFORCED=true` env var opts into RBAC enforcement: list endpoints filter by caller's tenants, write endpoints reject mismatched tenants, quota ceilings produce 429. Default (unset/`false`) preserves v2.2 behaviour.
- `docs/tutorials/05-multi-tenancy.md` — adoption walkthrough.

### Notes
- This phase ships the **data shape** and **opt-in flag**. Quota counters and write-time enforcement land in v2.3.x patches as adopter feedback comes in. v3.0 flips `YGGDRASIL_TENANCY_ENFORCED` default to `true`.

## [2.2.0] - 2026-04-25

### Added
- New manifest kind `ephemeral_environment`. Declares a time-bounded environment with `create_workflow`, `destroy_workflow`, `ttl_seconds`, `auto_destroy`, optional `cost_projection`, and free-form `metadata`. Adopters POST one per PR / nightly env / demo env; the create_workflow runs at apply time and destroy_workflow at TTL expiry.
- Validation: TTL must be 0 (no expiry) or ≥ 60 seconds; `auto_destroy` requires `destroy_workflow`; cost values must be non-negative.
- Normalisation: `workflow_ref.namespace` defaults to `global`; `cost_projection.currency` defaults to `USD`.
- `docs/tutorials/04-ephemeral-envs.md` — end-to-end tutorial.

### Notes
- TTL reaper goroutine ships in v2.2.x (next patch). Until then, schedule the destroy workflow externally on TTL expiry. The data shape and validation are stable in v2.2.0.

## [2.1.0] - 2026-04-25

### Added
- `GET /openapi.json` — serves the bundled OpenAPI 3 spec describing the public REST surface (no auth). External tools can fetch and discover the API contract.
- `docs/quickstart.md` — 12-step walkthrough from clean k3s to a working webhook → workflow → deploy pipeline. Target: 60 minutes for a competent platform engineer who has never seen Yggdrasil.
- `docs/api-reference/openapi.json` — hand-curated OpenAPI 3 spec (~12 endpoints across health, manifests, integrations, workflows, webhooks, secrets, products).
- `docs/api-reference/openapi.md` — narrative companion explaining manifest envelope, workflow templating language (`{{ inputs.* }}`, `{{ steps.* }}`, `{{ push.* }}`), webhook signature verification, skip semantics, error envelope, auth model, idempotency, and compatibility commitments.
- `docs/api-reference/README.md` — endpoint index for quick lookup.
- `docs/tutorials/01-webhook-cd.md` — wire a real service repository to declarative CD via `repository_binding`.
- `docs/tutorials/02-custom-adapter.md` — build and deploy a custom integration adapter (Datadog event poster as worked example).
- `docs/tutorials/03-secret-store.md` — migrate inline credentials to the managed secret store with rotation.
- `docs/tutorials/README.md` — tutorial catalogue.

## [2.0.0] - 2026-04-25

### BREAKING
- `POST /api/v1/products/{namespace}/{name}/deploy`, `POST /api/v1/products/deploy-all`, `POST /api/v1/bootstrap`, and the `/api/v1/console/products/...` mirrors now return `410 Gone`. CD goes through `kind: repository_binding` manifests with a `spec.deploy` block; the GitHub webhook handler dispatches the declared workflow.
- Package `provisioner/` removed (`KustomizeDeployer` deleted). The `deploy-via-kustomize-source` workflow (using `integration-kustomize` + `integration-kubernetes`) is the supported deploy primitive.
- `addons/deployer.go` removed. The `deployer` resource and `httpapi.WithDeployer` option are gone.
- `REPO_BASE_PATH` environment variable is no longer read; remove from your deployment configuration.
- Webhook handler no longer falls back to a hardcoded `repoProductMap`. Pushes from repositories without a `repository_binding` return `200` with `status=skipped`.

### Added
- `repository_binding.spec.deploy` field with `workflow_kind`, `workflow_ref`, `default_inputs`, `branch_filter`, `path_filter`. The GitHub webhook handler consults this field to dispatch Yggdrasil workflows on push events.
- Push event templating in `default_inputs`: `{{ push.repository.full_name }}`, `{{ push.repository.clone_url }}`, `{{ push.ref }}`, `{{ push.head_commit.id }}`, `{{ push.head_commit.message }}`, `{{ push.pusher.name }}`. Non-string values pass through unchanged; unknown placeholders return error; non-`push.*` placeholders pass through verbatim.
- Database indexes `manifests_repository_binding_lookup` (lookup) and `manifests_repository_binding_unique_repo` (one binding per repo).
- `repository.FindBindingByRepository` Go function for binding lookup by repository slug.
- `branch_filter` and `path_filter` on `repository_binding.spec.deploy` (glob via `path/filepath.Match`; `*` accepts any branch).
- `workflow_kind: github_actions` is reserved (returns `501 Not Implemented` in 2.0.0; future expansion).

### Removed
- `provisioner/kustomize.go` (entire `KustomizeDeployer`, `locatorMap`, `LocatorToLocalPath`).
- `addons/deployer.go` (constructor wiring).
- `controllers/httpapi/github_webhook.go` `repoProductMap` and `repoToProduct`.
- `controllers/httpapi/server.go` `deployer` field and `WithDeployer` option.

### Migration
See `dakasa-system/docs/runbooks/yggdrasil-v2-cutover.md` for the operator playbook. Apply 17 deploy bindings + 3 observe-only bindings before flipping the control_plane image to v2.0.0; no behavioural change at cutover beyond the granularity of "push to repo X deploys repo X" replacing "push to any repo in product P deploys all of P".

## [Unreleased]

### Changed
- Integration type seeds refreshed to reflect live HTTP-transport state (github, kubernetes, aws, manifest-sources-kustomize). Greenfield deployments now bootstrap with the correct schemas — no contract_mismatch on first run after the adapters connect.

### Added
- `control_plane.spec.name` — override default resource names (`yggdrasil-core`) so in-place updates of legacy deployments are possible.
- `control_plane.spec.image_pull_secrets` — list of Kubernetes Secret names mounted as `podSpec.imagePullSecrets`.
- `control_plane.spec.pull_policy` — enum `Always|IfNotPresent|Never`, propagated to `container.imagePullPolicy`.
- `control_plane.spec.extra_env_from` — array of `{secret_ref|config_map_ref}` entries added to the core container's `envFrom`.
- `control_plane.spec.annotations` — map merged into `Deployment.spec.template.metadata.annotations`.
- `control_plane.spec.labels` — map merged into `Deployment.spec.template.metadata.labels` alongside `baseLabels`.
- `control_plane.spec.postgres.mode=inherit` — skip Postgres infra rendering when credentials are supplied via `extra_env_from`.

### Changed
- `Render` now returns an error when `spec.Postgres.Mode == "external"` and `password_ref` is missing or not a `secret://` reference (previously silently emitted an incomplete envFrom).

### Fixed
- Validator now emits distinct errors for empty-pointer vs fully-absent `extra_env_from` entries, and rejects blank names on either `secret_ref` or `config_map_ref`.
- `spec.name` regex now enforces the DNS-1123 label 63-char limit.
