# Changelog

All notable changes to yggdrasil-core are documented here.

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
