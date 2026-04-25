# Changelog

All notable changes to yggdrasil-core are documented here.

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
