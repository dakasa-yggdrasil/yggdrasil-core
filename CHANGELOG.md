# Changelog

All notable changes to yggdrasil-core are documented here.

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
