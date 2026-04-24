# Self-hosted bootstrap seeds

This directory holds the **baseline catalog** that the first-run
bootstrap addon seeds into a fresh yggdrasil-core deployment. It is a
curated subset of `../manifests/` — only the generic,
deployment-agnostic `integration_family` and `integration_type`
records an adopter needs to start using the engine.

It intentionally does NOT include:

- `*-platform*.json` — Dakasa-specific integration_instance records.
- `workflows/*` — Dakasa-specific workflow definitions.
- `products/*` — Dakasa-specific product compositions.
- `surfaces/*` — Dakasa-specific UI registrations.
- `guardian-policies/*`, `remediation-contracts/*`,
  `repository-bindings/*` — internal Dakasa platform configs.

Adopters get these families + types at first boot and can then add
their own instances via `yggdrasil install` or `yggdrasil apply`.

Contents:

- **5 integration_family** manifests: database-admin, grafana,
  rabbitmq, schema-migrations, secrets-management.
- **13 integration_type** manifests: aws, gcp, github, kubernetes,
  database-admin-postgres, grafana (runtime + kubernetes), rabbitmq
  (runtime + kubernetes + topology), schema-migrations-goose-postgres,
  secrets-management (aws + gcp).

Heimdall is not seeded (commercial guardian; see
[docs/catalog.md](../../catalog.md#guardian-integrations)).

The `YGGDRASIL_BOOTSTRAP_MANIFESTS_PATH` env var resolves to
`/app/docs/bootstrap/seeds` by default in the production container
entrypoint. Point at `/app/docs/bootstrap/manifests` to replay the
full Dakasa-internal baseline (dev use only — most entries will
fail validation on a fresh self-hosted stack).
