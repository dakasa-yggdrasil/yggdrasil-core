# Architecture Decision Records — yggdrasil-yggdrasil-core

Curated, immutable record of durable architectural decisions — one decision per file.
Working scratch (brainstorming, plans, handoffs) lives in `docs/superpowers/` and is **not
tracked** (see `AGENTS.md` § Spec-driven docs). The domain-wide model is defined in the
monorepo root `docs/adr/0001-adopt-adr-plus-scratch-model.md`. To change a decision, write a
NEW ADR that supersedes the old one; never edit an Accepted ADR's Decision.

**16 decisions.**

| ADR | Title | Status | Date | Scope |
|-----|-------|--------|------|-------|
| [0001](0001-foundational-event-stream-transactional-emission-postgresql.md) | Foundational event stream — transactional emission, PostgreSQL-backed cursor pull, JSON Schema contracts | Accepted | 2026-04-10 | yggdrasil-core |
| [0002](0002-yggdrasil-core-materializes-managed-secrets-as-native-kubern.md) | yggdrasil-core materializes managed secrets as native Kubernetes Secrets via a built-in reconciler (no External Secrets Operator) | Accepted | 2026-04-12 | yggdrasil-core (reconciler engine, cluster-facing) |
| [0003](0003-yggdrasil-core-becomes-dakasa-s-own-oidc-provider-mediating.md) | Yggdrasil-core becomes DaKasa's own OIDC Provider, mediating Google Workspace SSO | Accepted | 2026-05-05 | yggdrasil-core, dakasa-commons (oidcclient), Tartaro (dakasa-tartaro-api/dakasa-tartaro-fe, first consumer), Yggdrasil console (Phase 1: internal SSO) |
| [0004](0004-declarative-lifecycle-reactor-framework-replaces-temporal-ba.md) | Declarative lifecycle reactor framework replaces Temporal-based onboarding/offboarding workflows | Accepted | 2026-05-15 | yggdrasil-core (event/reactor pipeline, core lifecycle propagation architecture), dakasa-system (workflow removal), integration adapters |
| [0005](0005-unify-password-credential-lifecycle-into-auth-identities-arg.md) | Unify password credential lifecycle into `auth_identities`; argon2id as the hashing scheme; deprecate `yggdrasil-identities` | Accepted | 2026-05-15 | yggdrasil-core (auth/identity) |
| [0006](0006-auto-heal-integration-type-manifest-drift-from-the-adapter-s.md) | Auto-heal `integration_type` manifest drift from the adapter's live `describe` response, preserving only the operator-owned `reactors` field | Accepted | 2026-05-16 | yggdrasil-core (`integration_type` manifest lifecycle) |
| [0007](0007-provider-neutral-collaborator-external-identity-mapping-popu.md) | Provider-neutral collaborator↔external-identity mapping, populated via reactor envelope + webhook receiver | Accepted | 2026-05-16 | yggdrasil-core (`internal/externalidentity/`), integration-slack, integration-google-workspace, integration-github (opt-in adapters) |
| [0008](0008-integration-surfaces-federated-per-adapter-admin-spas-discov.md) | Integration Surfaces — federated per-adapter admin SPAs discovered by manifest and slot | Accepted | 2026-05-17 | yggdrasil-core, surface-console, surface-template, per-`integration-<name>` adapter repos |
| [0009](0009-replace-per-user-tartaro-rbac-roles-with-team-scoped-action.md) | Replace per-user Tartaro RBAC roles with team-scoped action grants materialized via the reactor framework | Accepted | 2026-05-18 | yggdrasil-core (canon events + team_grant endpoints), integration-tartaro-dakasa, dakasa-tartaro-fe (tartaro-operations, tartaro-api and sibling services), dakasa-commons |
| [0010](0010-team-mirroring-reactors-ack-via-a-reserved-envelope-into-a-p.md) | Team-mirroring reactors ack via a reserved envelope into a provisioning log, self-healed by an anti-join reconcile sweep | Accepted | 2026-05-18 | yggdrasil-core (reactor dispatcher extension), integration-slack, integration-github, integration-google-workspace |
| [0011](0011-bootstrap-internal-public-oidc-clients-declaratively.md) | Bootstrap internal public OIDC clients declaratively | Accepted | 2026-08-25 | yggdrasil-core / internal OIDC client lifecycle |
| [0012](0012-keep-sensitive-integration-outputs-transient-between-workflow-steps.md) | Keep sensitive integration outputs transient between workflow steps | Accepted | 2026-09-01 | yggdrasil-core / workflow execution and integration adapter contract |
| [0013](0013-scope-adapter-mutation-event-credentials-to-event-publishing.md) | Scope adapter mutation-event credentials to event publishing | Superseded | 2026-09-01 | yggdrasil-core / adapter authentication |
| [0014](0014-bootstrap-confidential-oidc-clients-from-read-only-secret-files.md) | Bootstrap confidential OIDC clients from read-only Secret files | Accepted | 2026-09-02 | yggdrasil-core / confidential OIDC client lifecycle |
| [0015](0015-validate-and-redact-workflow-inputs-before-async-persistence.md) | Validate and redact workflow inputs before async persistence | Accepted | 2026-09-04 | yggdrasil-core / workflow dispatch and durable run evidence |
| [0016](0016-scope-machine-principals-by-route-workflow-and-run-ownership.md) | Scope machine principals by route, workflow, and run ownership | Accepted | 2026-09-05 | yggdrasil-core / non-human HTTP authentication and workflow dispatch |
