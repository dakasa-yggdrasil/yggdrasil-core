# ADR-0008: Integration Surfaces — federated per-adapter admin SPAs discovered by manifest and slot

- **Status:** Accepted
- **Date:** 2026-05-17
- **Deciders:** unknown
- **Scope:** yggdrasil-core, surface-console, surface-template, per-`integration-<name>` adapter repos
- **Supersedes:** —
- **Superseded by:** —

## Context

Yggdrasil integration adapters (Slack, GitHub, Google Workspace, AWS, Kubernetes, Grafana, secrets-management, webhooks-external, etc.) needed provider-specific admin UI (list channels, list dashboards/datasources, list secrets, list configured webhooks and failed deliveries, repos, ECR images, cluster workloads...) beyond the generic overview/drift/identities/actions/recent-runs views. Building all of this into a central `surface-console` would couple its release cycle to every adapter and require it to understand every provider's data shape.

yggdrasil-core already shipped (2026-05-08) a *server-driven* UI system for this: table `surface_manifests` keyed by `surface_id`, polled from each adapter's `GET /surface/manifest`, exposed via `/api/v1/ops/surfaces*`. That system is in production and works, but has no answer for a growing functional gap — features like `collaborator_external_identities` ship with no UI client, so operators can't list/unlink/force-resync identities or inspect drift per integration instance. Two options were on the table: extend the existing server-driven model, or build a new federated model where each integration ships its own standalone SPA. Per the standing architectural posture (surfaces are plugins, substitutable, optional), independently deployed/versioned SPAs sharing only a toolkit package and the core HTTP API is the topology that avoids shell-host coupling. Module Federation, plugin-into-shell registration, and iframes were all considered and rejected as introducing exactly that coupling.

## Decision

Adopt a **federated "integration surface" pattern**, coexisting with (not replacing) the existing server-driven `surface_manifests` system: each `integration-<name>` adapter repo optionally ships its own standalone SPA under `surface-ui/`.

**Namespacing vs. the existing server-driven system** (deliberately kept apart so the two can coexist without collision):

| Domain | Old (untouched) | New (this decision) |
|---|---|---|
| Table | `surface_manifests` | `integration_surfaces` |
| Go pkg | `internal/surface/` | `internal/integrationsurfaces/` |
| HTTP path | `/api/v1/ops/surfaces*` | `/api/v1/integration-surfaces*` |
| Manifest `kind` | `surface` | `integration_surface` |
| Canon events | `surface.*` | `integration_surface.registered/.updated/.deactivated/.drift_detected` |

**Build, package, and deploy:**
- Each surface is built with Vite + React 19 + a shared, published component library (`@dakasa-yggdrasil/surface-toolkit` / `@yggdrasil/surface-toolkit`) — a Vite library build (ESM+CJS+`.d.ts`), MUI 6 as peer dep — providing design tokens, primitives (`LoadingState`, `EmptyState`, `ErrorBoundary`, `PageHeader`, `Tabs`/`TabPanel`, `DataTable`, `JsonViewer`, `TimestampRelative`, `HealthBadge`, `DriftBadge`, `IdentityRow`), a `useYggdrasilAPI` fetch hook (JSON, `credentials: "include"`, base `/api/v1`), and the top-level orchestrator `IntegrationAdminShell` (router-driven tab switching via `basePath`/`tabId` URL segments).
- Deployed as its own Docker image: `ghcr.io/dakasa-yggdrasil/surface-<name>` for public adapters, `<ecr>/surface-<name>` on ECR `sa-east-1` for private `dakasa-co` adapters — private adapters never push to GHCR, mirroring the platform's existing private-vs-public adapter registry split (enforced per-workflow via `id-token: write` + `aws-actions/configure-aws-credentials` instead of GHCR login).
- A canonical kustomize base (`surface-template/deploy/surface-base/`: Deployment + Service + Ingress + kustomization, templated via `SURFACE_NAME`/`SURFACE_IMAGE`/`SURFACE_TAG`/`SURFACE_PATH_SUFFIX`) is copied into each adapter's `deploy/surface-base/`. Boilerplate (Vite config, `Dockerfile`/`nginx.conf` multi-stage parameterized by `BUILD_BASE_PATH`, root `Taskfile.yml`, the `build-surface` CI job) is likewise templated from the canonical Phase 1.1 (slack) implementation into every subsequent integration, with deltas documented per-integration rather than re-derived. Convention for these per-adapter surface repos is push-direct-to-main, no PR, no co-author trailer.
- All surfaces run behind the same host (`yggdrasil.dakasa.me`) and reuse the existing wildcard TLS cert. Routing goes through a single, cluster-wide, shared Traefik `Middleware` `dakasa/strip-surface-prefix` (regex `^/s/[^/]+`, strips exactly the `/s/<name>` segment) chained **before** the existing `surface-auth` ForwardAuth middleware, both applied via `traefik.ingress.kubernetes.io/router.middlewares` in that order — no per-surface auth or TLS setup. Auth itself reuses the cookie-based SSO already validated by the Tartaro OIDC cutover.

**Tabs and custom data:**
- Standard tabs (`overview`, `drift`, `identities`, `actions`, `recent-runs`) are toolkit-provided and router-driven — an integration needing nothing custom (e.g. `google-workspace` V1) wires zero adapter changes and just lists these tab ids against `IntegrationAdminShell`. Integrations with no identity concept (AWS, Kubernetes) explicitly omit the `identities` tab rather than rendering it empty.
- Custom tabs require a new adapter capability, `on_surface_query` (`Input: {query_name, params}`), added only by integrations with provider-specific data (GitHub repos/webhooks, AWS ECR images, Kubernetes workloads, Slack channels, Grafana dashboards/datasources) — entirely absent from adapters with no custom tab. Handlers wrap an existing capability or add a new one, returning `{items: [...]}` shaped for the toolkit's `<DataTable>`. Core proxies it synchronously via `POST /api/v1/integrations/{instance_id}/surface-query` (called through the surface's `useSurfaceQuery(instanceId, queryName)` hook), following the same RPC-over-RabbitMQ pattern as `on_list_identities`.

**Registration, discovery, and rendering:**
- Each surface ships `surface-ui/surface.manifest.json` (`kind: integration_surface`) declaring `runtime` (SPA kind, `base_path: /s/<name>`, `health_path: /healthz`, image ref), `display` (title/subtitle/icon/`color_token`/`appears_on` slots), `core_contracts` it depends on (authorization, integration_catalog, external_identity, workflow_runs, action_catalog), and `capabilities`/tabs. CI triggers `POST /api/v1/integration-surfaces/{name}/sync` on build, which the `manifest_sync` addon (extended, not duplicated — the same addon introduced for `integration_type` drift-healing) reconciles into the `integration_surfaces` table, hash-diffing spec changes and emitting canon events.
- `surface-console` exposes `GET /api/v1/integration-surfaces?appears_on=<slot>` and renders results via a generic `<IntegrationSurfaceSlot slot="...">` / `<IntegrationSurfaceCard>` pair (plain CSS, not MUI) wired into 3 core pages (`OverviewPage` → `console-home`, `OpsIntegrationsPage` → `ops-integrations`, `CollaboratorDetailPage` → `colaborador-detail`). The console never hardcodes a specific integration's UI. Clicking a card does a **full-page navigation** to `spec.runtime.base_path` (explicit, not client-side routing) — each surface owns its own internal routing.
- The backend filters `GET /api/v1/integration-surfaces` results by intersecting each surface's declared `core_contracts` against the requesting session's policy — surfaces whose contracts the user can't satisfy are hidden, not merely disabled.
- A curated slot enum (`console-home`, `ops-integrations`, `me`, `equipe`, `orgchart`, `colaborador-detail`) is the only vocabulary surfaces can declare `appears_on` against — a contract both core (manifest validation) and every surface's manifest must agree on. V1 actively wires 3 of the 6.

## Consequences

- Surfaces are additive and independently deployable/releasable per adapter; `surface-console` stays a thin shell + shared component library consumer and does not need a redeploy to add a new integration's UI.
- Every adapter that wants a surface must implement `on_surface_query` even for a single custom tab (some V1 implementations shipped only `Execute`-level routing with placeholder query handlers, e.g. secrets-management's AWS/GCP `list-secrets` and webhooks-external's `list-failed-deliveries` — real provider wiring was deferred, so `on_surface_query` existing does not guarantee the query is fully implemented).
- Middleware ordering is load-bearing: `strip-surface-prefix` must run before `surface-auth`, otherwise auth evaluates against the un-stripped `/s/<name>/...` path.
- Private (`dakasa-co`) adapters' surface images MUST publish to ECR `sa-east-1`, never GHCR.
- `surface-toolkit` becomes a shared dependency across all 8+ surfaces — a breaking change there fans out to every adapter's `surface-ui/`, requiring a coordinated bump-and-reverify.
- `on_surface_query` is intentionally open-ended (adapter-defined query names/params) — core cannot validate query semantics, only that the capability exists; adding a custom tab is a 2-repo change (adapter capability + surface tab component), not a core code change.
- Each surface is a full separate deployable (own Dockerfile/nginx/CI/image) — more moving parts per integration than a plugin-registration model, traded for independent versioning, independent rollback, and zero shell coupling.
- Two parallel surface systems now exist in the codebase permanently (until/unless a future ADR consolidates them) — anyone extending "surfaces" must know which one they mean; the namespacing table above is the disambiguation contract.
- `core_contracts` becomes a real authorization surface: yggdrasil-core must keep the mapping between contract names and the underlying tables/APIs current, or surfaces will be incorrectly hidden or exposed.
- Provider quirks (e.g. immutable identifiers) are surfaced but not solved by this architecture — each surface/adapter still owns its own provider-specific edge cases.

## Related
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.1-surface-slack.md`
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.4-surface-grafana.md`
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.7-surface-secrets-management.md`
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.8-surface-webhooks-external.md`
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-0c-console-slots.md`
- scratch: `docs/superpowers/plans/2026-05-17-integration-surfaces-phase-0d-deploy-template.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-0a-surface-toolkit.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.2-surface-google-workspace.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.3-surface-github.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.6-surface-aws.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.5-surface-kubernetes.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md`
