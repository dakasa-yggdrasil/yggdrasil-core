# Integration Surfaces — Federated Standalone Consoles

**Date:** 2026-05-17
**Status:** Draft — pending user review
**Scope:** V1 covers 8 integrations: `slack`, `google-workspace`, `github`, `grafana`, `kubernetes`, `aws`, `secrets-management`, `webhooks-external`.

---

## 1. Overview

Build a federated portal of standalone web consoles ("surfaces"), one per integration, dynamically discovered by yggdrasil-core and rendered as visual cards inside `surface-console`. Each surface is its own SPA, deployed independently behind Traefik at `https://yggdrasil.dakasa.me/s/<integration>/...`, sharing only a common toolkit package (`@yggdrasil/surface-toolkit`) and the yggdrasil-core HTTP API. No plugin-into-shell coupling, no Module Federation, no iframes.

The motivation is two-fold:
1. **Functional gap:** the `collaborator_external_identities` feature shipped 2026-05-16 has no UI client; operators cannot list/unlink/force-resync identities, nor inspect drift, nor view recent runs per integration instance.
2. **Architectural posture:** memory `feedback_yggdrasil_core_is_only_truth.md` is explicit that *surfaces are plugins, substituible, optional*. A federated model with dynamic discovery is the topology that respects that posture; everything else (plugin-into-shell, npm-registered surfaces) drifts toward shell-host coupling.

---

## 2. Architecture

```
                ┌─────────────────────────────────────────────────────────────┐
                │                  yggdrasil-core (Go)                         │
                │                                                              │
                │   ┌──────────────┐    ┌─────────────────┐                    │
                │   │ surfaces     │    │ manifest_sync   │  reconciles        │
                │   │ table        │◄───┤ addon (extended)│  surface_manifests │
                │   └──────┬───────┘    └─────────────────┘                    │
                │          │                                                   │
                │   ┌──────▼───────────────────┐                               │
                │   │ /api/v1/surfaces*        │                               │
                │   │ /api/v1/integrations/    │                               │
                │   │   {id}/surface-query     │  proxies to adapter           │
                │   └──────┬───────────────────┘                               │
                └──────────┼──────────────────────────────────────────────────┘
                           │ HTTP (cookie SSO)
                           │
  ┌────────────────────────┼─────────────────────────────────────────────┐
  │                        │                                              │
  │ ┌──────────────────────▼──┐  ┌──────────────────────┐                 │
  │ │ surface-console         │  │ surface-<integration>│  ... 8 surfaces │
  │ │ (at /)                  │  │ (at /s/<name>)       │                 │
  │ │                         │  │                      │                 │
  │ │ <SurfaceSlot slot="..."/│  │ <IntegrationAdmin    │                 │
  │ │  → calls /api/v1/       │  │  Shell tabs={...}/>  │                 │
  │ │  surfaces?appears_on=X  │  │                      │                 │
  │ │  → renders SurfaceCards │  │ Internal React Router│                 │
  │ │  → full-page nav to     │  │ for tabs             │                 │
  │ │    spec.runtime.base_   │  │                      │                 │
  │ │    path                 │  │ Uses @yggdrasil/     │                 │
  │ │                         │  │  surface-toolkit     │                 │
  │ └─────────────────────────┘  └──────────────────────┘                 │
  │                                                                       │
  │                Federated SPAs behind same Traefik / same cookie SSO   │
  └───────────────────────────────────────────────────────────────────────┘
```

**Discovery flow:**
1. Adapter ships `surface-ui/surface.manifest.json` in its repo.
2. On adapter image build (CI), workflow calls `POST /api/v1/surfaces/{name}/sync` triggering the `manifest_sync` addon to re-read the manifest from the repo (via integration-github) and upsert into the `surface_manifests` table. Emits canon `surface.registered` or `surface.updated`.
3. Console-console pages render `<SurfaceSlot slot="..."/>`, which calls `GET /api/v1/surfaces?appears_on=<slot>`.
4. Backend returns active surface manifests where `spec.display.appears_on` contains the slot AND the requesting session has the required `core_contracts`.
5. Frontend renders one `SurfaceCard` per result. Click navigates (full page) to `spec.runtime.base_path`.

**Auth:** cookie-based SSO (already validated in the Tartaro cutover 2026-05-14). Console-console and all surfaces share the same domain (`yggdrasil.dakasa.me`), so cookies propagate without configuration. Traefik `ForwardAuth` middleware delegates session validation to `surface-auth`.

**Provider-specific data:** each adapter can declare a new `OperationOnSurfaceQuery` operation. Core proxies `POST /api/v1/integrations/{instance_id}/surface-query` calls into the adapter via the existing RabbitMQ dispatch path. Adapter implements `on_surface_query(query_name, params)` returning JSON. Same operational pattern as `on_list_identities`.

---

## 3. Surface Manifest Schema

Each `integration-<name>/surface-ui/surface.manifest.json`:

```jsonc
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "surface",
  "metadata": {
    "name": "surface-slack",                          // globally unique
    "namespace": "global",
    "integration_type": "slack"                       // FK to integration_types.name
  },
  "spec": {
    "category": "integration",                        // "integration" | "core" | "domain"
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",                                  // new value (template had "http_api")
      "exposure": "public",
      "base_path": "/s/slack",                        // matches Traefik IngressRoute PathPrefix
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-slack"
    },
    "display": {
      "title": "Slack",
      "subtitle": "Workspace & vínculos",
      "icon": "slack",                                // resolved by design tokens
      "color_token": "brand.slack",
      "appears_on": ["ops-integrations", "console-home"]
    },
    "core_contracts": [
      "authorization",
      "integration_catalog",
      "external_identity"
    ],
    "capabilities": [
      {
        "name": "integration-admin",
        "tabs": ["overview", "drift", "identities", "actions", "recent-runs", "channels"]
      }
    ]
  }
}
```

### URL convention (path-based)

All surfaces are mounted under `https://yggdrasil.dakasa.me/s/<integration>/`. Within each surface, React Router handles the following pattern:

```
/s/<integration>/                              # entry; auto-redirects to /instance/<id> if single instance, else shows picker
/s/<integration>/instance/<instance_id>/       # default tab (overview)
/s/<integration>/instance/<instance_id>/<tab>  # specific tab (drift, identities, actions, etc.)
```

Card click in console-console navigates to `spec.runtime.base_path` (e.g., `/s/slack`); the surface then resolves the instance selection internally. Deep linking (`/s/slack/instance/abc-123/identities`) bookmarkable; the IntegrationAdminShell preserves tab+instance state across reloads.

### Slot enum (V1)

| Slot ID | Console page | Notes |
|---|---|---|
| `console-home` | `/` | grid hero — high-impact surfaces |
| `ops-integrations` | `/ops/integrations` | primary discovery page |
| `me` | `/me` | collaborator-facing (V2 candidates) |
| `equipe` | `/equipe/:id` | team-scoped (V2 candidates) |
| `orgchart` | `/orgchart` | reserved (V2+) |
| `colaborador-detail` | `/colaboradores/:id` | per-collaborator extension (grafana/slack/gh — show external_identity vinculation) |

V1 actively uses `console-home`, `ops-integrations`, and `colaborador-detail`. Other slots are wired but unused; surfaces may opt in in later iterations.

### Core_contracts enum

| Contract | Description |
|---|---|
| `authorization` | requires session + policy check |
| `integration_catalog` | needs integration_types + integration_instances |
| `external_identity` | needs collaborator_external_identities |
| `workflow_runs` | needs workflow_runs (recent-runs tab) |
| `webhooks` | needs audit_events with source=webhook |
| `action_catalog` | needs action_catalog table |

Backend cross-checks `core_contracts` against the session's policy when serving `GET /api/v1/surfaces`; surfaces whose contracts the user cannot fulfill are filtered out.

---

## 4. Discovery: yggdrasil-core changes

### 4.1 Migration (new)

`db/migrations/00045_surface_manifests.sql` (renumber if collision at apply time):

```sql
CREATE TABLE surface_manifests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  integration_type text,                              -- nullable; "core" surfaces don't have one
  category text NOT NULL CHECK (category IN ('integration','core','domain')),
  spec jsonb NOT NULL,
  active boolean NOT NULL DEFAULT true,
  registered_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_integration_type FOREIGN KEY (integration_type)
    REFERENCES integration_types(name) ON DELETE SET NULL
);

CREATE INDEX surface_manifests_active_idx ON surface_manifests (active) WHERE active;
CREATE INDEX surface_manifests_appears_on_idx ON surface_manifests
  USING gin ((spec->'display'->'appears_on'));
CREATE INDEX surface_manifests_integration_type_idx ON surface_manifests (integration_type)
  WHERE active;
```

### 4.2 manifest_sync addon extension

`internal/manifestsync/syncer.go` is extended to reconcile two collections:
- `integration_types` (existing)
- `surface_manifests` (new)

Same loop, same canon-event emission semantics, same cron priority (85). Reads `surface.manifest.json` from the adapter repo via integration-github; validates against schema (Section 3); upserts row.

### 4.3 Canon events

Four new constants registered in `internal/events/`:

| Event | Trigger | Payload |
|---|---|---|
| `surface.registered` | first time syncer sees a surface manifest | `{ surface_name, integration_type, spec, registered_at }` |
| `surface.updated` | manifest spec hash changes | `{ surface_name, prev_version, new_version, diff }` |
| `surface.deactivated` | adapter removes manifest or marks deprecated | `{ surface_name, reason }` |
| `surface.drift_detected` | persisted manifest differs from runtime image's bundled manifest | `{ surface_name, persisted_version, runtime_version }` |

Each has a JSON schema in `internal/events/schemas/`.

### 4.4 HTTP endpoints

In `controllers/httpapi/surfaces.go`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/surfaces` | list all active surfaces (paginated); supports `?appears_on=`, `?integration_type=`, `?category=` |
| GET | `/api/v1/surfaces/{name}` | full manifest + last health probe |
| POST | `/api/v1/surfaces/{name}/sync` | force re-read manifest from repo (operator-triggered) |

Authorization: standard session middleware. List endpoint additionally filters by `core_contracts` intersected with session policy.

### 4.5 Provider-specific query proxy

In `controllers/httpapi/integration_surface_query.go`:

```
POST /api/v1/integrations/{instance_id}/surface-query
Body: { "query_name": "list-channels", "params": { ... } }
```

Dispatches to adapter via RabbitMQ with operation `OperationOnSurfaceQuery`. Adapter response returned verbatim. Errors mapped to standard HTTP status codes (404 if instance not found, 400 if query_name not declared in adapter's catalog, 502 if adapter unreachable, 504 on timeout).

New operation constant `OperationOnSurfaceQuery` added to `internal/integrations/operations.go`. Manifest_sync validates that adapters claiming this operation declare a `query_name` enum in their input schema.

---

## 5. Console-console portal

### 5.1 New components in `surface-console/src/lib/surfaces/`

```
src/lib/surfaces/
├── SurfaceSlot.tsx          // <SurfaceSlot slot="ops-integrations" layout="grid"/>
├── SurfaceCard.tsx          // visual card; icon + title + subtitle + badge
├── useSurfaces.ts           // hook: fetch + cache + filter
├── useSurfacesByMany.ts     // batch fetch for pages with multiple slots
├── types.ts                 // SurfaceManifestT, SlotID, etc.
└── icons/                   // built-in icon set (slack, github, ...) — falls back to generic
```

### 5.2 Slot integration map (V1)

| Console file | Modification |
|---|---|
| `src/pages/ops/IntegrationsPage.tsx` | replace static integration_type grid with `<SurfaceSlot slot="ops-integrations" layout="grid"/>`; keep "+ Nova instância" action |
| `src/pages/HomePage.tsx` (or equivalent `/`) | add `<SurfaceSlot slot="console-home" layout="grid"/>` below welcome |
| `src/pages/collaborators/CollaboratorDetailPage.tsx` | add tabs section `<SurfaceSlot slot="colaborador-detail" layout="inline" context={{collaboratorId}}/>` |

### 5.3 Card UX

- Icon resolved via `display.icon` (curated set in toolkit + console)
- Background tint = `display.color_token` resolved against design tokens (e.g., `brand.slack` = `#4A154B`)
- Title + subtitle from manifest
- Badge: "Novo" if `registered_at` is within 7 days, "Atualizado" if `updated_at` within 24h, "Deprecated" if `active=false` (still shown for awareness)
- Click handler: `window.location.assign(spec.runtime.base_path)` — explicit full-page navigation, NOT React Router push

### 5.4 Empty state

Each slot can pass a custom `emptyState` element. Default shows "Nenhuma surface disponível neste contexto" with link to `/ops/integrations` if user has ops permission, or contextual help otherwise.

### 5.5 Performance

- Server-side: `/api/v1/surfaces` response is cacheable (60s TTL). Cache key includes session role for permission-filtered variants.
- Client-side: React Query, 5min staleTime. Pages with multiple slots batch into a single `?appears_on=<slot1>,<slot2>` request via `useSurfacesByMany`.

---

## 6. surface-toolkit package

### 6.1 New repo

`dakasa-yggdrasil/surface-toolkit` (public). Publishes `@yggdrasil/surface-toolkit@<version>` to npm + GHCR npm registry. Vite library mode build, TypeScript, React 19, react-router-dom 7 as peerDependencies (matching surface-console).

### 6.2 Exports

| Category | Symbols |
|---|---|
| Design tokens | `tokens.colors.*`, `tokens.spacing.*`, `tokens.typography.*`, `tokens.brand.<integration>` |
| Layout components | `<PageHeader>`, `<Tabs>`, `<TabPanel>`, `<EmptyState>`, `<LoadingState>`, `<ErrorBoundary>` |
| Data components | `<DataTable>`, `<JsonViewer>`, `<TimestampRelative>`, `<HealthBadge>`, `<DriftBadge>`, `<IdentityRow>` |
| Hooks | `useYggdrasilAPI()`, `useInstance(id)`, `useDriftStatus(id)`, `useIdentities(instanceId)`, `useActionCatalog(integrationType)`, `useRecentRuns(instanceId)`, `useWebhookLog(instanceId)`, `useSurfaceQuery(instanceId, queryName, params)` |
| Tab components (ready to wire) | `<OverviewTab>`, `<DriftTab>`, `<IdentitiesTab>`, `<ActionsTab>`, `<RecentRunsTab>`, `<WebhookLogTab>`, `<ResourcesTab>` |
| Shell | `<IntegrationAdminShell tabs={[...]}/>` |

### 6.3 IntegrationAdminShell contract

```tsx
type TabDefinition = {
  id: string;
  label: string;
  component: React.ComponentType<{
    instanceId: string;
    integrationType: string;
  }>;
};

<IntegrationAdminShell
  integrationType="slack"
  tabs={[
    { id: "overview", label: "Overview", component: OverviewTab },
    { id: "drift", label: "Drift", component: DriftTab },
    { id: "identities", label: "Identidades", component: IdentitiesTab },
    { id: "channels", label: "Canais", component: SlackChannelsTab },  // surface-specific
  ]}
/>
```

Internals:
- Reads `:instanceId` from React Router path; auto-redirects to first instance if multiple exist and none selected
- Auto-fetches instance metadata (via `useInstance`) and exposes it to children via React context (avoids per-tab re-fetch)
- Renders left sidebar of tabs (responsive collapses to top tabs on mobile)
- Breadcrumb: "Integrações / Slack / <instance_name> / <tab>"
- Handles loading/error states uniformly via toolkit primitives

### 6.4 Mandatory vs opt-in tabs (V1)

- **Mandatory** (every surface must include): `overview`, `drift`
- **Opt-in toolkit-provided:** `identities`, `actions`, `recent-runs`, `webhook-log`, `resources`
- **Opt-in surface-custom:** any number, must use toolkit primitives (`<DataTable>`, etc.)

Tabs each surface uses in V1:

| Surface | overview | drift | identities | actions | recent-runs | webhook-log | resources | custom |
|---|---|---|---|---|---|---|---|---|
| slack | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | Canais |
| google-workspace | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | – |
| github | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | – | Repos & Webhooks |
| grafana | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | Dashboards, Datasources |
| kubernetes | ✓ | ✓ | – | ✓ | ✓ | – | – | Workloads, Cluster info |
| aws | ✓ | ✓ | – | ✓ | ✓ | – | – | Accounts |
| secrets-management | ✓ | ✓ | – | ✓ | ✓ | – | ✓ | – |
| webhooks-external | ✓ | ✓ | – | ✓ | ✓ | ✓ | – | Webhooks configurados, Failed deliveries |

---

## 7. Build, CI, Deploy

### 7.1 Per-integration repo layout

```
integration-<name>/
├── providers/                       # Go adapter (existing)
├── family/                          # Go contract (existing)
├── surface-ui/                      # NEW
│   ├── surface.manifest.json
│   ├── package.json                 # deps: @yggdrasil/surface-toolkit, react, vite
│   ├── vite.config.ts               # base from VITE_BASE_PATH env
│   ├── tsconfig.json
│   ├── nginx.conf
│   ├── Dockerfile
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx                  # IntegrationAdminShell config
│   │   └── tabs/                    # surface-specific custom tabs
│   └── public/
│       └── healthz                  # "ok" static file
├── go.mod
├── main.go
├── Dockerfile                       # Go adapter (existing)
└── Taskfile.yml                     # extended with surface:* tasks
```

### 7.2 Dockerfile pattern (identical across 8 surfaces)

```dockerfile
FROM node:20-alpine AS build
ARG BUILD_BASE_PATH=/s/UNSET/
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ENV VITE_BASE_PATH=${BUILD_BASE_PATH}
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY --from=build /app/public/healthz /usr/share/nginx/html/healthz
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 7.3 Image routing

| Surface | Visibility | Registry |
|---|---|---|
| surface-slack | public | GHCR |
| surface-google-workspace | public | GHCR |
| surface-github | public | GHCR |
| surface-grafana | public | GHCR |
| surface-kubernetes | public | GHCR |
| surface-aws | public | GHCR |
| surface-secrets-management | public | GHCR |
| surface-webhooks-external | **private** | **ECR sa-east-1** |
| surface-toolkit (npm) | public | npm + GHCR npm |

Public images consumed in cluster via the existing ECR pull-through cache (`153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/...`). Private images push directly to ECR sa-east-1 + `ecr-pull-sa-east-1` imagePullSecret (per memory `feedback_private_adapters_ecr_not_ghcr`).

### 7.4 CI workflow extension

Each integration repo's `.github/workflows/ci.yml` adds a `build-surface` job parallel to `build-adapter`:

```yaml
build-surface:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with: { node-version: 20, cache: npm, cache-dependency-path: surface-ui/package-lock.json }
    - run: task surface:install
    - run: task surface:test
    - run: task surface:build
    # Login to ECR or GHCR depending on repo
    - run: task surface:docker:build SURFACE_NAME=<name> SURFACE_IMAGE=<image> TAG=${{ github.sha }}
    - run: task surface:docker:push
    - name: Trigger surface manifest sync
      run: |
        curl -X POST "$YGGDRASIL_URL/api/v1/surfaces/surface-<name>/sync" \
          -H "Authorization: Bearer $YGGDRASIL_WORKFLOW_RUN_TOKEN"
```

### 7.5 Deploy via dakasa-system-yggdrasil-v2

New kustomize overlay per surface: `yggdrasil/dakasa/services/surface-<integration>/`. Contains:

- `Deployment` (1 replica V1, scales independently)
- `Service` (ClusterIP, port 80)
- `IngressRoute` (Traefik v3):

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: surface-<name>
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`yggdrasil.dakasa.me`) && PathPrefix(`/s/<name>`)
      kind: Rule
      middlewares:
        - name: strip-surface-prefix
        - name: yggdrasil-auth
      services:
        - name: surface-<name>
          port: 80
```

`strip-surface-prefix` is a Traefik `StripPrefix` middleware stripping `/s/<name>` so nginx sees `/`. `yggdrasil-auth` is the existing `ForwardAuth` middleware delegating to `surface-auth`.

### 7.6 Service discovery (core → surface)

Optional. Core does NOT need to call surfaces (data flow is reversed). For the card health badge ("degraded" badge if a surface is down), the syncer can probe `http://surface-<name>.yggdrasil.svc.cluster.local/healthz` periodically. URL inferred by convention from `metadata.name`.

---

## 8. Execution order

### 8.1 Phase 0 — Foundation (4 parallel streams)

Contracts (Sections 3–7) are fixed before Phase 0 starts; all 4 streams build against them in parallel.

| Stream | Repo | Deliverable |
|---|---|---|
| 0a | new `surface-toolkit` | published `@yggdrasil/surface-toolkit@0.1.0` with all exports from §6.2 |
| 0b | `yggdrasil-core` | migration, handlers, manifest_sync extension, 4 canon events, `OperationOnSurfaceQuery` proxy |
| 0c | `surface-console` | `SurfaceSlot`, `SurfaceCard`, hooks, integration into `/ops/integrations`, `/`, `/colaboradores/:id` |
| 0d | `dakasa-system-yggdrasil-v2` | kustomize template `services/surface-template/`, smoke deploy with placeholder surface |

**Phase 0 sync gate:**
1. `@yggdrasil/surface-toolkit@0.1.0` published and installable
2. yggdrasil-core deployed, `GET /api/v1/surfaces` returns `[]`
3. surface-console deployed, slots render empty states
4. Placeholder surface deployed via 0d's template, reachable at `/s/placeholder`, smoke E2E green

### 8.2 Phase 1 — 8 surfaces in parallel + adapter capabilities

Each integration repo gets its own implementer subagent. Work per surface:
1. `surface-ui/` directory: `surface.manifest.json`, `package.json`, `vite.config.ts`, `Dockerfile`, `nginx.conf`, `src/App.tsx`, custom tabs as needed
2. CI extension: `build-surface` job in `.github/workflows/ci.yml`
3. Taskfile extension: `surface:*` tasks
4. **If applicable:** adapter spec extension adding `OperationOnSurfaceQuery` + handler implementation with the queries this surface's custom tabs require

Adapter capability additions (7 of 8 — google-workspace has no custom tab V1):

| Surface | Custom queries |
|---|---|
| slack | `list-channels` |
| github | `list-repos`, `list-webhooks` |
| grafana | `list-dashboards`, `list-datasources` |
| kubernetes | `list-workloads`, `cluster-info` |
| aws | `list-accounts` |
| secrets-management | `list-secrets` |
| webhooks-external | `list-configured`, `list-failed-deliveries` |

**Phase 1 smoke E2E:**
1. Each surface accessible at `/s/<integration>`
2. `GET /api/v1/surfaces` returns 8 manifests
3. `/ops/integrations` renders 8 cards
4. Click each card → loads surface, mandatory tabs work
5. Identities surfaces (slack/gw/github/grafana) list real identities
6. Each custom tab via `on_surface_query` returns real data

### 8.3 Estimated parallelism

- Phase 0: 4 concurrent subagent dispatches, ~3–5 days wall time with two-stage review per task
- Phase 1: 8 concurrent surface implementers + adapter-capability work bundled into each = 8 dispatches, ~1–2 days wall time
- Total: 5–7 days realistic, ~10 days conservative including review loops

### 8.4 Risk register

| Risk | Mitigation |
|---|---|
| Toolkit instability after `@0.1.0` | Phase 0a includes smoke test "install + IntegrationAdminShell renders" before Phase 1 opens |
| Naming/concept drift across 8 surfaces | Spec glossary (§10); spec-compliance reviewer cross-checks |
| Custom tab implementations diverge | Toolkit provides `<DataTable>` with built-in pagination; spec prohibits custom pagination in V1 |
| CI workflow incompatibility | Spec pins node 20, vite 5, react 19 |
| Production breakage on deploy | `replicas: 1` V1; 24h monitor; rollback = revert Deployment |
| Cookie SSO breaks across new path `/s/*` | Tartaro cutover already validated cookie SSO at arbitrary subpaths; ForwardAuth middleware applied to all `/s/*` ingress routes |
| `on_surface_query` adds latency to custom tabs | Provider-specific data fetched lazily on tab activation, not on surface load; toolkit `<LoadingState>` covers UX |

---

## 9. Out of scope (V2 candidates)

- Surfaces in other integrations beyond the 8 (loki, prometheus, heimdall, etc.)
- `me`, `equipe`, `orgchart`, `dashboard_card` slots (wired but unused V1)
- Surface-to-surface navigation (deep linking between surfaces)
- Surface theming per tenant
- Self-hosted surface marketplace (third-party contributions)
- Module Federation (revisit if third parties want to contribute surfaces without forking the integration repo)
- WebSocket / live updates inside surfaces (V1 is polling-based via React Query)
- Mobile-first responsive design (V1 desktop-first; toolkit components are responsive but no E2E mobile QA)
- A11y certification (toolkit components ship a11y attributes; full audit deferred)

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **Surface** | A standalone web SPA serving a focused UI area (admin, collaborator self-service, etc.) |
| **Surface manifest** | `surface.manifest.json` declaring deploy unit + display + capabilities |
| **Slot** | Named "vitrine" inside a console-console page that lists surface cards |
| **Mount** | (Deprecated mid-brainstorm.) Was the extension-point concept; superseded by federated standalone model |
| **`appears_on`** | Manifest field listing which slots a surface inscribes itself into |
| **`core_contracts`** | Manifest field listing yggdrasil-core APIs the surface depends on; gates permission filtering |
| **Tab** | An internal navigation section within an `IntegrationAdminShell` instance; surface-internal concept |
| **Toolkit** | The `@yggdrasil/surface-toolkit` npm package shared by all surfaces |
| **`on_surface_query`** | New adapter operation for provider-specific data queries from surface custom tabs |
| **Mandatory tab** | Toolkit-provided tab every surface must include (`overview`, `drift`) |
| **Opt-in tab** | Toolkit-provided tab a surface may include (identities, actions, recent-runs, webhook-log, resources) |
| **Custom tab** | Surface-specific tab built using toolkit primitives and `on_surface_query` for data |

---

## 11. References

- [[project-collaborator-external-identities-shipped-2026-05-16]] — context for identities tab
- [[project-manifest-sync-shipped-2026-05-16]] — addon that reconciles `surface_manifests`
- [[project-tartaro-sso-login-e2e-2026-05-15]] — cookie SSO validated cross-path
- [[reference-yggdrasil-core-repos]] — `yggdrasil-core` is the only source of truth
- [[feedback-yggdrasil-core-is-only-truth]] — surfaces are plugins, optional, substituble
- [[feedback-private-adapters-ecr-not-ghcr]] — ECR routing for dakasa-co repos
- `surface-template/surface.manifest.json` — existing manifest shape; `runtime.kind: "spa"` is the new value introduced here
- `surface-employment-clt-ui/package.json` — exists as npm-package precedent; not applicable to federated model
- HANDOFF-yggdrasil-console-ops.md (2026-05-08) — earlier server-driven UI proposal; superseded
