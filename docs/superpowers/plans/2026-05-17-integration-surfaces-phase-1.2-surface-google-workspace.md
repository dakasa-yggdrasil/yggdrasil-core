# Integration Surfaces — Phase 1.2: surface-google-workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `surface-google-workspace` as `surface-ui/` inside `integration-google-workspace`, consuming `@dakasa-yggdrasil/surface-toolkit@0.1.1`. NO custom tabs (V1) — uses toolkit-provided tabs only.

**Reference plan:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.1-surface-slack.md` — Phase 1.1 (slack) is the canonical Phase 1 template. This plan defers boilerplate (Vite, Dockerfile, nginx, CI) to that plan and only documents the **deltas specific to google-workspace**.

**Working directory:** `/Users/dakasa/projects/yggdrasil/integration-google-workspace/`.

**Real codebase patterns** (from Explore agent):
- Adapter at `providers/runtime/adapter/spec.go` (NOT `internal/adapter/` — different from slack)
- Contract: `family/contract` types (NOT `internal/protocol` — different envelope shape)
- 20 operation constants at L17-46
- `Execute()` switch at L239
- Existing list capabilities: `list_users`, `list_user_groups`, `list_identities`
- No Taskfile.yml (Plan adds one)
- No deploy.yml (Plan adds `build-surface` job to ci.yml)

**Tabs:** overview, drift, identities, actions, recent-runs (all toolkit-provided; NO custom). No `on_surface_query` capability needed for V1 — surface uses generic core endpoints only.

**V1 note:** Since no custom tab → adapter unchanged in this phase. We CAN skip the `on_surface_query` constant and dispatch entirely for 1.2. If V2 needs `list-users` exposed in surface, add the capability then.

**Push direct to main. No co-author trailers.**

---

## Task 1: surface-ui/ scaffolding (boilerplate from Plan 1.1)

**Files (under `surface-ui/`):**
- Create: `surface-ui/package.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `src/main.tsx`, `public/healthz`, `.gitignore`, `.npmrc`

- [ ] **Step 1: Copy Plan 1.1 Task 2 verbatim, with substitutions:**

In every file, apply:
- `surface-slack` → `surface-google-workspace`
- `/s/slack/` → `/s/google-workspace/`
- `basename="/s/slack"` → `basename="/s/google-workspace"`
- `<title>Slack — Yggdrasil</title>` → `<title>Google Workspace — Yggdrasil</title>`

So `surface-ui/package.json`:

```json
{
  "name": "surface-google-workspace",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@dakasa-yggdrasil/surface-toolkit": "^0.1.1",
    "@tanstack/react-query": "^5.0.0",
    "@mui/material": "^6.0.0",
    "@emotion/react": "^11.0.0",
    "@emotion/styled": "^11.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router-dom": "^7.0.0"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@vitejs/plugin-react": "^4.3.0",
    "typescript": "^5.5.0",
    "vite": "^5.4.0"
  }
}
```

Other files (`tsconfig.json`, `vite.config.ts`, `index.html`, `src/main.tsx`, `public/healthz`, `.gitignore`) — exact contents from Plan 1.1 Task 2 with the same substitutions applied.

`surface-ui/.npmrc`:
```
@dakasa-yggdrasil:registry=https://npm.pkg.github.com
```

- [ ] **Step 2: Install + build smoke**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-google-workspace/surface-ui
npm install
npm run build
```

Expected: clean. `npm install` requires GHCR auth — CI has it via `secrets.GITHUB_TOKEN`; for local: set `NODE_AUTH_TOKEN` env from a GH Personal Access Token (read:packages scope).

- [ ] **Step 3: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-google-workspace
git add surface-ui/
git commit -m "feat(surface-ui): bootstrap Vite + React 19 + @dakasa-yggdrasil/surface-toolkit"
```

---

## Task 2: App.tsx with 5 toolkit tabs (no custom)

**Files:**
- Create: `surface-ui/src/App.tsx`

- [ ] **Step 1: Write App.tsx**

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import {
  IntegrationAdminShell,
  OverviewTab,
  DriftTab,
  IdentitiesTab,
  ActionsTab,
  RecentRunsTab
} from "@dakasa-yggdrasil/surface-toolkit";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "identities", label: "Identidades", component: IdentitiesTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Recent runs", component: RecentRunsTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<InstancePicker />} />
      <Route
        path="/instance/:instanceId"
        element={<IntegrationAdminShell integrationType="google-workspace" tabs={TABS} basePath="/" />}
      />
      <Route
        path="/instance/:instanceId/:tabId"
        element={<IntegrationAdminShell integrationType="google-workspace" tabs={TABS} basePath="/" />}
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function InstancePicker() {
  return <div style={{ padding: 32 }}>Selecione uma instância…</div>;
}
```

- [ ] **Step 2: Build verify + commit**

```bash
cd surface-ui && npm run build
cd .. && git add surface-ui/src/App.tsx && git commit -m "feat(surface-ui): App with 5 toolkit tabs (no custom)"
```

---

## Task 3: surface.manifest.json

**Files:**
- Create: `surface-ui/surface.manifest.json`

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-google-workspace",
    "namespace": "global",
    "integration_type": "google-workspace"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/google-workspace",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-google-workspace"
    },
    "display": {
      "title": "Google Workspace",
      "subtitle": "Usuários e grupos",
      "icon": "google-workspace",
      "color_token": "brand.google-workspace",
      "appears_on": ["ops-integrations"]
    },
    "core_contracts": [
      "authorization",
      "integration_catalog",
      "external_identity",
      "workflow_runs",
      "action_catalog"
    ],
    "capabilities": [
      {
        "name": "integration-admin",
        "tabs": ["overview", "drift", "identities", "actions", "recent-runs"]
      }
    ]
  }
}
```

Commit: `feat(surface-ui): surface.manifest.json — google-workspace`

---

## Task 4: nginx.conf + Dockerfile

**Reference:** Plan 1.1 Task 5. Copy `surface-ui/nginx.conf` and `surface-ui/Dockerfile` verbatim — they are integration-agnostic (the `BUILD_BASE_PATH` arg makes them parameterized).

Smoke build + run as in Plan 1.1 Task 5 Step 3/4.

Commit: `feat(surface-ui): nginx + Dockerfile (multi-stage)`

---

## Task 5: Root Taskfile.yml (NEW — google-workspace has none)

**Reference:** Plan 1.1 Task 6. Copy `Taskfile.yml` verbatim with substitutions:
- `SURFACE_NAME: slack` → `SURFACE_NAME: google-workspace`
- `SURFACE_IMAGE: ghcr.io/dakasa-yggdrasil/surface-slack` → `ghcr.io/dakasa-yggdrasil/surface-google-workspace`
- `ADAPTER_IMAGE: ghcr.io/dakasa-yggdrasil/integration-slack` → `ghcr.io/dakasa-yggdrasil/integration-google-workspace`

Commit: `feat(taskfile): root Taskfile.yml with surface:* tasks`

---

## Task 6: CI workflow extension

**Reference:** Plan 1.1 Task 7. Append `build-surface` job to `.github/workflows/ci.yml` with substitutions:
- `surface-slack` → `surface-google-workspace`
- `/s/slack/` → `/s/google-workspace/`
- The "Trigger surface manifest sync" step: `surface-slack` → `surface-google-workspace`

Commit: `feat(ci): build-and-push surface-google-workspace image`

---

## Task 7: Push + observe

**Reference:** Plan 1.1 Task 8.

```bash
git push origin main
```

Watch:
```bash
curl -sS "https://api.github.com/repos/dakasa-yggdrasil/integration-google-workspace/actions/runs?per_page=2" 2>/dev/null | head -100
```

Tag sync gate:
```bash
git commit --allow-empty -m "chore: Phase 1.2 complete — surface-google-workspace image pushed to GHCR"
```

---

## Phase 1.2 sync gate

1. ✅ `surface-ui/` directory complete (manifest + Vite + Dockerfile)
2. ✅ Image `ghcr.io/dakasa-yggdrasil/surface-google-workspace` built + pushed
3. ✅ CI workflow triggers + posts manifest sync to core
4. ⏳ Cluster deploy: via Phase 0d kustomize template (separate phase)
5. ⏳ Browser smoke: `https://yggdrasil.dakasa.me/s/google-workspace` (post-deploy)

## Final code reviewer (after Task 7)

Same checks as Plan 1.1, adapted: `integration_type: "google-workspace"`, 5 tabs (no custom), no adapter changes (no `on_surface_query` added in this phase).
