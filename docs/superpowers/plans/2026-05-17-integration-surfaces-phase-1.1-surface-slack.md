# Integration Surfaces — Phase 1.1: surface-slack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `surface-slack` — the first federated standalone surface — as a sub-folder `surface-ui/` inside `integration-slack`, consuming `@dakasa-yggdrasil/surface-toolkit@0.1.1` from GHCR npm. Add `on_surface_query` capability to the adapter for the custom "Canais" tab.

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md`.

**Working directory:** `/Users/dakasa/projects/yggdrasil/integration-slack/`.

**Real codebase patterns** (verified by Explore agent):
- Adapter: `internal/adapter/spec.go` (466 lines, 22 op constants at L15-34, `Execute()` switch at L261)
- Contract: standard `protocol.AdapterExecuteIntegrationRequest`/`Response`
- Existing capability `list_user_channels` (returns Slack channels) — we will RE-USE this internally via `on_surface_query` dispatch
- No Taskfile.yml (Plan adds one)
- CI: `.github/workflows/ci.yml` + `release.yml` (no deploy.yml — Plan adds `build-surface` job to ci.yml; deploy handled by surface-template kustomize pattern from Phase 0d)
- Registry: `ghcr.io/dakasa-yggdrasil/integration-slack` (existing); surface image: `ghcr.io/dakasa-yggdrasil/surface-slack` (NEW)

**Tabs for surface-slack** (per spec §6.4):
| Tab id | Source | Notes |
|---|---|---|
| `overview` | toolkit OverviewTab | mandatory |
| `drift` | toolkit DriftTab | mandatory |
| `identities` | toolkit IdentitiesTab | uses /collaborator-external-identities?integration_type=slack |
| `actions` | toolkit ActionsTab | uses /action-catalog?integration_type=slack |
| `recent-runs` | toolkit RecentRunsTab | uses /workflow-runs?integration_instance_id=... |
| `channels` | **custom** | uses `useSurfaceQuery(instanceId, "list-channels")` → adapter on_surface_query → list_user_channels |

**Push direct to main. No co-author trailers.**

---

## Task 1: Add `OperationOnSurfaceQuery` constant + dispatch in adapter

**Files:**
- Modify: `internal/adapter/spec.go`
- Create: `internal/adapter/surface_query.go`
- Create: `internal/adapter/surface_query_test.go`

- [ ] **Step 1: Inspect current operation constants & Execute switch**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
sed -n '15,40p' internal/adapter/spec.go
grep -n "case Operation" internal/adapter/spec.go | head -20
```

Note where the constants are declared and where the switch routes (around L261).

- [ ] **Step 2: Failing test for surface_query dispatch**

`internal/adapter/surface_query_test.go`:

```go
package adapter

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/integration-slack/internal/protocol"
)

func TestSurfaceQuery_ListChannels_ForwardsToExistingHandler(t *testing.T) {
	// Build an Input with query_name=list-channels and verify the
	// adapter routes it via on_surface_query → listUserChannels internally.
	// The actual Slack API isn't called here; we only check dispatch routing.
	req := protocol.AdapterExecuteIntegrationRequest{
		Operation:  OperationOnSurfaceQuery,
		Capability: OperationOnSurfaceQuery,
		Input: map[string]any{
			"query_name": "list-channels",
			"params":     map[string]any{},
		},
	}
	// We just verify the operation routes (not panicking, not "unknown operation").
	// Real Slack API call is mocked at a higher level if needed; for this test the
	// downstream listUserChannels will fail without credentials — that's expected and
	// we assert the error message reflects auth/config, not "unknown operation".
	resp, err := Execute(req)
	if err != nil {
		// Acceptable: credential-missing error from listUserChannels.
		// NOT acceptable: "unknown operation" — that means routing failed.
		if got := err.Error(); contains(got, "unknown operation") || contains(got, "unsupported operation") {
			t.Fatalf("on_surface_query routing failed: %v", err)
		}
		return
	}
	// If somehow it succeeds (mocked transport), assert response is at least a struct.
	if _, err := json.Marshal(resp); err != nil {
		t.Fatalf("response not marshalable: %v", err)
	}
}

func TestSurfaceQuery_UnknownQueryName_Returns400Like(t *testing.T) {
	req := protocol.AdapterExecuteIntegrationRequest{
		Operation:  OperationOnSurfaceQuery,
		Capability: OperationOnSurfaceQuery,
		Input: map[string]any{
			"query_name": "list-mars-bases",
			"params":     map[string]any{},
		},
	}
	_, err := Execute(req)
	if err == nil {
		t.Fatal("expected error for unknown query_name")
	}
	if !contains(err.Error(), "unknown query") && !contains(err.Error(), "list-mars-bases") {
		t.Errorf("error should mention unknown query or the name; got: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Run — expect FAIL**

`go test ./internal/adapter/... -run SurfaceQuery`

Expected: `OperationOnSurfaceQuery` undefined.

- [ ] **Step 4: Add constant to spec.go**

Edit `internal/adapter/spec.go`. In the constants block (around L15-34), append:

```go
// OperationOnSurfaceQuery is the adapter capability invoked by core's
// /api/v1/integrations/{instance_id}/surface-query HTTP proxy. The surface
// passes { query_name, params } as Input; this adapter routes by query_name
// to internal handlers. See yggdrasil-core spec 2026-05-17-integration-surfaces §5.5.
const OperationOnSurfaceQuery = "on_surface_query"
```

Also add to whatever `SupportedExecuteOperations` or `Describe()` list enumerates operations (if such a list exists in spec.go) — search for `OperationOnListIdentities` and add `OperationOnSurfaceQuery` adjacent.

- [ ] **Step 5: Add dispatch case to Execute switch**

In `internal/adapter/spec.go` near L261 (the `Execute()` switch), add:

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(req)
```

(Match the existing case style — likely returns `(protocol.AdapterExecuteIntegrationResponse, error)`.)

- [ ] **Step 6: Implement surface_query.go**

`internal/adapter/surface_query.go`:

```go
package adapter

import (
	"fmt"

	"github.com/dakasa-yggdrasil/integration-slack/internal/protocol"
)

// onSurfaceQuery routes surface-driven queries to existing capabilities.
// Each query_name maps to a specific resource enumeration. Add new
// branches as the surface needs more provider-specific data.
func onSurfaceQuery(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := req.Input["query_name"].(string)
	params, _ := req.Input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	switch queryName {
	case "list-channels":
		// Forward to the existing list_user_channels capability, then
		// re-shape the output for the surface's <DataTable> consumption.
		inner := protocol.AdapterExecuteIntegrationRequest{
			Operation:   OperationListUserChannels,
			Capability:  OperationListUserChannels,
			Integration: req.Integration,
			Input:       params,
		}
		resp, err := listUserChannels(inner)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-channels: %w", err)
		}
		// Re-shape inner output → { items: [{ id, name, kind }] } expected by surface.
		out, _ := resp.Output.(map[string]any)
		raw, _ := out["channels"].([]any)
		items := make([]any, 0, len(raw))
		for _, c := range raw {
			ch, _ := c.(map[string]any)
			items = append(items, map[string]any{
				"id":   ch["id"],
				"name": ch["name"],
				"kind": "channel",
			})
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil
	default:
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}
```

IMPORTANT: verify the existing handler name. If `listUserChannels` is unexported under a different name (e.g., `handleListUserChannels` or inside another file), grep for it and use the correct name:

```bash
grep -n "func listUserChannels\|func handleListUserChannels\|case OperationListUserChannels" internal/adapter/*.go
```

Also verify the output key. The existing handler likely returns `{"channels": [...]}` or `{"items": [...]}` — adjust the reshape accordingly.

- [ ] **Step 7: Run — expect PASS**

`go test ./internal/adapter/... -run SurfaceQuery`

Expected: 2 tests PASS (the first may fail with a credential error from listUserChannels, but routing is verified; the test treats credential errors as acceptable).

- [ ] **Step 8: Commit**

```bash
git add internal/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery dispatch — list-channels routes to existing listUserChannels"
```

---

## Task 2: surface-ui/ bootstrap

**Files (all NEW under `surface-ui/`):**
- Create: `surface-ui/package.json`
- Create: `surface-ui/tsconfig.json`
- Create: `surface-ui/vite.config.ts`
- Create: `surface-ui/index.html`
- Create: `surface-ui/src/main.tsx`
- Create: `surface-ui/src/App.tsx`
- Create: `surface-ui/public/healthz`
- Create: `surface-ui/.gitignore`

- [ ] **Step 1: Create directory + package.json**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
mkdir -p surface-ui/src/tabs surface-ui/public
```

`surface-ui/package.json`:

```json
{
  "name": "surface-slack",
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

- [ ] **Step 2: tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: vite.config.ts**

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: process.env.VITE_BASE_PATH ?? "/s/slack/",
  build: { sourcemap: true }
});
```

- [ ] **Step 4: index.html**

```html
<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Slack — Yggdrasil</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 5: src/main.tsx**

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App } from "./App";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1, refetchOnWindowFocus: false }
  }
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename="/s/slack">
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>
);
```

- [ ] **Step 6: public/healthz**

```
ok
```

- [ ] **Step 7: .gitignore**

```
node_modules/
dist/
*.log
.env*
```

- [ ] **Step 8: Install + build smoke**

```bash
cd surface-ui
npm install
npm run build
```

Expected: clean. If `@dakasa-yggdrasil/surface-toolkit@0.1.1` not resolvable from public npm yet, install via GHCR npm registry:

```bash
echo "@dakasa-yggdrasil:registry=https://npm.pkg.github.com" >> .npmrc
# Token may be needed for private packages — see ../README for cluster secret
npm install
```

- [ ] **Step 9: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add surface-ui
git commit -m "feat(surface-ui): bootstrap Vite + React 19 + toolkit dependency"
```

---

## Task 3: App.tsx with IntegrationAdminShell + custom Canais tab

**Files:**
- Create: `surface-ui/src/App.tsx`
- Create: `surface-ui/src/tabs/SlackChannelsTab.tsx`

- [ ] **Step 1: Implement SlackChannelsTab**

`surface-ui/src/tabs/SlackChannelsTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface ChannelItem extends Record<string, unknown> {
  id: string;
  name?: string;
  kind?: string;
}

export interface SlackChannelsTabProps {
  instanceId: string;
  integrationType: string;
}

export function SlackChannelsTab({ instanceId }: SlackChannelsTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: ChannelItem[] }>(instanceId, "list-channels");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items || data.items.length === 0) {
    return <EmptyState title="Nenhum canal" description="O bot pode não estar adicionado ao workspace ainda." />;
  }
  return (
    <DataTable<ChannelItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Canal", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "id", header: "ID", accessor: (r) => r.id }
      ]}
    />
  );
}
```

- [ ] **Step 2: Implement App.tsx**

`surface-ui/src/App.tsx`:

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
import { SlackChannelsTab } from "./tabs/SlackChannelsTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "identities", label: "Identidades", component: IdentitiesTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Recent runs", component: RecentRunsTab },
  { id: "channels", label: "Canais", component: SlackChannelsTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<InstancePicker />} />
      <Route
        path="/instance/:instanceId"
        element={<IntegrationAdminShell integrationType="slack" tabs={TABS} basePath="/" />}
      />
      <Route
        path="/instance/:instanceId/:tabId"
        element={<IntegrationAdminShell integrationType="slack" tabs={TABS} basePath="/" />}
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

// Minimal instance picker that auto-redirects to the single instance,
// or shows a select when multiple. Uses fetch directly (the toolkit doesn't
// yet ship a useInstances hook — V2 candidate).
function InstancePicker() {
  return <div style={{ padding: 32 }}>Selecione uma instância…</div>;
  // Full implementation: fetch /api/v1/integration-instances?integration_type=slack
  // and either redirect (single) or render a list (multiple).
  // For V1, the orchestrator/console-console redirects directly to a known instance.
}
```

- [ ] **Step 3: Build + visual smoke**

```bash
cd surface-ui
npm run build
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add surface-ui/src
git commit -m "feat(surface-ui): App with 5 toolkit tabs + custom Canais tab"
```

---

## Task 4: surface.manifest.json

**Files:**
- Create: `surface-ui/surface.manifest.json`

- [ ] **Step 1: Write the manifest**

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-slack",
    "namespace": "global",
    "integration_type": "slack"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/slack",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-slack"
    },
    "display": {
      "title": "Slack",
      "subtitle": "Workspace, identidades, canais",
      "icon": "slack",
      "color_token": "brand.slack",
      "appears_on": ["ops-integrations", "console-home"]
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
        "tabs": ["overview", "drift", "identities", "actions", "recent-runs", "channels"]
      }
    ]
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add surface-ui/surface.manifest.json
git commit -m "feat(surface-ui): surface.manifest.json — integration_surface kind, 5 contracts"
```

---

## Task 5: nginx.conf + Dockerfile

**Files:**
- Create: `surface-ui/nginx.conf`
- Create: `surface-ui/Dockerfile`

- [ ] **Step 1: nginx.conf**

```nginx
events {}
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;

    location / {
      try_files $uri $uri/ /index.html;
    }
    location ~* \.(js|css|woff2?|svg|png|jpg|ico)$ {
      expires 1y;
      add_header Cache-Control "public, immutable";
    }
    location = /healthz {
      return 200 'ok';
      add_header Content-Type text/plain;
    }
  }
}
```

- [ ] **Step 2: Dockerfile**

```dockerfile
FROM node:20-alpine AS build
ARG BUILD_BASE_PATH=/s/slack/
WORKDIR /app
COPY package*.json .npmrc* ./
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

- [ ] **Step 3: Build the Docker image locally**

```bash
cd surface-ui
docker build -t surface-slack:dev .
```

Expected: clean. If `npm ci` fails because `@dakasa-yggdrasil/surface-toolkit` isn't on the public npm registry, the `.npmrc` (Task 2 Step 8) handles GHCR auth — copy it into the build context.

- [ ] **Step 4: Smoke-run the image**

```bash
docker run --rm -d -p 8765:80 --name surface-slack-smoke surface-slack:dev
sleep 1
curl -sI http://localhost:8765/healthz | head -2
curl -sI http://localhost:8765/ | head -2
docker stop surface-slack-smoke
```

Expected: `HTTP/1.1 200 OK` for `/healthz`. `/` should serve index.html with status 200 (or 304).

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-slack
git add surface-ui/nginx.conf surface-ui/Dockerfile
git commit -m "feat(surface-ui): nginx + Dockerfile (multi-stage Vite build → nginx)"
```

---

## Task 6: Taskfile.yml extension (NEW for slack — repo has no Taskfile)

**Files:**
- Create: `Taskfile.yml` (root level)

- [ ] **Step 1: Write Taskfile**

```yaml
version: '3'
vars:
  SURFACE_NAME: slack
  SURFACE_IMAGE: ghcr.io/dakasa-yggdrasil/surface-slack
  ADAPTER_IMAGE: ghcr.io/dakasa-yggdrasil/integration-slack

tasks:
  test:
    desc: run Go adapter tests
    cmds:
      - go test ./...

  surface:install:
    dir: surface-ui
    desc: install npm deps
    cmds:
      - npm ci

  surface:build:
    dir: surface-ui
    desc: build SPA bundle
    env:
      VITE_BASE_PATH: "/s/{{.SURFACE_NAME}}/"
    cmds:
      - npm run build

  surface:docker:build:
    dir: surface-ui
    desc: build SPA Docker image
    cmds:
      - docker build --build-arg BUILD_BASE_PATH=/s/{{.SURFACE_NAME}}/ -t {{.SURFACE_IMAGE}}:{{.TAG | default "dev"}} .

  surface:docker:push:
    desc: push SPA image to GHCR
    cmds:
      - docker push {{.SURFACE_IMAGE}}:{{.TAG | default "dev"}}
```

- [ ] **Step 2: Smoke**

```bash
task --list
task surface:install
task surface:build
```

- [ ] **Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "feat(taskfile): root Taskfile.yml with surface:* tasks"
```

---

## Task 7: CI workflow extension — build-and-push surface

**Files:**
- Modify: `.github/workflows/ci.yml` (add `build-surface` job)
- OR Create: `.github/workflows/surface.yml` (separate workflow)

- [ ] **Step 1: Inspect existing ci.yml shape**

```bash
sed -n '1,60p' .github/workflows/ci.yml
```

Note whether it uses matrix, what credentials, what triggers (push on main? PR? tags?).

- [ ] **Step 2: Add `build-surface` job**

Append to `.github/workflows/ci.yml` (or create as separate `.github/workflows/surface.yml` if cleaner):

```yaml
  build-surface:
    name: Build & Push surface-slack image
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    needs: [test]  # adjust to whatever existing job IDs are
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: surface-ui/package-lock.json
          registry-url: "https://npm.pkg.github.com"
          scope: "@dakasa-yggdrasil"
      - name: Install + build surface
        working-directory: surface-ui
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VITE_BASE_PATH: "/s/slack/"
        run: |
          npm ci --no-audit --no-fund
          npm run build
      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build + push image
        working-directory: surface-ui
        run: |
          IMAGE=ghcr.io/dakasa-yggdrasil/surface-slack
          TAG=sha-${GITHUB_SHA::7}
          docker build --build-arg BUILD_BASE_PATH=/s/slack/ -t $IMAGE:$TAG -t $IMAGE:latest .
          docker push $IMAGE:$TAG
          docker push $IMAGE:latest
      - name: Trigger surface manifest sync
        env:
          YGG_URL: https://yggdrasil.dakasa.me
          YGG_TOKEN: ${{ secrets.YGGDRASIL_WORKFLOW_RUN_TOKEN }}
        run: |
          if [ -z "$YGG_TOKEN" ]; then
            echo "YGGDRASIL_WORKFLOW_RUN_TOKEN not set; skipping sync trigger"
            exit 0
          fi
          curl -X POST "$YGG_URL/api/v1/integration-surfaces/surface-slack/sync" \
            -H "Authorization: Bearer $YGG_TOKEN"
```

- [ ] **Step 3: Verify YAML syntax**

```bash
# If yamllint installed; otherwise just visually inspect
yamllint .github/workflows/ci.yml || true
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows
git commit -m "feat(ci): build-and-push surface-slack image + trigger manifest sync"
```

---

## Task 8: Push + observe CI

**Files:** none (deploy only)

- [ ] **Step 1: Push all commits**

```bash
git push origin main
```

If push fails (SAML / branch protection), report and stop.

- [ ] **Step 2: Watch the workflow run**

```bash
curl -sS "https://api.github.com/repos/dakasa-yggdrasil/integration-slack/actions/runs?per_page=2" 2>/dev/null | head -100
```

- [ ] **Step 3: Verify image published**

```bash
curl -sS https://ghcr.io/v2/dakasa-yggdrasil/surface-slack/tags/list 2>/dev/null | head -20
```

(May require auth; if not accessible publicly, check via cluster ECR pull-through or via GH API.)

- [ ] **Step 4: Tag sync gate**

```bash
git commit --allow-empty -m "chore: Phase 1.1 complete — surface-slack image pushed to GHCR"
```

---

## Phase 1.1 sync gate

1. ✅ Adapter exposes `on_surface_query` with list-channels routing
2. ✅ `surface-ui/` directory complete (manifest + Vite + Dockerfile)
3. ✅ Image `ghcr.io/dakasa-yggdrasil/surface-slack` built + pushed
4. ✅ CI workflow triggers + posts manifest sync to core
5. ⏳ Deploy to cluster: Phase 0d's template + cluster Yggdrasil workflow apply (separate step, blocked on 0d)
6. ⏳ End-to-end browser smoke: `https://yggdrasil.dakasa.me/s/slack` loads Slack admin shell

---

## Final code reviewer dispatch (after Task 8)

Reviewer checks:
- `OperationOnSurfaceQuery` constant present in `internal/adapter/spec.go`
- `Execute()` switch routes `on_surface_query` → `onSurfaceQuery`
- `onSurfaceQuery` errors with non-trivial message for unknown query_name (test verifies)
- `list_user_channels` output reshaped to `{items: [{id, name, kind}]}` shape (matches toolkit DataTable expectation)
- `surface.manifest.json` kind is `integration_surface` (NOT `surface`)
- `runtime.base_path` matches Vite `base` config and Docker BUILD_BASE_PATH
- No secrets baked into Dockerfile or bundle (verified by `grep -r "token\|password" surface-ui/dist/` finding nothing)
- CI workflow uses `secrets.GITHUB_TOKEN` for GHCR (no PAT)
- `npm ci` succeeds against GHCR npm with the `.npmrc` scope mapping
