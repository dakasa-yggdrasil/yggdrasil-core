# Integration Surfaces — Phase 1.3: surface-github Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `surface-github` as `surface-ui/` inside `integration-github`. Custom tab "Repos & Webhooks" via `on_surface_query` with `list-repos` and `list-webhooks` query names.

**Reference plan:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-05-17-integration-surfaces-phase-1.1-surface-slack.md` — boilerplate (Vite, Dockerfile, nginx, CI YAML structure) deferred.

**Working directory:** `/Users/dakasa/projects/yggdrasil/integration-github/`.

**Real codebase patterns:**
- Adapter at `internal/adapter/spec.go` (1713 lines, 45+ ops at L17-77)
- Contract: `internal/protocol`
- `Execute()` switch large; locate the closing `default:` case for the insertion point
- Existing list capabilities to potentially re-use: `list_runners`, `list_workflow_runs`, `list_container_packages`
- **HAS Taskfile.yml + deploy.yml** (existing — extend, don't recreate)
- Existing `release.yml` workflow

**Tabs:** overview, drift, identities, actions, recent-runs, webhook-log, **repos** (custom), **webhooks** (custom — uses adapter `on_webhook` data via `list-webhook-configs`).

Push direct to main. No co-author trailers.

---

## Task 1: Adapter `on_surface_query` with `list-repos` + `list-webhook-configs`

**Files:**
- Modify: `internal/adapter/spec.go` (add constant + dispatch case)
- Create: `internal/adapter/surface_query.go`
- Create: `internal/adapter/surface_query_test.go`

- [ ] **Step 1: Locate existing list operations**

```bash
grep -n "OperationListRunners\|OperationListContainerPackages\|OperationListEnterpriseOrgs" internal/adapter/spec.go | head -5
grep -n "func listRunners\|func listContainerPackages" internal/adapter/*.go
```

- [ ] **Step 2: Failing test**

`internal/adapter/surface_query_test.go`:

```go
package adapter

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/integration-github/internal/protocol"
)

func TestSurfaceQuery_RejectsUnknownQuery(t *testing.T) {
	req := protocol.AdapterExecuteIntegrationRequest{
		Operation:  OperationOnSurfaceQuery,
		Capability: OperationOnSurfaceQuery,
		Input:      map[string]any{"query_name": "list-mars-bases", "params": map[string]any{}},
	}
	_, err := Execute(req)
	if err == nil || !strings.Contains(err.Error(), "list-mars-bases") {
		t.Fatalf("expected error mentioning unknown query name, got %v", err)
	}
}

func TestSurfaceQuery_ListReposRoutesToCatalog(t *testing.T) {
	// Test that list-repos routes correctly. Real GitHub API not called;
	// credential failure is acceptable, "unknown operation" is not.
	req := protocol.AdapterExecuteIntegrationRequest{
		Operation:  OperationOnSurfaceQuery,
		Capability: OperationOnSurfaceQuery,
		Input:      map[string]any{"query_name": "list-repos", "params": map[string]any{}},
	}
	_, err := Execute(req)
	if err != nil && (strings.Contains(err.Error(), "unknown operation") || strings.Contains(err.Error(), "unsupported")) {
		t.Fatalf("list-repos routing failed: %v", err)
	}
}
```

- [ ] **Step 3: Add constant to spec.go**

In the constants block (around L17-77), append:

```go
// OperationOnSurfaceQuery — see yggdrasil-core spec 2026-05-17-integration-surfaces §5.5.
const OperationOnSurfaceQuery = "on_surface_query"
```

Also add to any operations enumeration list if present (search for `OperationOnListIdentities` and add adjacent).

- [ ] **Step 4: Add Execute switch case**

Find the `Execute()` switch and add before `default:`:

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(req)
```

- [ ] **Step 5: Implement surface_query.go**

```go
package adapter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/integration-github/internal/protocol"
)

func onSurfaceQuery(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := req.Input["query_name"].(string)
	params, _ := req.Input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	apiBaseURL, token, instanceConfig, _, err := resolveExecuteConfig(req)
	if err != nil {
		return protocol.AdapterExecuteIntegrationResponse{}, err
	}

	switch queryName {
	case "list-repos":
		// Direct GitHub API call to list org repos (read-only).
		owner := firstString(params, []string{"owner"})
		if owner == "" {
			owner = firstString(instanceConfig, []string{"default_owner"})
		}
		if owner == "" {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-repos: owner required")
		}
		path := fmt.Sprintf("/orgs/%s/repos?type=all&per_page=100", owner)
		payload, _, err := doGitHubRequest(apiBaseURL, token, http.MethodGet, path, nil, http.StatusOK)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-repos: %w", err)
		}
		var raw []map[string]any
		if err := json.Unmarshal(payload, &raw); err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-repos: decode: %w", err)
		}
		items := make([]any, 0, len(raw))
		for _, r := range raw {
			items = append(items, map[string]any{
				"id":         fmt.Sprintf("%v", r["id"]),
				"name":       r["name"],
				"kind":       "repository",
				"visibility": r["visibility"],
				"updated_at": r["updated_at"],
			})
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	case "list-webhook-configs":
		// List org-level webhooks (the configured callbacks GitHub will fire).
		owner := firstString(params, []string{"owner"})
		if owner == "" {
			owner = firstString(instanceConfig, []string{"default_owner"})
		}
		if owner == "" {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-webhook-configs: owner required")
		}
		path := fmt.Sprintf("/orgs/%s/hooks?per_page=100", owner)
		payload, _, err := doGitHubRequest(apiBaseURL, token, http.MethodGet, path, nil, http.StatusOK)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-webhook-configs: %w", err)
		}
		var raw []map[string]any
		if err := json.Unmarshal(payload, &raw); err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-webhook-configs: decode: %w", err)
		}
		items := make([]any, 0, len(raw))
		for _, h := range raw {
			cfg, _ := h["config"].(map[string]any)
			var url string
			if cfg != nil {
				url, _ = cfg["url"].(string)
			}
			events, _ := h["events"].([]any)
			items = append(items, map[string]any{
				"id":     fmt.Sprintf("%v", h["id"]),
				"name":   h["name"],
				"kind":   "webhook",
				"active": h["active"],
				"url":    url,
				"events": strings.Join(stringSlice(events), ", "),
			})
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	default:
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}

func stringSlice(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
```

Verify `doGitHubRequest`, `resolveExecuteConfig`, `firstString` exist (they're used elsewhere in this repo). If signatures differ, adapt.

- [ ] **Step 6: Run tests + build**

```bash
go test ./internal/adapter/... -run SurfaceQuery
```

- [ ] **Step 7: Commit**

```bash
git add internal/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery — list-repos + list-webhook-configs"
```

---

## Task 2: surface-ui/ scaffolding

Apply Plan 1.1 Task 2 with substitutions:
- `surface-slack` → `surface-github`
- `/s/slack/` → `/s/github/`
- title `Slack — Yggdrasil` → `GitHub — Yggdrasil`

`.npmrc`: `@dakasa-yggdrasil:registry=https://npm.pkg.github.com`

`package.json` deps include `@dakasa-yggdrasil/surface-toolkit: ^0.1.1`.

Install + build smoke. Commit.

---

## Task 3: Custom tabs

**Files:**
- Create: `surface-ui/src/tabs/GithubReposTab.tsx`
- Create: `surface-ui/src/tabs/GithubWebhooksTab.tsx`

`GithubReposTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface RepoItem extends Record<string, unknown> {
  id: string;
  name?: string;
  visibility?: string;
  updated_at?: string;
}

export interface GithubReposTabProps {
  instanceId: string;
  integrationType: string;
}

export function GithubReposTab({ instanceId }: GithubReposTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: RepoItem[] }>(instanceId, "list-repos");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items || data.items.length === 0) {
    return <EmptyState title="Nenhum repositório" />;
  }
  return (
    <DataTable<RepoItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Repositório", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "visibility", header: "Visibilidade", accessor: (r) => r.visibility ?? "—" },
        { id: "updated_at", header: "Atualizado", accessor: (r) => r.updated_at ?? "—" }
      ]}
    />
  );
}
```

`GithubWebhooksTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface WebhookItem extends Record<string, unknown> {
  id: string;
  name?: string;
  active?: boolean;
  url?: string;
  events?: string;
}

export interface GithubWebhooksTabProps {
  instanceId: string;
  integrationType: string;
}

export function GithubWebhooksTab({ instanceId }: GithubWebhooksTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: WebhookItem[] }>(instanceId, "list-webhook-configs");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items || data.items.length === 0) {
    return <EmptyState title="Nenhum webhook" />;
  }
  return (
    <DataTable<WebhookItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Hook", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "active", header: "Ativo", accessor: (r) => (r.active ? "✓" : "✗") },
        { id: "url", header: "URL", accessor: (r) => r.url ?? "—" },
        { id: "events", header: "Eventos", accessor: (r) => r.events ?? "—" }
      ]}
    />
  );
}
```

Commit: `feat(surface-ui): GithubReposTab + GithubWebhooksTab via on_surface_query`

---

## Task 4: App.tsx

`surface-ui/src/App.tsx`:

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import {
  IntegrationAdminShell,
  OverviewTab, DriftTab, IdentitiesTab,
  ActionsTab, RecentRunsTab, WebhookLogTab
} from "@dakasa-yggdrasil/surface-toolkit";
import { GithubReposTab } from "./tabs/GithubReposTab";
import { GithubWebhooksTab } from "./tabs/GithubWebhooksTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "identities", label: "Identidades", component: IdentitiesTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "webhook-log", label: "Webhook log", component: WebhookLogTab },
  { id: "repos", label: "Repos", component: GithubReposTab },
  { id: "webhooks", label: "Webhooks", component: GithubWebhooksTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="github" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="github" tabs={TABS} basePath="/" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
```

Build + commit.

---

## Task 5: surface.manifest.json

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-github",
    "namespace": "global",
    "integration_type": "github"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/github",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-github"
    },
    "display": {
      "title": "GitHub",
      "subtitle": "Repositórios, webhooks, runners",
      "icon": "github",
      "color_token": "brand.github",
      "appears_on": ["ops-integrations", "console-home"]
    },
    "core_contracts": [
      "authorization",
      "integration_catalog",
      "external_identity",
      "workflow_runs",
      "action_catalog",
      "webhooks"
    ],
    "capabilities": [
      {
        "name": "integration-admin",
        "tabs": ["overview", "drift", "identities", "actions", "recent-runs", "webhook-log", "repos", "webhooks"]
      }
    ]
  }
}
```

Commit.

---

## Task 6: nginx.conf + Dockerfile

Apply Plan 1.1 Task 5 verbatim. Smoke build + commit.

---

## Task 7: Taskfile.yml (EXTEND existing — github has Taskfile)

`integration-github` has root `Taskfile.yml`. **APPEND** surface tasks instead of overwriting:

```yaml
  # === surface-ui tasks (added 2026-05-18) ===
  surface:install:
    dir: surface-ui
    cmds: [npm ci]

  surface:build:
    dir: surface-ui
    env:
      VITE_BASE_PATH: "/s/github/"
    cmds: [npm run build]

  surface:docker:build:
    dir: surface-ui
    cmds:
      - docker build --build-arg BUILD_BASE_PATH=/s/github/ -t ghcr.io/dakasa-yggdrasil/surface-github:{{.TAG | default "dev"}} .

  surface:docker:push:
    cmds:
      - docker push ghcr.io/dakasa-yggdrasil/surface-github:{{.TAG | default "dev"}}
```

Commit.

---

## Task 8: CI workflow

`integration-github` has existing `ci.yml` + `deploy.yml`. Add `build-surface` job to `ci.yml` per Plan 1.1 Task 7, substituting:
- `surface-slack` → `surface-github`
- `/s/slack/` → `/s/github/`
- trigger sync URL: `surface-github`

Commit.

---

## Task 9: Push + observe

```bash
git push origin main
sleep 30
curl -sS "https://api.github.com/repos/dakasa-yggdrasil/integration-github/actions/runs?per_page=2" 2>/dev/null | head -100
```

Tag sync gate:
```bash
git commit --allow-empty -m "chore: Phase 1.3 complete — surface-github image pushed to GHCR"
```

## Phase 1.3 sync gate

1. ✅ Adapter routes `on_surface_query` → list-repos + list-webhook-configs
2. ✅ Custom GithubReposTab + GithubWebhooksTab
3. ✅ Image pushed to GHCR
4. ⏳ Cluster deploy via Phase 0d template
5. ⏳ Browser smoke `https://yggdrasil.dakasa.me/s/github`
