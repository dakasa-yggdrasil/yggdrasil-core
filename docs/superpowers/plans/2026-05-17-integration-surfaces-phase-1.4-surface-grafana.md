# Integration Surfaces — Phase 1.4: surface-grafana Implementation Plan

> Use `superpowers:subagent-driven-development`. Checkbox steps.

**Goal:** Ship `surface-grafana` inside `integration-grafana`. Custom tabs Dashboards + Datasources via `on_surface_query` (NEW capability).

**Reference:** Plan 1.1 (slack) for boilerplate (Vite, Dockerfile, nginx, CI structure).

**Working dir:** `/Users/dakasa/projects/yggdrasil/integration-grafana/`.

**Real patterns:**
- Adapter at `providers/runtime/adapter/spec.go` (1137 lines, 20 ops at L19-49)
- Contract: `family/contract` (NOT `internal/protocol`)
- `Execute()` switch at L305
- No Taskfile (Plan adds), HAS deploy.yml + ci.yml
- Existing helpers verified by grep first: `firstString`, `firstStringDefault`, `doHTTPRequest` (or whatever Grafana adapter uses for HTTP calls — likely a `grafanaClient` struct)

Push direct to main. No co-author trailers.

---

## Task 1: Adapter `on_surface_query` with list-dashboards + list-datasources

**Files:**
- Modify: `providers/runtime/adapter/spec.go` (constant + dispatch)
- Create: `providers/runtime/adapter/surface_query.go`
- Create: `providers/runtime/adapter/surface_query_test.go`

- [ ] **Step 1: Grep existing helpers**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-grafana
grep -n "grafanaClient\|doGrafana\|grafanaRequest\|client.do" providers/runtime/adapter/*.go | head -10
grep -n "func listUsersPage\|func grafanaGet" providers/runtime/adapter/*.go | head -5
```

Note the HTTP helper pattern used by existing `list_identities` (it's `client.doJSON(ctx, "GET", path, nil, &users, 200)` per memory grafana commit chain).

- [ ] **Step 2: Failing test**

`providers/runtime/adapter/surface_query_test.go`:

```go
package adapter

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/integration-grafana/family/contract"
)

func TestSurfaceQuery_RejectsUnknownQuery(t *testing.T) {
	_, err := Execute(contract.AdapterExecuteIntegrationRequest{
		Operation: OperationOnSurfaceQuery,
		Input:     map[string]any{"query_name": "list-mars-bases"},
	})
	if err == nil || !strings.Contains(err.Error(), "list-mars-bases") {
		t.Fatalf("expected unknown-query error, got %v", err)
	}
}
```

- [ ] **Step 3: Add constant**

In `providers/runtime/adapter/spec.go` (L19-49 constants block):

```go
const OperationOnSurfaceQuery = "on_surface_query"
```

Also add to `ResourceTypes`/`DefaultActions`/etc. if those enumerate operations.

- [ ] **Step 4: Add Execute switch case**

In `Execute()` switch (L305 area):

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(ctx, client, input)
```

(Match the actual signature — likely `(ctx, client, req.Input)`).

- [ ] **Step 5: Implement surface_query.go**

```go
package adapter

import (
	"context"
	"fmt"

	"github.com/dakasa-yggdrasil/integration-grafana/family/contract"
)

func onSurfaceQuery(ctx context.Context, client grafanaClient, input map[string]any) (contract.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := input["query_name"].(string)
	switch queryName {
	case "list-dashboards":
		var dashboards []map[string]any
		_, _, err := client.doJSON(ctx, "GET", "/search?type=dash-db&limit=1000", nil, &dashboards, 200)
		if err != nil {
			return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-dashboards: %w", err)
		}
		items := make([]any, 0, len(dashboards))
		for _, d := range dashboards {
			items = append(items, map[string]any{
				"id":     fmt.Sprintf("%v", d["uid"]),
				"name":   d["title"],
				"kind":   "dashboard",
				"folder": d["folderTitle"],
			})
		}
		return contract.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	case "list-datasources":
		var ds []map[string]any
		_, _, err := client.doJSON(ctx, "GET", "/datasources", nil, &ds, 200)
		if err != nil {
			return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-datasources: %w", err)
		}
		items := make([]any, 0, len(ds))
		for _, d := range ds {
			items = append(items, map[string]any{
				"id":   fmt.Sprintf("%v", d["uid"]),
				"name": d["name"],
				"kind": d["type"],
			})
		}
		return contract.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	default:
		return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}
```

Verify `grafanaClient` exposes `doJSON` — if it's called differently in the actual code, adapt. Verify the Execute switch passes `client` and `input` in the matched order.

- [ ] **Step 6: Run + commit**

```bash
go test ./providers/runtime/adapter/... -run SurfaceQuery
git add providers/runtime/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery — list-dashboards + list-datasources"
```

---

## Task 2: surface-ui/ scaffolding

Apply Plan 1.1 Task 2 with substitutions `surface-slack` → `surface-grafana`, `/s/slack/` → `/s/grafana/`, title accordingly. `.npmrc` with `@dakasa-yggdrasil` scope. Install + build + commit.

---

## Task 3: Custom tabs

**Files:**
- Create: `surface-ui/src/tabs/GrafanaDashboardsTab.tsx`
- Create: `surface-ui/src/tabs/GrafanaDatasourcesTab.tsx`

`GrafanaDashboardsTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface DashboardItem extends Record<string, unknown> {
  id: string;
  name?: string;
  folder?: string;
}

export interface GrafanaDashboardsTabProps {
  instanceId: string;
  integrationType: string;
}

export function GrafanaDashboardsTab({ instanceId }: GrafanaDashboardsTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: DashboardItem[] }>(instanceId, "list-dashboards");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhum dashboard" />;
  return (
    <DataTable<DashboardItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Dashboard", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "folder", header: "Pasta", accessor: (r) => r.folder ?? "—" }
      ]}
    />
  );
}
```

`GrafanaDatasourcesTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface DatasourceItem extends Record<string, unknown> {
  id: string;
  name?: string;
  kind?: string;
}

export interface GrafanaDatasourcesTabProps {
  instanceId: string;
  integrationType: string;
}

export function GrafanaDatasourcesTab({ instanceId }: GrafanaDatasourcesTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: DatasourceItem[] }>(instanceId, "list-datasources");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhuma datasource" />;
  return (
    <DataTable<DatasourceItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Datasource", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "kind", header: "Tipo", accessor: (r) => r.kind ?? "—" }
      ]}
    />
  );
}
```

Commit.

---

## Task 4: App.tsx

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import {
  IntegrationAdminShell,
  OverviewTab, DriftTab, IdentitiesTab, ActionsTab, RecentRunsTab
} from "@dakasa-yggdrasil/surface-toolkit";
import { GrafanaDashboardsTab } from "./tabs/GrafanaDashboardsTab";
import { GrafanaDatasourcesTab } from "./tabs/GrafanaDatasourcesTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "identities", label: "Identidades", component: IdentitiesTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "dashboards", label: "Dashboards", component: GrafanaDashboardsTab },
  { id: "datasources", label: "Datasources", component: GrafanaDatasourcesTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="grafana" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="grafana" tabs={TABS} basePath="/" />} />
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
    "name": "surface-grafana",
    "namespace": "global",
    "integration_type": "grafana"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/grafana",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-grafana"
    },
    "display": {
      "title": "Grafana",
      "subtitle": "Dashboards e datasources",
      "icon": "grafana",
      "color_token": "brand.grafana",
      "appears_on": ["ops-integrations"]
    },
    "core_contracts": ["authorization", "integration_catalog", "external_identity", "workflow_runs", "action_catalog"],
    "capabilities": [{
      "name": "integration-admin",
      "tabs": ["overview", "drift", "identities", "actions", "recent-runs", "dashboards", "datasources"]
    }]
  }
}
```

Commit.

---

## Task 6: nginx.conf + Dockerfile

Apply Plan 1.1 Task 5 verbatim. Smoke build + commit.

---

## Task 7: Taskfile.yml (NEW — grafana has none)

Apply Plan 1.1 Task 6 with substitutions:
- `SURFACE_NAME: slack` → `grafana`
- `surface-slack` → `surface-grafana`
- `integration-slack` → `integration-grafana`

Commit.

---

## Task 8: CI workflow

`integration-grafana` has existing `ci.yml` + `deploy.yml`. Append `build-surface` job to `ci.yml` per Plan 1.1 Task 7 with `surface-slack` → `surface-grafana` substitutions throughout.

Commit.

---

## Task 9: Push + observe

```bash
git push origin main
sleep 30
curl -sS "https://api.github.com/repos/dakasa-yggdrasil/integration-grafana/actions/runs?per_page=2" 2>/dev/null | head -100
```

Tag sync gate:
```bash
git commit --allow-empty -m "chore: Phase 1.4 complete — surface-grafana image pushed to GHCR"
```
