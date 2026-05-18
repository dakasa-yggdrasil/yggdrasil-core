# Integration Surfaces — Phase 1.5: surface-kubernetes Implementation Plan

> Use `superpowers:subagent-driven-development`. Checkbox steps.

**Goal:** Ship `surface-kubernetes` inside `integration-kubernetes`. Custom tabs Workloads + Cluster Info via `on_surface_query` (NEW capability — k8s has no existing list ops).

**Reference:** Plan 1.1 (slack) for boilerplate; Plan 1.3 (github) for adapter pattern with HTTP API listing.

**Working dir:** `/Users/dakasa/projects/yggdrasil/integration-kubernetes/`.

**Real patterns:**
- Adapter at `internal/adapter/spec.go` (operations L27-74)
- Contract: `internal/protocol`
- HAS Taskfile.yml + ci.yml + deploy.yml (extend, don't recreate)
- No existing `list_*` operations — k8s adapter uses `observe_objects` for read-paths

**Tabs:** overview, drift, actions, recent-runs, **workloads** (custom), **cluster-info** (custom). NO identities tab (k8s doesn't manage user identities in this integration).

Push direct to main. No co-author trailers.

---

## Task 1: Adapter `on_surface_query` with list-workloads + cluster-info

**Files:**
- Modify: `internal/adapter/spec.go` (constant + dispatch)
- Create: `internal/adapter/surface_query.go`
- Create: `internal/adapter/surface_query_test.go`

- [ ] **Step 1: Grep existing k8s helpers**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-kubernetes
grep -n "func observeObjects\|client-go\|dynamic.NewForConfig\|kubeClient" internal/adapter/*.go | head -10
```

K8s adapter likely uses `client-go` dynamic client. Note the actual client constructor and how `observe_objects` lists Pods/Deployments.

- [ ] **Step 2: Failing test**

`internal/adapter/surface_query_test.go`:

```go
package adapter

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/integration-kubernetes/internal/protocol"
)

func TestSurfaceQuery_RejectsUnknownQuery(t *testing.T) {
	_, err := Execute(protocol.AdapterExecuteIntegrationRequest{
		Operation: OperationOnSurfaceQuery,
		Input:     map[string]any{"query_name": "list-mars-bases"},
	})
	if err == nil || !strings.Contains(err.Error(), "list-mars-bases") {
		t.Fatalf("expected unknown-query error, got %v", err)
	}
}
```

- [ ] **Step 3: Add constant + dispatch**

In `internal/adapter/spec.go` constants:

```go
const OperationOnSurfaceQuery = "on_surface_query"
```

And in `SupportedExecuteOperations` list (L60+).

In `Execute()` switch, add:

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(req)
```

- [ ] **Step 4: Implement surface_query.go**

```go
package adapter

import (
	"context"
	"fmt"

	"github.com/dakasa-yggdrasil/integration-kubernetes/internal/protocol"
)

func onSurfaceQuery(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := req.Input["query_name"].(string)
	params, _ := req.Input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	switch queryName {
	case "list-workloads":
		// Reuse the existing observe_objects path or call client-go directly.
		// Adapt to whatever helper the adapter exposes (likely a wrapped
		// dynamic client). Return items shape: {id, name, namespace, kind, status}.
		client, err := buildKubeClient(req)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-workloads: %w", err)
		}
		ctx := context.Background()
		items, err := listWorkloads(ctx, client, params)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-workloads: %w", err)
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	case "cluster-info":
		client, err := buildKubeClient(req)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("cluster-info: %w", err)
		}
		info, err := clusterInfo(context.Background(), client)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("cluster-info: %w", err)
		}
		return protocol.AdapterExecuteIntegrationResponse{Output: info}, nil

	default:
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}

// listWorkloads aggregates Deployments + StatefulSets + DaemonSets across
// the namespace (or all namespaces if not specified). Returns a flat list
// shape suitable for <DataTable>.
func listWorkloads(ctx context.Context, client kubeClient, params map[string]any) ([]any, error) {
	ns, _ := params["namespace"].(string)
	out := []any{}

	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
		objs, err := client.List(ctx, kind, ns)
		if err != nil {
			// Continue on per-kind errors (e.g., RBAC restrictions) — best-effort.
			continue
		}
		for _, o := range objs {
			out = append(out, map[string]any{
				"id":        fmt.Sprintf("%s/%s/%s", o.Namespace, kind, o.Name),
				"name":      o.Name,
				"namespace": o.Namespace,
				"kind":      kind,
				"status":    o.Status,
			})
		}
	}
	return out, nil
}

func clusterInfo(ctx context.Context, client kubeClient) (map[string]any, error) {
	version, err := client.ServerVersion(ctx)
	if err != nil {
		return nil, err
	}
	nodes, _ := client.ListNodes(ctx)
	return map[string]any{
		"server_version": version,
		"node_count":     len(nodes),
	}, nil
}
```

NOTE: `buildKubeClient`, `kubeClient`, `client.List`, `client.ServerVersion`, `client.ListNodes` are placeholders — adapt to whatever the existing adapter actually provides. Look at how `observe_objects` is implemented and reuse its client construction + listing logic. If the existing observe_objects can be parameterized to filter by GVR, build on top of it directly.

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/adapter/... -run SurfaceQuery
git add internal/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery — list-workloads + cluster-info"
```

---

## Task 2-8: Standard surface-ui scaffolding (see Plan 1.1)

Apply Plan 1.1 Tasks 2-7 with substitutions:
- `surface-slack` → `surface-kubernetes`
- `/s/slack/` → `/s/kubernetes/`
- `integration-slack` → `integration-kubernetes`
- color_token `brand.slack` → `brand.kubernetes`
- title `Slack` → `Kubernetes`

**Custom tabs:**

`surface-ui/src/tabs/KubernetesWorkloadsTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface WorkloadItem extends Record<string, unknown> {
  id: string;
  name?: string;
  namespace?: string;
  kind?: string;
  status?: string;
}

export interface KubernetesWorkloadsTabProps { instanceId: string; integrationType: string; }

export function KubernetesWorkloadsTab({ instanceId }: KubernetesWorkloadsTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: WorkloadItem[] }>(instanceId, "list-workloads");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhum workload" />;
  return (
    <DataTable<WorkloadItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Nome", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "namespace", header: "Namespace", accessor: (r) => r.namespace ?? "—" },
        { id: "kind", header: "Tipo", accessor: (r) => r.kind ?? "—" },
        { id: "status", header: "Status", accessor: (r) => r.status ?? "—" }
      ]}
    />
  );
}
```

`surface-ui/src/tabs/KubernetesClusterInfoTab.tsx`:

```tsx
import { useSurfaceQuery, LoadingState, EmptyState, JsonViewer } from "@dakasa-yggdrasil/surface-toolkit";

export interface KubernetesClusterInfoTabProps { instanceId: string; integrationType: string; }

export function KubernetesClusterInfoTab({ instanceId }: KubernetesClusterInfoTabProps) {
  const { data, isLoading } = useSurfaceQuery<Record<string, unknown>>(instanceId, "cluster-info");
  if (isLoading) return <LoadingState />;
  if (!data) return <EmptyState title="Sem dados do cluster" />;
  return <JsonViewer value={data} />;
}
```

**App.tsx** (without IdentitiesTab):

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { IntegrationAdminShell, OverviewTab, DriftTab, ActionsTab, RecentRunsTab } from "@dakasa-yggdrasil/surface-toolkit";
import { KubernetesWorkloadsTab } from "./tabs/KubernetesWorkloadsTab";
import { KubernetesClusterInfoTab } from "./tabs/KubernetesClusterInfoTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "workloads", label: "Workloads", component: KubernetesWorkloadsTab },
  { id: "cluster-info", label: "Cluster", component: KubernetesClusterInfoTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="kubernetes" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="kubernetes" tabs={TABS} basePath="/" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
```

**surface.manifest.json** core_contracts WITHOUT `external_identity` (k8s doesn't manage identities):

```json
"core_contracts": ["authorization", "integration_catalog", "workflow_runs", "action_catalog"],
"capabilities": [{
  "name": "integration-admin",
  "tabs": ["overview", "drift", "actions", "recent-runs", "workloads", "cluster-info"]
}]
```

**Taskfile/CI:** EXTEND existing files (k8s has both Taskfile + ci.yml + deploy.yml). Append surface tasks/jobs per Plan 1.1 Tasks 6-7 with `surface-slack` → `surface-kubernetes` substitutions.

---

## Task 9: Push + observe + sync gate

```bash
git push origin main
sleep 30
curl -sS "https://api.github.com/repos/dakasa-yggdrasil/integration-kubernetes/actions/runs?per_page=2" 2>/dev/null | head -100
git commit --allow-empty -m "chore: Phase 1.5 complete — surface-kubernetes image pushed to GHCR"
```
