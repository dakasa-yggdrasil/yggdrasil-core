# Integration Surfaces — Phase 1.6: surface-aws Implementation Plan

> Use `superpowers:subagent-driven-development`. Checkbox steps.

**Goal:** Ship `surface-aws` inside `integration-aws`. Custom tabs ECR Images + Accounts via `on_surface_query` (list-ecr-images wraps existing, list-accounts NEW).

**Reference:** Plan 1.1 (slack), Plan 1.3 (github — similar HTTP listing pattern).

**Working dir:** `/Users/dakasa/projects/yggdrasil/integration-aws/`.

**Real patterns:**
- Adapter at `internal/adapter/spec.go` (60+ ops L42-88)
- Contract: `internal/protocol`
- Existing `list_ecr_images` — REUSE via internal dispatch
- HAS Taskfile + ci.yml + deploy.yml (extend)
- Uses AWS SDK Go v2

**Tabs:** overview, drift, actions, recent-runs, **ecr-images** (custom), **accounts** (custom). NO identities tab (AWS doesn't directly manage user identities via this adapter — Identity Center is a separate path).

Push direct to main. No co-author trailers.

---

## Task 1: Adapter `on_surface_query`

**Files:**
- Modify: `internal/adapter/spec.go`
- Create: `internal/adapter/surface_query.go`
- Create: `internal/adapter/surface_query_test.go`

- [ ] **Step 1: Grep AWS helpers**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-aws
grep -n "func listECRImages\|ecr.ListImages\|sts.ListAccounts\|organizations.ListAccounts" internal/adapter/*.go | head -10
```

- [ ] **Step 2: Failing test**

```go
package adapter

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/integration-aws/internal/protocol"
)

func TestSurfaceQuery_RejectsUnknownQuery(t *testing.T) {
	_, err := Execute(protocol.AdapterExecuteIntegrationRequest{
		Operation: OperationOnSurfaceQuery,
		Input:     map[string]any{"query_name": "list-mars"},
	})
	if err == nil || !strings.Contains(err.Error(), "list-mars") {
		t.Fatalf("expected unknown-query error, got %v", err)
	}
}
```

- [ ] **Step 3: Add constant + switch case**

```go
const OperationOnSurfaceQuery = "on_surface_query"
```

In Execute switch:

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(req)
```

- [ ] **Step 4: Implement surface_query.go**

```go
package adapter

import (
	"fmt"

	"github.com/dakasa-yggdrasil/integration-aws/internal/protocol"
)

func onSurfaceQuery(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := req.Input["query_name"].(string)
	params, _ := req.Input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	switch queryName {
	case "list-ecr-images":
		// Wrap the existing listECRImages handler. Pass through params (repository_name, region).
		inner := protocol.AdapterExecuteIntegrationRequest{
			Operation:   OperationListECRImages,
			Capability:  OperationListECRImages,
			Integration: req.Integration,
			Input:       params,
		}
		resp, err := listECRImages(inner)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-ecr-images: %w", err)
		}
		out, _ := resp.Output.(map[string]any)
		raw, _ := out["images"].([]any)
		items := make([]any, 0, len(raw))
		for _, i := range raw {
			img, _ := i.(map[string]any)
			items = append(items, map[string]any{
				"id":         fmt.Sprintf("%v", img["image_digest"]),
				"name":       img["image_tag"],
				"kind":       "ecr_image",
				"repository": img["repository_name"],
				"pushed_at":  img["pushed_at"],
			})
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	case "list-accounts":
		// New capability: list AWS accounts via Organizations.ListAccounts.
		// Build STS/Organizations client from the request's instance config and call.
		items, err := listOrganizationAccounts(req)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-accounts: %w", err)
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	default:
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}

// listOrganizationAccounts paginates Organizations.ListAccounts.
// Returns items in {id, name, kind="aws_account", status} shape.
// The agent must adapt this to whatever Organizations client constructor
// the existing adapter exposes — likely something like newOrganizationsClient(req).
func listOrganizationAccounts(req protocol.AdapterExecuteIntegrationRequest) ([]any, error) {
	// PLACEHOLDER — implementer to wire to existing AWS client builder.
	// Pattern is well-established in this adapter for other capabilities.
	// If integration-aws lacks an existing Organizations call:
	//   - import "github.com/aws/aws-sdk-go-v2/service/organizations"
	//   - reuse the AWS config loader (look at how listECRImages or similar
	//     constructs awsConfig from req.Integration.InstanceSpec.Credentials)
	//   - call client.ListAccounts(ctx, &organizations.ListAccountsInput{...})
	//   - loop with NextToken
	return nil, fmt.Errorf("list-accounts: not yet wired to Organizations client; implementer must adapt to adapter's AWS config builder")
}
```

NOTE: `listECRImages` function name + `OperationListECRImages` constant must match the actual names. Grep `internal/adapter/*.go` for `ListECRImages` (any case) and adapt. The list-accounts implementation requires the implementer to wire to whatever AWS SDK client constructor exists in this adapter — leave as placeholder fail until adapted; the test (rejects unknown query) still passes.

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/adapter/... -run SurfaceQuery
git add internal/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery — list-ecr-images (wrap) + list-accounts (Orgs)"
```

---

## Task 2-8: Standard scaffolding (see Plan 1.1 Tasks 2-7)

Substitutions:
- `surface-slack` → `surface-aws`
- `/s/slack/` → `/s/aws/`
- `integration-slack` → `integration-aws`
- color_token `brand.slack` → `brand.aws`
- title → "AWS"

Custom tabs:

`surface-ui/src/tabs/AWSECRImagesTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface ImageItem extends Record<string, unknown> {
  id: string;
  name?: string;
  repository?: string;
  pushed_at?: string;
}

export interface AWSECRImagesTabProps { instanceId: string; integrationType: string; }

export function AWSECRImagesTab({ instanceId }: AWSECRImagesTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: ImageItem[] }>(instanceId, "list-ecr-images");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhuma imagem ECR" />;
  return (
    <DataTable<ImageItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "repository", header: "Repo", accessor: (r) => r.repository ?? "—", sortable: true },
        { id: "name", header: "Tag", accessor: (r) => r.name ?? r.id },
        { id: "pushed_at", header: "Push", accessor: (r) => r.pushed_at ?? "—" }
      ]}
    />
  );
}
```

`surface-ui/src/tabs/AWSAccountsTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface AccountItem extends Record<string, unknown> {
  id: string;
  name?: string;
  status?: string;
}

export interface AWSAccountsTabProps { instanceId: string; integrationType: string; }

export function AWSAccountsTab({ instanceId }: AWSAccountsTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: AccountItem[] }>(instanceId, "list-accounts");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhuma conta encontrada" description="A capability list-accounts pode não estar configurada." />;
  return (
    <DataTable<AccountItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Conta", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "id", header: "ID", accessor: (r) => r.id },
        { id: "status", header: "Status", accessor: (r) => r.status ?? "—" }
      ]}
    />
  );
}
```

App.tsx (NO IdentitiesTab — AWS surface focuses on infra resources):

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { IntegrationAdminShell, OverviewTab, DriftTab, ActionsTab, RecentRunsTab } from "@dakasa-yggdrasil/surface-toolkit";
import { AWSECRImagesTab } from "./tabs/AWSECRImagesTab";
import { AWSAccountsTab } from "./tabs/AWSAccountsTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "ecr-images", label: "ECR", component: AWSECRImagesTab },
  { id: "accounts", label: "Accounts", component: AWSAccountsTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="aws" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="aws" tabs={TABS} basePath="/" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
```

surface.manifest.json (NO `external_identity` contract):

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-aws",
    "namespace": "global",
    "integration_type": "aws"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/aws",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-aws"
    },
    "display": {
      "title": "AWS",
      "subtitle": "ECR e contas",
      "icon": "aws",
      "color_token": "brand.aws",
      "appears_on": ["ops-integrations"]
    },
    "core_contracts": ["authorization", "integration_catalog", "workflow_runs", "action_catalog"],
    "capabilities": [{
      "name": "integration-admin",
      "tabs": ["overview", "drift", "actions", "recent-runs", "ecr-images", "accounts"]
    }]
  }
}
```

**Taskfile + CI:** integration-aws HAS Taskfile.yml + ci.yml + deploy.yml — EXTEND, don't recreate. Append surface tasks/jobs per Plan 1.1 Tasks 6-7.

---

## Task 9: Push + sync gate

```bash
git push origin main
sleep 30
git commit --allow-empty -m "chore: Phase 1.6 complete — surface-aws image pushed to GHCR"
```
