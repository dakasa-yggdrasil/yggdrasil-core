# Integration Surfaces — Phase 1.7: surface-secrets-management Implementation Plan

> Use `superpowers:subagent-driven-development`. Checkbox steps.

**Goal:** Ship `surface-secrets-management` inside `integration-secrets-management`. Custom tab Secrets (lista de secrets por provider). NEW `on_surface_query` capability.

**Reference:** Plan 1.1 (slack), Plan 1.4 (grafana — `family/contract` pattern).

**Working dir:** `/Users/dakasa/projects/yggdrasil/integration-secrets-management/`.

**Real patterns:**
- Multi-provider: `providers/aws/adapter/spec.go`, `providers/gcp/adapter/spec.go` (and possibly more)
- Contract: `family/contract`
- Each provider has own `Execute()` — surface_query needs to be added to EACH provider
- No Taskfile, only `release.yml` workflow (NO ci.yml — Plan adds one)

**Tabs:** overview, drift, actions, recent-runs, **secrets** (custom). NO identities tab.

**V1 simplification:** the surface assumes each `integration-instance` is bound to a SINGLE provider (configured at instance creation). So the surface doesn't need to multiplex providers in the UI — it just calls `list-secrets` and the adapter dispatches to whichever provider this instance uses.

Push direct to main. No co-author trailers.

---

## Task 1: Add `on_surface_query` to EACH provider adapter

**Files (per provider):**
- Modify: `providers/aws/adapter/spec.go` (constant + dispatch)
- Create: `providers/aws/adapter/surface_query.go`
- Create: `providers/aws/adapter/surface_query_test.go`
- Same for `providers/gcp/` (and any other provider directories — grep `providers/`)

- [ ] **Step 1: Discover all providers**

```bash
cd /Users/dakasa/projects/yggdrasil/integration-secrets-management
ls providers/
```

For each provider (likely `aws/`, `gcp/`, possibly `azure/`):

- [ ] **Step 2: Add constant + dispatch in each provider's spec.go**

```go
const OperationOnSurfaceQuery = "on_surface_query"
```

Switch case:

```go
case OperationOnSurfaceQuery:
    return onSurfaceQuery(ctx, client, input)
```

- [ ] **Step 3: Failing test (one per provider — keep them simple)**

`providers/aws/adapter/surface_query_test.go`:

```go
package adapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/integration-secrets-management/family/contract"
)

func TestSurfaceQuery_RejectsUnknownQuery(t *testing.T) {
	_, err := Execute(contract.AdapterExecuteIntegrationRequest{
		Operation: OperationOnSurfaceQuery,
		Input:     map[string]any{"query_name": "list-mars"},
	})
	if err == nil || !strings.Contains(err.Error(), "list-mars") {
		t.Fatalf("expected unknown-query error, got %v", err)
	}
}
```

(Adapt to whatever `Execute` signature the AWS provider uses — may be `Execute(ctx, req)` instead of `Execute(req)`.)

- [ ] **Step 4: Implement surface_query.go (per provider)**

`providers/aws/adapter/surface_query.go`:

```go
package adapter

import (
	"context"
	"fmt"

	"github.com/dakasa-yggdrasil/integration-secrets-management/family/contract"
)

func onSurfaceQuery(ctx context.Context, client awsClient, input map[string]any) (contract.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := input["query_name"].(string)
	params, _ := input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	switch queryName {
	case "list-secrets":
		items, err := listSecrets(ctx, client, params)
		if err != nil {
			return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-secrets: %w", err)
		}
		return contract.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil
	default:
		return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}

// listSecrets paginates Secrets Manager ListSecrets and returns
// {items: [{id (ARN), name, kind="secret", last_rotated}]}.
// IMPLEMENTER: wire to the existing AWS SDK client construction pattern.
// The describe_secret capability already constructs a Secrets Manager
// client — copy that pattern.
func listSecrets(ctx context.Context, client awsClient, params map[string]any) ([]any, error) {
	// PLACEHOLDER — adapt to existing client wiring.
	// Likely: client.secretsManager.ListSecrets(ctx, &secretsmanager.ListSecretsInput{}) with NextToken loop.
	return nil, fmt.Errorf("list-secrets: implementer must wire to AWS Secrets Manager ListSecrets via existing client builder")
}
```

`providers/gcp/adapter/surface_query.go` (analogous, using GCP Secret Manager SDK):

```go
package adapter

import (
	"context"
	"fmt"

	"github.com/dakasa-yggdrasil/integration-secrets-management/family/contract"
)

func onSurfaceQuery(ctx context.Context, client gcpClient, input map[string]any) (contract.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := input["query_name"].(string)
	switch queryName {
	case "list-secrets":
		// PLACEHOLDER — wire to gcpsm.ListSecrets via existing client builder.
		return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-secrets: implementer wire to GCP Secret Manager ListSecrets")
	default:
		return contract.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}
```

Verify each provider's actual client type name and adapt. The reject-unknown test works regardless of placeholder wiring.

- [ ] **Step 5: Run + commit**

```bash
go test ./providers/... -run SurfaceQuery
git add providers/
git commit -m "feat(adapter): OperationOnSurfaceQuery in aws + gcp providers — list-secrets (placeholder wiring)"
```

---

## Task 2-8: Standard surface-ui scaffolding (Plan 1.1)

Substitutions:
- `surface-slack` → `surface-secrets-management`
- `/s/slack/` → `/s/secrets-management/`
- `integration-slack` → `integration-secrets-management`
- color_token `brand.slack` → `brand.secrets-management`
- title → "Secrets Management"

Custom tab:

`surface-ui/src/tabs/SecretsListTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface SecretItem extends Record<string, unknown> {
  id: string;
  name?: string;
  last_rotated?: string;
}

export interface SecretsListTabProps { instanceId: string; integrationType: string; }

export function SecretsListTab({ instanceId }: SecretsListTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: SecretItem[] }>(instanceId, "list-secrets");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) {
    return <EmptyState title="Nenhum secret" description="A capability list-secrets pode ainda não estar wired no provider." />;
  }
  return (
    <DataTable<SecretItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Secret", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "id", header: "ARN/ID", accessor: (r) => r.id },
        { id: "last_rotated", header: "Última rotação", accessor: (r) => r.last_rotated ?? "—" }
      ]}
    />
  );
}
```

App.tsx:

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { IntegrationAdminShell, OverviewTab, DriftTab, ActionsTab, RecentRunsTab } from "@dakasa-yggdrasil/surface-toolkit";
import { SecretsListTab } from "./tabs/SecretsListTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "secrets", label: "Secrets", component: SecretsListTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="secrets-management" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="secrets-management" tabs={TABS} basePath="/" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
```

surface.manifest.json:

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-secrets-management",
    "namespace": "global",
    "integration_type": "secrets-management"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/secrets-management",
      "health_path": "/healthz",
      "image": "ghcr.io/dakasa-yggdrasil/surface-secrets-management"
    },
    "display": {
      "title": "Secrets Management",
      "subtitle": "Secrets em AWS e GCP",
      "icon": "secrets-management",
      "color_token": "brand.secrets-management",
      "appears_on": ["ops-integrations"]
    },
    "core_contracts": ["authorization", "integration_catalog", "workflow_runs", "action_catalog"],
    "capabilities": [{
      "name": "integration-admin",
      "tabs": ["overview", "drift", "actions", "recent-runs", "secrets"]
    }]
  }
}
```

**Taskfile + CI:** secrets-management has NO Taskfile + NO ci.yml (only release.yml). Plan CREATES both:
- Root `Taskfile.yml` per Plan 1.1 Task 6 with substitutions
- `.github/workflows/ci.yml` per Plan 1.1 Task 7 (full file, since none exists) — drop the `needs: [test]` if no existing test job, or add `test` job alongside

---

## Task 9: Push + sync gate

```bash
git push origin main
sleep 30
git commit --allow-empty -m "chore: Phase 1.7 complete — surface-secrets-management image pushed to GHCR"
```
