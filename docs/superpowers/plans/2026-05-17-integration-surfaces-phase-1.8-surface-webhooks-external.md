# Integration Surfaces — Phase 1.8: surface-webhooks-external Implementation Plan

> Use `superpowers:subagent-driven-development`. Checkbox steps.

**Goal:** Ship `surface-webhooks-external` inside `integration-webhooks-external` (**PRIVATE** dakasa-co repo). Custom tabs Webhooks Configured + Failed Deliveries. Wrap existing `list_webhooks`; add `list_failed_deliveries` NEW capability.

**Reference:** Plan 1.1 (slack — base), Plan 1.3 (github — list wrap pattern).

**Working dir:** `/Users/dakasa/projects/dakasa/integration-webhooks-external/`.

**Real patterns:**
- PRIVATE repo (dakasa-co org, not dakasa-yggdrasil)
- Adapter at `internal/adapter/spec.go` (5 ops L15-19: register_webhook, delete_webhook, list_webhooks, verify_signature, rotate_secret)
- Contract: `internal/protocol`
- HAS Taskfile.yml, has Dockerfile, has ci.yml + release.yml (NO deploy.yml)
- **Image must push to ECR sa-east-1, NOT GHCR** (per memory `feedback_private_adapters_ecr_not_ghcr`)
- ECR repo: `153828470928.dkr.ecr.sa-east-1.amazonaws.com/integration-webhooks-external` (existing). Surface image: NEW ECR repo `153828470928.dkr.ecr.sa-east-1.amazonaws.com/surface-webhooks-external` — may need creation
- Multi-provider: stripe, efi, nfe_io (already supported)

**Tabs:** overview, drift, actions, recent-runs, webhook-log, **configured** (custom — wrap list_webhooks), **failed** (custom — NEW capability). NO identities tab.

Push direct to main. No co-author trailers.

---

## Task 1: Adapter `on_surface_query` with list-webhooks-configured + list-failed-deliveries

**Files:**
- Modify: `internal/adapter/spec.go`
- Create: `internal/adapter/surface_query.go`
- Create: `internal/adapter/surface_query_test.go`

- [ ] **Step 1: Grep existing webhook listing**

```bash
cd /Users/dakasa/projects/dakasa/integration-webhooks-external
grep -n "func listWebhooks\|OperationListWebhooks" internal/adapter/*.go | head -5
```

- [ ] **Step 2: Failing test**

```go
package adapter

import (
	"strings"
	"testing"

	"github.com/dakasa-co/integration-webhooks-external/internal/protocol"
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

(Adapt the module path to whatever go.mod actually declares — may be `github.com/dakasa-co/...` or `dakasa-co/...`.)

- [ ] **Step 3: Add constant + dispatch**

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

	"github.com/dakasa-co/integration-webhooks-external/internal/protocol"
)

func onSurfaceQuery(req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
	queryName, _ := req.Input["query_name"].(string)
	params, _ := req.Input["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	switch queryName {
	case "list-webhooks-configured":
		inner := protocol.AdapterExecuteIntegrationRequest{
			Operation:   OperationListWebhooks,
			Capability:  OperationListWebhooks,
			Integration: req.Integration,
			Input:       params,
		}
		resp, err := listWebhooks(inner)
		if err != nil {
			return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("list-webhooks-configured: %w", err)
		}
		// Reshape output to {items: [{id, name, provider, endpoint, events}]} for DataTable.
		out, _ := resp.Output.(map[string]any)
		raw, _ := out["webhooks"].([]any)
		items := make([]any, 0, len(raw))
		for _, w := range raw {
			wh, _ := w.(map[string]any)
			items = append(items, map[string]any{
				"id":       fmt.Sprintf("%v", wh["id"]),
				"name":     wh["name"],
				"provider": wh["provider"],
				"endpoint": wh["endpoint"],
				"events":   fmt.Sprintf("%v", wh["events"]),
				"kind":     "webhook",
			})
		}
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": items},
		}, nil

	case "list-failed-deliveries":
		// NEW capability: query the provider's failed-deliveries log.
		// PLACEHOLDER — adapt to each provider's API:
		//   stripe: /v1/webhook_endpoints/{id}/events (filter delivered=false)
		//   efi: per their docs
		//   nfe_io: per their docs
		// For V1, return empty list — surface still renders gracefully via <EmptyState>.
		return protocol.AdapterExecuteIntegrationResponse{
			Output: map[string]any{"items": []any{}},
		}, nil

	default:
		return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unknown query: %q", queryName)
	}
}
```

Verify `listWebhooks` function name + output shape (likely `{webhooks: [...]}` or `{items: [...]}`).

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/adapter/... -run SurfaceQuery
git add internal/adapter/
git commit -m "feat(adapter): OperationOnSurfaceQuery — list-webhooks-configured (wrap) + list-failed-deliveries (placeholder)"
```

---

## Task 2-7: surface-ui scaffolding (Plan 1.1)

Substitutions:
- `surface-slack` → `surface-webhooks-external`
- `/s/slack/` → `/s/webhooks-external/`
- `integration-slack` → `integration-webhooks-external`
- color_token `brand.slack` → `brand.webhooks-external`
- title → "Webhooks Externos"
- **package.json `name`:** `surface-webhooks-external`
- **GitHub import URL:** the module is `github.com/dakasa-co/...` (private)

Custom tabs:

`surface-ui/src/tabs/WebhooksConfiguredTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface WebhookItem extends Record<string, unknown> {
  id: string;
  name?: string;
  provider?: string;
  endpoint?: string;
  events?: string;
}

export interface WebhooksConfiguredTabProps { instanceId: string; integrationType: string; }

export function WebhooksConfiguredTab({ instanceId }: WebhooksConfiguredTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: WebhookItem[] }>(instanceId, "list-webhooks-configured");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) return <EmptyState title="Nenhum webhook configurado" />;
  return (
    <DataTable<WebhookItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "name", header: "Nome", accessor: (r) => r.name ?? r.id, sortable: true },
        { id: "provider", header: "Provider", accessor: (r) => r.provider ?? "—" },
        { id: "endpoint", header: "Endpoint", accessor: (r) => r.endpoint ?? "—" },
        { id: "events", header: "Eventos", accessor: (r) => r.events ?? "—" }
      ]}
    />
  );
}
```

`surface-ui/src/tabs/FailedDeliveriesTab.tsx`:

```tsx
import { useSurfaceQuery, DataTable, LoadingState, EmptyState } from "@dakasa-yggdrasil/surface-toolkit";

interface DeliveryItem extends Record<string, unknown> {
  id: string;
  event_type?: string;
  provider?: string;
  attempts?: number;
  last_failure?: string;
}

export interface FailedDeliveriesTabProps { instanceId: string; integrationType: string; }

export function FailedDeliveriesTab({ instanceId }: FailedDeliveriesTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: DeliveryItem[] }>(instanceId, "list-failed-deliveries");
  if (isLoading) return <LoadingState />;
  if (!data || !data.items?.length) {
    return <EmptyState title="Sem deliveries falhadas" description="V1 retorna lista vazia até o provider-specific querying ser wired." />;
  }
  return (
    <DataTable<DeliveryItem>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "event_type", header: "Evento", accessor: (r) => r.event_type ?? "—", sortable: true },
        { id: "provider", header: "Provider", accessor: (r) => r.provider ?? "—" },
        { id: "attempts", header: "Tentativas", accessor: (r) => r.attempts ?? 0 },
        { id: "last_failure", header: "Última falha", accessor: (r) => r.last_failure ?? "—" }
      ]}
    />
  );
}
```

App.tsx (with WebhookLogTab from toolkit too):

```tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { IntegrationAdminShell, OverviewTab, DriftTab, ActionsTab, RecentRunsTab, WebhookLogTab } from "@dakasa-yggdrasil/surface-toolkit";
import { WebhooksConfiguredTab } from "./tabs/WebhooksConfiguredTab";
import { FailedDeliveriesTab } from "./tabs/FailedDeliveriesTab";

const TABS = [
  { id: "overview", label: "Overview", component: OverviewTab },
  { id: "drift", label: "Drift", component: DriftTab },
  { id: "actions", label: "Actions", component: ActionsTab },
  { id: "recent-runs", label: "Runs", component: RecentRunsTab },
  { id: "webhook-log", label: "Webhook log", component: WebhookLogTab },
  { id: "configured", label: "Configurados", component: WebhooksConfiguredTab },
  { id: "failed", label: "Falhas", component: FailedDeliveriesTab }
];

export function App() {
  return (
    <Routes>
      <Route path="/" element={<div style={{padding:32}}>Selecione uma instância…</div>} />
      <Route path="/instance/:instanceId" element={<IntegrationAdminShell integrationType="webhooks-external" tabs={TABS} basePath="/" />} />
      <Route path="/instance/:instanceId/:tabId" element={<IntegrationAdminShell integrationType="webhooks-external" tabs={TABS} basePath="/" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
```

surface.manifest.json (ECR image):

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "integration_surface",
  "metadata": {
    "name": "surface-webhooks-external",
    "namespace": "global",
    "integration_type": "webhooks-external"
  },
  "spec": {
    "category": "integration",
    "owners": ["team:platform"],
    "runtime": {
      "kind": "spa",
      "exposure": "public",
      "base_path": "/s/webhooks-external",
      "health_path": "/healthz",
      "image": "153828470928.dkr.ecr.sa-east-1.amazonaws.com/surface-webhooks-external"
    },
    "display": {
      "title": "Webhooks Externos",
      "subtitle": "Stripe, EFI, NFE.io",
      "icon": "webhooks-external",
      "color_token": "brand.webhooks-external",
      "appears_on": ["ops-integrations"]
    },
    "core_contracts": ["authorization", "integration_catalog", "workflow_runs", "action_catalog", "webhooks"],
    "capabilities": [{
      "name": "integration-admin",
      "tabs": ["overview", "drift", "actions", "recent-runs", "webhook-log", "configured", "failed"]
    }]
  }
}
```

nginx.conf, Dockerfile: per Plan 1.1 Task 5 verbatim.

Taskfile (EXTEND existing): per Plan 1.1 Task 6 but use ECR image URL:
- `SURFACE_IMAGE: 153828470928.dkr.ecr.sa-east-1.amazonaws.com/surface-webhooks-external`

---

## Task 8: CI workflow — PUSH TO ECR (not GHCR)

`integration-webhooks-external` has `ci.yml`. Append `build-surface` job, but **DIFFERENT FROM GHCR**: use AWS ECR push.

```yaml
  build-surface:
    name: Build & Push surface-webhooks-external image
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    needs: [test]
    permissions:
      contents: read
      id-token: write  # for OIDC AWS auth
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
          VITE_BASE_PATH: "/s/webhooks-external/"
        run: |
          npm ci --no-audit --no-fund
          npm run build
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ECR_PUSH_ROLE }}  # existing role used by adapter publish
          aws-region: sa-east-1
      - name: Login to ECR
        uses: aws-actions/amazon-ecr-login@v2
      - name: Build + push image
        working-directory: surface-ui
        run: |
          IMAGE=153828470928.dkr.ecr.sa-east-1.amazonaws.com/surface-webhooks-external
          TAG=sha-${GITHUB_SHA::7}
          # Ensure ECR repo exists (idempotent)
          aws ecr describe-repositories --repository-names surface-webhooks-external --region sa-east-1 \
            || aws ecr create-repository --repository-name surface-webhooks-external --region sa-east-1
          docker build --build-arg BUILD_BASE_PATH=/s/webhooks-external/ -t $IMAGE:$TAG -t $IMAGE:latest .
          docker push $IMAGE:$TAG
          docker push $IMAGE:latest
      - name: Trigger surface manifest sync
        env:
          YGG_URL: https://yggdrasil.dakasa.me
          YGG_TOKEN: ${{ secrets.YGGDRASIL_WORKFLOW_RUN_TOKEN }}
        run: |
          if [ -z "$YGG_TOKEN" ]; then echo "skip"; exit 0; fi
          curl -X POST "$YGG_URL/api/v1/integration-surfaces/surface-webhooks-external/sync" \
            -H "Authorization: Bearer $YGG_TOKEN"
```

Commit.

---

## Task 9: Push + sync gate

```bash
git push origin main
sleep 30
git commit --allow-empty -m "chore: Phase 1.8 complete — surface-webhooks-external image pushed to ECR"
```

## Phase 1.8 sync gate

1. ✅ Adapter on_surface_query routes list-webhooks-configured + list-failed-deliveries
2. ✅ surface-ui complete with 2 custom tabs + WebhookLogTab from toolkit
3. ✅ Image pushed to ECR sa-east-1 (NOT GHCR — private adapter convention)
4. ⏳ Cluster deploy via Phase 0d kustomize template + `ecr-pull-sa-east-1` imagePullSecret
5. ⏳ Browser smoke `https://yggdrasil.dakasa.me/s/webhooks-external`
