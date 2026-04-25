# Tutorial 5 — Multi-tenancy

**Time:** ~30 minutes.
**Outcome:** Yggdrasil's manifests are organised by tenant. Each tenant has a slug, owners, and informational quotas.

> **v2.3.0 status:** the `tenant` manifest kind is shipped and validated. RBAC enforcement is **opt-in** via env var `YGGDRASIL_TENANCY_ENFORCED=true`. Adopters running with `unset` or `false` (default in v2.3) get the schema and audit-log integration without authorization gates. Full enforcement defaults to on in **v3.0**.

## Why opt-in

The full multi-tenant promise is "tenant A cannot see, modify, or run anything tenant B owns". Reaching that promise requires:

- Database-level filtering on every list endpoint (`/api/v1/manifests`, `/api/v1/workflow-runs`, `/api/v1/audit`)
- Authorization checks at write time (POST manifest must include caller's tenant; reject mismatched tenant)
- Tenant-aware secret namespacing (`secret://yggdrasil/<tenant>/<name>`)
- Quota tracking with hard ceilings

In v2.3.0 we ship the data shape and the opt-in flag so adopters can adopt the convention before flipping the enforcement switch. v3.0 makes enforcement default-on; adopters who don't migrate will still see the system function (single implicit `default` tenant) but lose isolation guarantees.

## Step 1 — Apply your tenant manifest

```json
{
  "name": "acme",
  "namespace": "global",
  "spec": {
    "slug": "acme",
    "display_name": "Acme Corp",
    "description": "Acme's tenancy on the Yggdrasil platform",
    "owners": ["team:acme-platform", "user:alice"],
    "billing_ref": "stripe:cust_acme_001",
    "quotas": {
      "max_projects": 50,
      "max_manifests": 5000,
      "max_workflow_runs_per_day": 10000,
      "max_secrets": 200,
      "max_ephemeral_environments": 30,
      "max_integration_instances": 50
    },
    "metadata": {
      "tier": "enterprise",
      "region_pref": "sa-east-1"
    }
  }
}
```

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=tenant" \
  -d @tenant-acme.json | jq '.manifest.metadata.name'
```

Slug rules:

- 2-63 characters
- Lowercase alphanumeric or hyphens
- First and last character alphanumeric (no leading or trailing hyphen)

Owner format: `user:<id>`, `team:<name>`, or `service:<name>`. Mismatched format returns `400`.

## Step 2 — Annotate other manifests with `metadata.tenant`

```json
{
  "name": "deploy-acme-widget",
  "namespace": "default",
  "spec": { /* workflow */ },
  "metadata": {"tenant": "acme"}
}
```

`metadata.tenant` is informational in v2.3 — Yggdrasil stores and audits it but does not gate writes against it. Tools that respect tenancy (the surface-console, future `yggdrasil` CLI flag `--tenant`) read this field to scope listings.

## Step 3 — Enable enforcement (optional in v2.3)

```bash
kubectl -n yggdrasil set env statefulset/yggdrasil YGGDRASIL_TENANCY_ENFORCED=true
kubectl -n yggdrasil rollout status statefulset/yggdrasil --timeout=60s
```

When `YGGDRASIL_TENANCY_ENFORCED=true`:

- `POST /api/v1/manifests` requires `metadata.tenant` and rejects manifests whose tenant the caller cannot administer (per the tenant's `owners`).
- List endpoints filter to manifests whose `metadata.tenant` matches one of the caller's authorised tenants.
- Quota counts are enforced at write time. Adopters who exceed `max_manifests` or `max_workflow_runs_per_day` get `429 Too Many Requests`.

When `YGGDRASIL_TENANCY_ENFORCED` is unset or `false` (default in v2.3):

- All endpoints behave as v2.2 (no tenant filtering).
- Tenant manifests still validate and persist.
- `metadata.tenant` annotations are recorded but ignored at gate time.

This default lets adopters introduce tenants over weeks rather than days; flip the env var when every manifest carries the right `metadata.tenant`.

## Step 4 — Verify

```bash
curl -sf "$YGG_URL/api/v1/manifests?kind=tenant" | jq '.[].spec.slug'
```

Expected:

```
"acme"
```

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `tenant slug must match ^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` | Slug has uppercase, leading/trailing hyphen, or single character | Adjust to a 2-63 lowercase alphanumeric+hyphen string |
| `tenant owners[N] must be 'user:<id>', 'team:<name>' or 'service:<name>'` | Owner missing prefix or unknown prefix | Use one of the three accepted prefixes |
| `tenant quotas.X must be >= 0 (use 0 for no cap)` | Negative quota | Use 0 for "no cap"; positive integer for an explicit ceiling |

## What you accomplished

- A first-class tenant manifest organising your Yggdrasil deployment.
- A path from "single implicit tenant" (v2.2) to "fully isolated tenants" (v3) without a flag day. Adopters can introduce tenants in stages.

## Next

- Annotate every existing manifest with `metadata.tenant`. Recommended order: integration_instance → workflow → repository_binding → ephemeral_environment.
- When all manifests are annotated, set `YGGDRASIL_TENANCY_ENFORCED=true` to flip enforcement on.
- Watch for v2.4 (Phase 4 observability) to surface per-tenant metrics and audit trails.
