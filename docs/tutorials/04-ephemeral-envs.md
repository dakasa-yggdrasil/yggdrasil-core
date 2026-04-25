# Tutorial 4 — Spin Up Ephemeral Environments per Pull Request

**Time:** ~30 minutes.
**Outcome:** every pull request gets a dedicated namespace with the full stack deployed and a cost projection. Hard TTL via `auto_destroy` keeps environment count bounded.

## Assumed state

- Quickstart complete; `YGG_URL=http://localhost:9080`.
- You have two workflows ready: `spin-up-stack` and `tear-down-stack`. (Worked example below.)
- Tutorial 1 (webhook CD) optional — useful if you want PR webhooks to trigger ephemeral envs automatically.

## Step 1 — Define the create and destroy workflows

`spin-up-stack` creates a namespace, applies a kustomize overlay, and seeds a database. `tear-down-stack` deletes the namespace. Both are normal Yggdrasil workflows; no special hooks.

(See the [features/workflows.md](../features/workflows.md) reference for full workflow shape.)

## Step 2 — Apply the ephemeral_environment manifest

```json
{
  "name": "pr-1234",
  "namespace": "project-acme",
  "description": "Ephemeral env for PR #1234 — branch `feature/billing-rewrite`",
  "spec": {
    "create_workflow": {
      "workflow_ref": {"namespace": "project-acme", "name": "spin-up-stack"},
      "inputs": {"branch": "feature/billing-rewrite", "pr_number": "1234"}
    },
    "destroy_workflow": {
      "workflow_ref": {"namespace": "project-acme", "name": "tear-down-stack"},
      "inputs": {"namespace": "pr-1234"}
    },
    "ttl_seconds": 28800,
    "auto_destroy": true,
    "cost_projection": {
      "cpu_hours": 0.5,
      "memory_gb_hours": 8,
      "estimated_cost": 0.42,
      "currency": "USD"
    },
    "metadata": {
      "pr_number": "1234",
      "branch": "feature/billing-rewrite",
      "owner": "team:billing"
    }
  }
}
```

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=ephemeral_environment" \
  -d @pr-1234.json | jq '.manifest.metadata.name'
```

Yggdrasil persists the manifest. Adopters drive the actual create call by dispatching `create_workflow` themselves (in v2.2.0; native auto-create on apply ships in v2.2.x).

## Step 3 — Dispatch the create_workflow

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/workflow-runs" \
  -d '{
    "workflow": {"namespace": "project-acme", "name": "spin-up-stack"},
    "inputs": {"branch": "feature/billing-rewrite", "pr_number": "1234"}
  }' | jq '.status, [.steps[] | .id + ":" + .status]'
```

After the run completes, your PR namespace `pr-1234` is live with the stack.

## Step 4 — Inspect the cost projection

```bash
curl -sf "$YGG_URL/api/v1/manifests?kind=ephemeral_environment&namespace=project-acme&name=pr-1234" \
  | jq '.[0].spec.cost_projection'
```

The projection is informational; reconcile against actual costs in your billing system. v2.2 projects via fixed inputs declared in the manifest; v2.3 (Phase 3 multi-tenancy) introduces per-project budgets.

## Step 5 — Auto-destroy after TTL (v2.2.x reaper)

In v2.2.0 the reaper is **not** yet enabled. Operators run the destroy workflow manually when the TTL expires:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/workflow-runs" \
  -d '{
    "workflow": {"namespace": "project-acme", "name": "tear-down-stack"},
    "inputs": {"namespace": "pr-1234"}
  }'
```

The auto-destroy reaper goroutine ships in **v2.2.x** (next patch). Behaviour: a server-side ticker (60s default) queries `manifests` for active `ephemeral_environment` rows where `created_at + ttl_seconds < now()` AND `auto_destroy = true`, dispatches each `destroy_workflow`, and marks the manifest with `metadata.yggdrasil.io/destroyed = true` so the same env is not destroyed twice.

Until then, schedule a cron / GitHub Action that does the equivalent query and POST.

## Step 6 — Wire to PR events (optional)

Create a `repository_binding` whose `deploy.workflow_ref` points at a workflow that POSTs the ephemeral_environment manifest plus dispatches `create_workflow`. The webhook handler dispatches the workflow on every push; that workflow does the manifest POST and create dispatch on its own. This keeps the webhook surface minimal — Yggdrasil receives the event, adopter logic decides what shape of work to dispatch.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `ephemeral_environment ttl_seconds must be 0 or >= 60` | TTL below 60 seconds (sub-minute is reap-thrash territory) | Use ≥ 60 seconds, or 0 to disable TTL |
| `ephemeral_environment auto_destroy requires destroy_workflow` | `auto_destroy: true` without a `destroy_workflow` block | Provide both, or set `auto_destroy: false` |
| Cost projection shows `null` after apply | `cost_projection` block was omitted | Add the block; it is informational and entirely optional |

## What you accomplished

- One declarative source of truth per PR environment, including TTL and cost.
- Reusable create/destroy workflows. The same `ephemeral_environment` shape works for nightly load-test envs, vendor demo envs, and per-developer playgrounds.

## Next

- Wait for v2.2.x to enable the auto-destroy reaper (out of the box) — in the meantime, schedule destroy externally.
- Combine with multi-tenancy (v2.3 / Phase 3) to scope ephemeral envs to a project and enforce per-project quotas.
