# Tutorial 1 — Wire your first service to Yggdrasil CD

**Time:** ~45 minutes.
**Outcome:** every push to `main` of one of your repositories triggers a Yggdrasil workflow that renders the kustomize overlay and applies it to your cluster.

## Assumed state

- The [quickstart](../quickstart.md) is complete. `YGG_URL=http://localhost:9080`. `integration-kubernetes-adapter` is healthy.
- You have a service repository (call it `acme/widget`) with a kustomize overlay at `deploy/overlays/dev/`. The overlay must produce a valid `kubectl apply -f -` payload.
- You have a public Yggdrasil URL the GitHub webhook can reach. For local development we will simulate the webhook with `curl`.

## Step 1 — Apply a workflow that deploys via kustomize

The workflow renders the source and applies it. Save as `deploy.json`:

```json
{
  "name": "deploy-acme-widget",
  "namespace": "default",
  "description": "Render and apply the dev overlay of acme/widget",
  "spec": {
    "trigger": {"mode": "manual"},
    "input_schema": {
      "required": ["git_url", "revision"],
      "properties": {
        "git_url": {"type": "string"},
        "revision": {"type": "string"},
        "path": {"type": "string", "default": "deploy/overlays/dev"},
        "namespace": {"type": "string", "default": "acme-dev"}
      }
    },
    "defaults": {"path": "deploy/overlays/dev", "namespace": "acme-dev"},
    "steps": [
      {
        "id": "render",
        "use": {
          "kind": "integration",
          "instance_ref": {"namespace": "default", "name": "kustomize-quickstart"},
          "capability": "generate_installation"
        },
        "with": {
          "git_url": "{{ inputs.git_url }}",
          "path": "{{ inputs.path }}",
          "revision": "{{ inputs.revision }}"
        },
        "timeout_seconds": 120
      },
      {
        "id": "apply",
        "depends_on": ["render"],
        "use": {
          "kind": "integration",
          "instance_ref": {"namespace": "default", "name": "kubernetes-quickstart"},
          "capability": "declarative_apply"
        },
        "with": {
          "namespace": "{{ inputs.namespace }}",
          "objects": "{{ steps.render.metadata.objects }}"
        },
        "timeout_seconds": 300
      },
      {
        "id": "observe",
        "depends_on": ["apply"],
        "use": {
          "kind": "integration",
          "instance_ref": {"namespace": "default", "name": "kubernetes-quickstart"},
          "capability": "observe_objects"
        },
        "with": {"objects": "{{ steps.render.metadata.objects }}"},
        "retry": {"max_attempts": 12, "backoff_seconds": 10},
        "timeout_seconds": 240
      }
    ]
  }
}
```

POST it:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=workflow" \
  -d @deploy.json
```

If your quickstart did not include `kustomize-quickstart` integration_instance, apply it now (see [feature/integrations.md](../features/integrations.md) for shape; the dev overlay seeds one in the quickstart).

## Step 2 — Apply the `repository_binding`

Save as `binding.json`:

```json
{
  "name": "acme-widget",
  "namespace": "default",
  "spec": {
    "component_kind": "product",
    "component_name": "widget",
    "component_namespace": "default",
    "repository": "acme/widget",
    "default_branch": "main",
    "automation": {"observe": true, "allow_dispatch_workflow": true},
    "deploy": {
      "workflow_kind": "yggdrasil",
      "workflow_ref": {"namespace": "default", "name": "deploy-acme-widget"},
      "default_inputs": {
        "git_url": "{{ push.repository.clone_url }}",
        "revision": "{{ push.head_commit.id }}",
        "path": "deploy/overlays/dev",
        "namespace": "acme-dev"
      },
      "branch_filter": ["main"]
    }
  }
}
```

POST:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=repository_binding" \
  -d @binding.json
```

## Step 3 — Configure the webhook secret

```bash
WEBHOOK_SECRET=$(openssl rand -hex 32)
kubectl -n yggdrasil set env statefulset/yggdrasil GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET
kubectl -n yggdrasil rollout status statefulset/yggdrasil --timeout=60s
echo "Save this secret somewhere — you will paste it in GitHub: $WEBHOOK_SECRET"
```

## Step 4 — Configure the GitHub webhook

In your GitHub repo Settings → Webhooks → Add webhook:

- **Payload URL**: `https://<your-yggdrasil-url>/api/v1/github/webhook`
- **Content type**: `application/json`
- **Secret**: paste the `$WEBHOOK_SECRET` value
- **Events**: "Just the push event"
- **Active**: ✓

If your Yggdrasil instance is not internet-reachable yet, skip Step 4 and use Step 5's curl simulation to validate the pipeline locally; revisit once you expose the API.

## Step 5 — Simulate a push (or push for real)

```bash
PAYLOAD='{"ref":"refs/heads/main","repository":{"full_name":"acme/widget","clone_url":"https://github.com/acme/widget.git"},"head_commit":{"id":"'$(git rev-parse HEAD)'","message":"deploy test","modified":["deploy/overlays/dev/kustomization.yaml"]},"pusher":{"name":"'$USER'"}}'
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print "sha256="$2}')

curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: $SIG" \
  "$YGG_URL/api/v1/github/webhook" \
  -d "$PAYLOAD" | jq
```

Expected:

```json
{
  "status": "deploying",
  "workflow": "default/deploy-acme-widget",
  "binding": "default/acme-widget",
  "repo": "acme/widget"
}
```

## Step 6 — Observe the workflow_run

```bash
curl -sf "$YGG_URL/api/v1/workflow-runs?limit=5" | jq '.[] | {workflow: .workflow.name, status: .status, started_at}'
```

The latest entry should be your `deploy-acme-widget` run with `status: succeeded` (or `running` if you caught it mid-execution).

Inspect step-by-step:

```bash
RUN_ID=$(curl -sf "$YGG_URL/api/v1/workflow-runs?limit=1" | jq -r '.[0].id')
curl -sf "$YGG_URL/api/v1/workflow-runs/$RUN_ID" | jq '.steps[] | {id, status, attempts, error}'
```

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| Webhook returns `200 {"status":"skipped","reason":"no repository_binding for ..."}` | The binding was applied to a different namespace, or `spec.repository` doesn't match the push payload | `curl $YGG_URL/api/v1/manifests?kind=repository_binding` and confirm the slug is exactly `acme/widget` |
| Webhook returns `401 {"error":"invalid webhook signature"}` | `WEBHOOK_SECRET` env var on Yggdrasil pod is not the same string used to sign the payload | Re-do step 3 and verify with `kubectl -n yggdrasil exec deploy/yggdrasil -- printenv GITHUB_WEBHOOK_SECRET` |
| Webhook returns `200 {"status":"skipped","reason":"ref refs/heads/feature/x outside branch_filter"}` | Pushed to a branch not in the binding's `branch_filter` | Add the branch to `branch_filter` or use `["*"]` to accept any |
| Workflow run `status: failed` at `render` | `kustomize-quickstart` integration_instance is unhealthy | `curl $YGG_URL/api/v1/integration-runtime-states` to diagnose; redeploy adapter if needed |
| Workflow run `status: failed` at `apply` with "field is immutable" | The deployed resource was created with a different selector than the new one | Delete the old object manually or redesign your overlay |

## What you accomplished

- A binding declaratively maps `acme/widget` → `deploy-acme-widget` workflow with templated inputs.
- The webhook handler routes pushes via the binding without any code change in `yggdrasil-core`.
- The workflow rendered → applied → observed your overlay end-to-end with retries and a structured run record.

## Next

- Apply the same pattern for the rest of your services. One binding per repository.
- Replace the `default` namespace with one per project / team when you adopt multi-tenancy (Phase 3 / v2.3).
- Move secret values out of overlays using [Tutorial 3](./03-secret-store.md).
