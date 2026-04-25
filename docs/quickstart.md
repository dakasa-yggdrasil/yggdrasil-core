# Quickstart — Deploy Yggdrasil and Trigger Your First Workflow Run

This guide takes you from a clean machine to a working Yggdrasil control plane with a real webhook → workflow → deploy pipeline. Plan ~60 minutes for a first run; ~20 minutes once you know the moves.

## What you will end up with

- Yggdrasil-core v2.x running in your cluster
- One `integration-kubernetes` adapter wired to that cluster
- One `repository_binding` manifest mapping a fake "acme/widget" repository to a workflow
- A push webhook that dispatches `deploy-via-kustomize-source` and observes the rollout

## Prerequisites

Install these once:

| Tool | Why |
|---|---|
| **k3s** (or any kube cluster) | Where Yggdrasil and your services run. The quickstart uses k3s on a laptop because it is free and starts in under five minutes. EKS/GKE/AKS work the same way; substitute your cluster credentials in step 6. |
| **kubectl** ≥ 1.28 | Local cluster access |
| **curl** + **jq** | Talking to the Yggdrasil HTTP API |
| **openssl** | Signing the simulated GitHub webhook payload (step 10) |

```bash
# k3s on macOS / Linux laptop (one-liner from https://k3s.io)
curl -sfL https://get.k3s.io | sh -

# Verify
kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get nodes
```

## Step 1 — Clone the upstream

```bash
git clone https://github.com/dakasa-yggdrasil/yggdrasil-core.git
cd yggdrasil-core
```

The quickstart artefacts you will use live in:

- `deploy/overlays/dev/` — kustomize overlay for Yggdrasil + Postgres + RabbitMQ + the kubernetes adapter
- `docs/quickstart-fixtures/` — workflow + binding manifests you POST during the walkthrough

## Step 2 — Apply the dev overlay

```bash
kubectl apply -k deploy/overlays/dev
kubectl -n yggdrasil rollout status statefulset/yggdrasil --timeout=180s
kubectl -n yggdrasil rollout status deployment/integration-kubernetes-adapter --timeout=120s
```

This brings up:

- **yggdrasil-core** as a `StatefulSet/yggdrasil` (1 replica)
- **postgres** for manifest persistence
- **rabbitmq** for transport (default is HTTP; AMQP is opt-in)
- **integration-kubernetes adapter** as a `Deployment`, exposed at `integration-kubernetes-adapter.yggdrasil.svc.cluster.local:8081`
- A **port-forward** helper Service `yggdrasil-public:9080` you can `kubectl port-forward` to talk to the API.

```bash
# Port-forward the API to localhost
kubectl -n yggdrasil port-forward svc/yggdrasil-public 9080:9080 &
export YGG_URL=http://localhost:9080
```

## Step 3 — Verify health

```bash
curl -sf $YGG_URL/healthz                 # → ok
curl -sf $YGG_URL/api/v1/health | jq      # → {"status":"ok",...}
curl -sf $YGG_URL/readyz | jq             # → {"status":"ready",...}
```

If `/readyz` returns `not_ready` with `postgres_unavailable`, the rollout is still running. Wait 30 seconds and retry.

## Step 4 — List the seeded `integration_type` manifests

The dev overlay seeds `kubernetes` and `manifest-sources-kustomize` integration types so you do not have to build adapters yourself:

```bash
curl -sf "$YGG_URL/api/v1/manifests?kind=integration_type" | jq '.[] | .metadata.name'
# → "kubernetes"
# → "manifest-sources-kustomize"
```

Check the runtime handshake — the adapter answered `Describe()` correctly:

```bash
curl -sf "$YGG_URL/api/v1/integration-runtime-states" | jq '.runtime_states[] | {ref: .integration_instance.namespace + "/" + .integration_instance.name, status: .status}'
```

Both rows should report `status: healthy`.

## Step 5 — Apply your first workflow

The fixture `docs/quickstart-fixtures/workflow-observe-pod.json` is a tiny three-step workflow that observes the API server pod and exits successfully. POST it:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=workflow" \
  -d @docs/quickstart-fixtures/workflow-observe-pod.json | jq '.manifest.metadata'
# → {"name":"observe-pod","namespace":"global","active":true}
```

## Step 6 — Run the workflow

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/workflow-runs" \
  -d '{"workflow":{"namespace":"global","name":"observe-pod"},"inputs":{}}' \
  | jq '{status, steps: [.steps[] | {id, status}]}'
```

Expected output:

```json
{
  "status": "succeeded",
  "steps": [
    {"id": "observe", "status": "succeeded"}
  ]
}
```

Your first workflow ran. The control plane resolved the workflow manifest, validated inputs, dispatched the `observe_objects` capability through the kubernetes adapter, and recorded the outcome.

## Step 7 — Apply your first `repository_binding`

The fixture `docs/quickstart-fixtures/binding-acme-widget.json` declares a binding for a fake `acme/widget` repo:

```json
{
  "apiVersion": "yggdrasil.io/v1alpha1",
  "kind": "repository_binding",
  "metadata": {"namespace": "default", "name": "acme-widget"},
  "spec": {
    "component_kind": "product",
    "component_name": "widget",
    "component_namespace": "default",
    "repository": "acme/widget",
    "default_branch": "main",
    "automation": {"observe": true, "allow_dispatch_workflow": true},
    "deploy": {
      "workflow_kind": "yggdrasil",
      "workflow_ref": {"namespace": "global", "name": "observe-pod"},
      "default_inputs": {},
      "branch_filter": ["main"]
    }
  }
}
```

POST it:

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=repository_binding" \
  -d @docs/quickstart-fixtures/binding-acme-widget.json | jq '.manifest.metadata.name'
# → "acme-widget"
```

## Step 8 — Configure the webhook secret

Yggdrasil verifies GitHub push payloads with HMAC-SHA256:

```bash
WEBHOOK_SECRET=quickstart-secret
kubectl -n yggdrasil set env statefulset/yggdrasil GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET
kubectl -n yggdrasil rollout status statefulset/yggdrasil --timeout=60s
```

(In production you would set `GITHUB_WEBHOOK_SECRET` via your secret store, not as a literal env var.)

## Step 9 — Forge a signed push payload

```bash
PAYLOAD='{"ref":"refs/heads/main","repository":{"full_name":"acme/widget","clone_url":"https://github.com/acme/widget.git"},"head_commit":{"id":"deadbeef","message":"hello","modified":[]},"pusher":{"name":"alice"}}'
SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print "sha256="$2}')
echo "Signature: $SIG"
```

## Step 10 — Send the webhook

```bash
curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: $SIG" \
  "$YGG_URL/api/v1/github/webhook" \
  -d "$PAYLOAD" | jq
```

Expected response:

```json
{
  "status": "deploying",
  "workflow": "global/observe-pod",
  "binding": "default/acme-widget",
  "repo": "acme/widget"
}
```

The webhook handler:

1. Verified the HMAC signature.
2. Looked up the `repository_binding` for `acme/widget` (success).
3. Confirmed the push ref matches `branch_filter` (`["main"]`).
4. Dispatched `global/observe-pod` with templated inputs.

## Step 11 — Observe the dispatched workflow_run

```bash
curl -sf "$YGG_URL/api/v1/workflow-runs?limit=5" | jq '.[] | {workflow: .workflow.name, status: .status, started_at}'
```

You should see your `observe-pod` run with `status: succeeded`, dispatched within seconds of the webhook POST.

## Step 12 — Cleanup

```bash
kubectl delete -k deploy/overlays/dev
kubectl delete namespace yggdrasil
```

If you used k3s and want to teardown:

```bash
sudo /usr/local/bin/k3s-uninstall.sh
```

---

## What is next

You now know the four primitives that compose Yggdrasil's CD model:

- **integration_type / integration_instance** — the connector to an external system (k8s, GitHub, AWS, …)
- **workflow** — a manifest declaring a sequence of integration capability calls
- **repository_binding** — the policy "when repo X pushes, dispatch workflow Y with these inputs"
- **manifest** — the declarative envelope persisted in Postgres and validated server-side

For a deeper walk through each primitive, follow the tutorials:

1. **[T1 — Wire your first service to Yggdrasil CD](./tutorials/01-webhook-cd.md)** — bring a real service repo under Yggdrasil-driven CD.
2. **[T2 — Build a custom integration adapter](./tutorials/02-custom-adapter.md)** — extend Yggdrasil with a connector for any system.
3. **[T3 — Use Yggdrasil as your secret store](./tutorials/03-secret-store.md)** — eliminate cleartext secrets from your manifests.

For the REST API reference, see [api-reference/](./api-reference/).
For internals and design rationale, see [architecture/](./architecture/).
