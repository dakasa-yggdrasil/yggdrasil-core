# Products

A product is a versioned bundle of components that ship together. It's
how Yggdrasil represents internal platform capabilities that combine
multiple integrations, templates, and infrastructure into a single
deployable unit.

## What it is

Where a `workflow` describes "how to do something", a `product`
describes "what something is and how to deploy it". A product can
have multiple components, each with their own renderer (raw_k8s,
kustomize, helm) and target (Kubernetes cluster, integration
instance, custom).

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: product
metadata:
  name: cert-manager
  namespace: global
spec:
  category: certificate
  class: platform
  owners: [team:platform]
  lifecycle:
    tier: critical
    stage: production
  components:
    - name: cert-manager-bundle
      source:
        kind: inline
        objects:
          - apiVersion: v1
            kind: Namespace
            metadata: { name: cert-manager }
      renderer: { kind: raw_k8s }
      target:
        kind: kubernetes
        integration_instance_ref: { name: kubernetes-prod, namespace: global }
        namespace: cert-manager
      reconcile: { strategy: apply, prune: true }
```

## How it works

Three lifecycle operations, each running as a workflow step
(`kind: product`):

| Operation | What it does |
|---|---|
| `installation.apply` | Materialize each component, render via the chosen renderer, dispatch to the target integration. |
| `installation.observe` | Read live state of each component's target. Compare to the materialized spec. |
| `installation.uninstall` | Reverse the apply. Optionally prune everything created. |

All three are dispatched from a workflow step:

```yaml
- id: deploy-cert-manager
  use:
    kind: product
    operation: installation.apply
  with:
    product_ref: { name: cert-manager, namespace: global }
```

## Component sources

A component can come from:

| Source kind | Use when |
|---|---|
| `inline` | Small, version-controlled, owned by the platform team. |
| `git` | The component lives in another repo (kustomize overlay, raw manifests). |
| `oci` | An OCI artifact (helm chart in an OCI registry, OPA bundle). |
| `integration` | The component is *generated* by an integration adapter at materialize time (e.g. the RabbitMQ adapter generates a full operator install bundle). |

`integration` source is the powerful one: it lets a plugin contribute
fully-formed components that the product treats uniformly.

## Component renderers

| Renderer | Output |
|---|---|
| `raw_k8s` | Pass-through. The source already produced k8s objects. |
| `kustomize` | Build a kustomize overlay; produce k8s objects. |
| `helm` | Render a Helm chart (with values); produce k8s objects. |

`raw_k8s` is the default for inline; `kustomize` is the recommended
default for git-sourced internal services. `helm` exists for
upstream/vendor compatibility — see
[deployment.md](../deployment.md) for the full preference order.

## Component targets

A target identifies *where* the rendered objects go. Today: Kubernetes
clusters reached through `integration-kubernetes`. Future targets
(VMs, ECS, Nomad) plug in as new target kinds.

## Reconcile strategies

| Strategy | Behavior |
|---|---|
| `apply` | One-time apply. Re-running is idempotent. |
| `sync` | Apply + remove drift. Live cluster mirrors the manifest. |

`prune: true` removes objects no longer in the spec — required for
`sync` semantics.

## Wire shape

### Apply a product

```http
POST /api/v1/workflow-runs
{
  "workflow":   { "namespace": "global", "name": "deploy-product" },
  "inputs":     { "product_name": "cert-manager", "product_namespace": "global" }
}
```

Where `deploy-product` is a workflow with one product step that
references `inputs.product_name`.

### Read product state

```sql
GET /api/v1/products
GET /api/v1/products/{namespace}/{name}
```

Returns the manifest plus, when materialization has been run, the
materialized spec snapshot from `product_materializations`.

## Operate it

**Monitor:**

- `workflow.run.step.failed` events with `step.kind == "product"`.
  Component failures are loud; an apply that drops a single
  component still fails the whole step.
- Product materialization time. Helm + git renderers can be slow;
  inline + raw_k8s is sub-second.
- Drift on `sync`-strategy components. The observe operation reports
  it; surface as a metric.

**Back up:**

Product manifests + `product_materializations` are normal Postgres
tables — standard backup applies.

## Pitfalls

- **Product as a workflow.** If a product has only one component and
  zero composition, it's probably better as a single workflow step.
  Reserve `product` for genuine bundles.
- **Helm by default.** The platform's preferred order is
  `raw_k8s > kustomize > helm` — Helm is for upstream compatibility,
  not the first choice. See [deployment.md](../deployment.md).
- **Drifting between manifest and renderer.** A `git` source pinned
  to `main` drifts every commit; pin to a tag or sha for production
  components.
- **Cross-product `requires`.** Don't build deep `requires` graphs
  between products. Two products are an integration boundary; if
  they need to coordinate, model the coordination as a workflow
  that dispatches both, not as cross-product dependencies.
