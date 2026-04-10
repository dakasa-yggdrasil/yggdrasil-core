# Yggdrasil Core Backlog

External follow-ups identified during development. These are not bugs — they
are capability gaps that block specific consumer flows end-to-end, but where
the core side of the work is either complete or out of scope for this repo.

Each entry describes:
- **What** is missing
- **Why** it matters (which consumer flow is blocked)
- **Where** the work lives (this repo, adapter plugins, or both)
- **Surface** already landed that the rest of the work needs to match

---

## 1. `integration-aws` adapter — IaC actions (EKS, RDS, ElastiCache, VPC, IAM)

**What:** The `integration-aws` integration_type currently exposes
`action_catalog` entries only for S3, ECR, Secrets Manager, Route53, SES and
SNS (see `docs/bootstrap/manifests/integrations/aws-integration-type.json`).
It cannot provision the infrastructure primitives that Kubernetes-targeted
products depend on.

**Why it matters:** Bloco 3.1 of the DaKasa CD reformulation needs the
Yggdrasil bootstrap workflow to provision a full EKS-backed stack (VPC +
subnets + NAT + EKS cluster + RDS + ElastiCache + ECR repos + IAM roles).
Without these actions, the bootstrap is a mixture of manual runbook steps
(`eksctl create cluster`) and declarative workflow steps. The goal is to
make the whole flow declarative.

**Where the work lives:** Outside this repo. The core's responsibility is
the RPC contract and the integration_type manifest. The adapter plugin
(separate repo) implements the actual AWS SDK calls.

**Required actions to add:**
- `ensure_vpc`
- `ensure_subnet`
- `ensure_nat_gateway`
- `ensure_eks_cluster`
- `ensure_eks_nodegroup`
- `ensure_rds_instance`
- `ensure_elasticache_cluster`
- `ensure_iam_role`
- `ensure_iam_policy_attachment`
- `ensure_oidc_provider` (for IRSA bootstrap)

**Surface already landed:** None. This is purely additive — each new action
needs a `resource_type`, `action_catalog` entry, adapter handler, and
optionally new canonical resource prefixes.

**Blocked consumer:** DaKasa Bloco 3.1 workflow `bootstrap-dakasa-validation`
(Fase A–B — currently manual pre-requisite).

---

## 2. `integration-kubernetes` adapter — `declarative_delete` action handler

**What:** The `kubernetes-integration-type.json` manifest now declares a
`declarative_delete` action (added by this repo in commit "Add product
installation.uninstall operation"). The core-side product uninstall
pipeline dispatches `AdapterDeclarativeDeleteRequest` through the
`declarativeDeleteContract` RPC. **The adapter worker must implement the
handler for this action.**

**Why it matters:** The `product.installation.uninstall` operation is
complete in the core but returns an RPC error until the adapter plugin
has a handler for `declarative_delete`. DaKasa uses this for ephemeral
environment teardown (Bloco 3.1 workflow `teardown-dakasa-validation`
is blocked on it).

**Where the work lives:** In the `integration-kubernetes` adapter repo.
The core contract is already defined.

**Required implementation:**
- Subscribe to the adapter execute queue, dispatch on
  `request.operation == "declarative_delete"`
- For each object in `request.objects`, call kube API delete (respecting
  `request.namespace`, server-side apply field manager ownership)
- Return `AdapterDeclarativeDeleteResponse{Uninstalled: true, Resources: ...}`
  with the per-object outcome (status "deleted" / "missing" / "error")

**Surface already landed:**
- Contract schemas `declarativeDeleteRequest` / `declarativeDeleteResponse`
  (`docs/contracts/product-installation-adapter/v1/schema.json`)
- RPC contract spec `declarativeDeleteContract` (`controllers/message/contract_rpc.go`)
- Product executor method `uninstallComponentTarget`
  (`controllers/message/products.go`)
- `declarative_delete` in `action_catalog` of `kubernetes-integration-type.json`

**Blocked consumer:** DaKasa Bloco 3.1 workflow `teardown-dakasa-validation`.

---

## 3. `integration-kubernetes` adapter — `ImageOverrides` at render time

**What:** `AdapterDeclarativeApplyRequest.ImageOverrides` is now populated
by the core when a workflow step passes `target_overrides[*].image_overrides`
(see commit "Propagate image overrides through target overrides (core
side)"). The field carries a map of original image reference →
replacement reference. **The adapter must consume this map at render
time** before running server-side apply.

**Why it matters:** Without render-time image override, the DaKasa CD flow
has to commit a new Kustomize image tag to git for every build, adding a
round trip and coupling deployments to repository state. With it, the CI
pipeline emits an event carrying the new tag and the workflow applies it
directly.

**Where the work lives:** In the `integration-kubernetes` adapter repo.
Specifically the Kustomize renderer step.

**Required implementation:**
- When `request.ImageOverrides` is non-empty and the source component
  uses the Kustomize renderer, merge the map into the generated
  `kustomization.yaml` `images:` section (or the equivalent Kustomize
  overlay step) before running `kustomize build`.
- For components that use plain raw_k8s objects (no Kustomize step),
  walk the object graph and substitute `spec.containers[*].image` +
  `spec.initContainers[*].image` where `image` matches a key in the
  override map.
- Preserve the original request semantics (same namespace, same
  reconcile options) — image overrides are purely a render-stage
  transformation.

**Surface already landed:**
- `model.TargetOverride.ImageOverrides` (`model/product_target_execution.go`)
- `model.AdapterDeclarativeApplyRequest.ImageOverrides` (same file)
- JSON schema entry `declarativeApplyRequest.image_overrides`
  (`docs/contracts/product-installation-adapter/v1/schema.json`)
- Workflow step parser `parseTargetOverridesFromStepInput`
  (`controllers/message/workflows.go`)
- Executor method `imageOverridesForOriginalKey` +
  `applyProduct`/`applyComponent`/`applyComponentTarget` threading
  (`controllers/message/products.go`)

**Blocked consumer:** DaKasa Bloco 3.2 CI/CD flow
`dakasa-deploy-component`. Currently works by committing tag to git,
but the point of this work is to remove that round-trip.

---

## 4. Workflow step `condition` — potential expansion with `&&` / `||`

**What:** The current `WorkflowStepSpec.Condition` evaluator
(`manifest/workflow.go::EvaluateWorkflowStepCondition`) supports unary
truthiness and two binary operators (`==`, `!=`). It does not support
logical conjunction or disjunction.

**Why it matters:** Real-world conditions like "run only in validation
and only when skip flag is false" currently require splitting into
multiple steps (first step always runs and short-circuits via an
unambiguous single condition, then the real step runs).

**Where the work lives:** In this repo, `manifest/workflow.go`.

**Proposed extension:**
- Parse `&&` and `||` with left-to-right evaluation, no precedence
  beyond what left-to-right provides (keep it dumb simple).
- Allow `!` prefix on a sub-expression.
- Continue to parse templates inside each leaf.

**Status:** Not yet planned. Register here because the current syntax is
known to be minimal by design, and consumers should expect a near-term
extension when real workflows start using conditions.

---

## Adding entries to this file

When landing a feature whose *consumer side* depends on work in another
repo, capture that dependency here. Each entry should be precise enough
that the adapter team can pick it up without needing a meeting — the
core contract is the handoff.
