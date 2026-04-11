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

## 1. ✅ DONE — `integration-aws` adapter — IaC actions (EKS, RDS, ElastiCache, VPC, IAM)

**Status:** **Resolved** on 2026-04-11. All 10 IaC actions are implemented
in the adapter (`integration-aws/internal/adapter/spec.go`) and registered
in the integration_type manifest at
`docs/bootstrap/manifests/integrations/aws-integration-type.json`. The
manifest now exposes 18 total `action_catalog` entries (8 pre-existing +
10 new).

**What was delivered:**
- `ensure_iam_role`, `ensure_iam_policy_attachment`, `ensure_oidc_provider`
  (IAM phase — foundation for IRSA + GitHub Actions OIDC)
- `ensure_vpc`, `ensure_subnet`, `ensure_nat_gateway` (VPC phase — network
  foundation)
- `ensure_eks_cluster`, `ensure_eks_nodegroup` (EKS phase — compute plane)
- `ensure_rds_instance`, `ensure_elasticache_cluster` (storage phase)

Each action uses the same idempotent pattern as the pre-existing operations:
Describe-then-Create, tag reconciliation on re-run, and structured response
outputs (arn, status, existed, and resource-specific fields). All 10 new
operations have dispatcher unit tests in `spec_test.go` bringing total from
8 to 18 tests.

**Consumer unblocked:** DaKasa Bloco 3.1 `bootstrap-dakasa-validation`
workflow can now fully declaratively provision the EKS-backed validation
stack from zero — no `eksctl`/Terraform pre-requisites. Writing the
`bootstrap-dakasa-infra` workflow that uses these actions is a DaKasa-side
follow-up, not a core debt.

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

## 5. `integration-grafana` adapter — `upsert_dashboard` and `upsert_alert_rule` capabilities

**What:** The `integration-grafana` integration_type manifest at
`docs/bootstrap/manifests/integrations/grafana-integration-type.json`
does not define capabilities for pushing Grafana dashboards or alert
rules. Today the only path for delivering dashboard/alert content is
via Grafana provisioning at startup (ConfigMap mount), which requires
a pod restart on every change.

**Why it matters:** DaKasa Bloco 4.1 (observability) commits 6 Grafana
dashboards + 12 alert rules to the git repo and needs a workflow to
push them into the running Grafana instance. Without `upsert_dashboard`
and `upsert_alert_rule` capabilities, the DaKasa team must fall back to
Abordagem A (ConfigMap provisioning + rolling restart) instead of the
preferred Abordagem B (runtime updates via HTTP API, no restart).

**Where the work lives:** Outside this repo. The core's responsibility
is to extend the integration_type manifest with the capability
declarations and any contract schema the adapter needs to validate
input payloads against. The adapter plugin (`integration-grafana`
repo, external) implements the actual Grafana HTTP API calls.

**Required additions:**
- `upsert_dashboard` — takes a dashboard JSON payload + optional
  folder UID + optional overwrite flag
- `upsert_alert_rule` — takes a rule YAML/JSON payload + optional
  folder UID

**Blocked consumer:** DaKasa Bloco 4.1 Abordagem B (runtime dashboard
provisioning via `dakasa-deploy-observability` workflow). Currently
falling back to Abordagem A (ConfigMap + restart).

---

## 6. `handleWorkflowRun` authorization integration with RBAC + Policy

**What:** `controllers/httpapi/workflow_runs.go:36`
`authorizeWorkflowRunRequest` currently does simple bearer-token
comparison against the `YGGDRASIL_WORKFLOW_RUN_TOKEN` environment
variable. It does NOT route the request through the
`authorizationEvaluateHandler` (at
`controllers/message/manifests.go:304`) which combines RBAC and Policy
via `EvaluateAuthorizationRequest`.

**Why it matters:** DaKasa Bloco 4.2 commits 3 governance manifests
(RBAC with 4 roles + 4 bindings, Policy with 3 conditional rules,
Guardian Policy with approval_required autonomy). These are
authoritative in the catalog but bypassed at the CD entrypoint — the
bearer token on `POST /api/v1/workflow-runs` is the only enforcement
point. The Policy `cd-dispatcher-validation-only` (which restricts
the CD bot to `environment == "validation"`) is dead until this
integration lands.

**Where the work lives:** In this repo, `controllers/httpapi/`.

**Proposed shape:**
1. Extract the subject from the incoming bearer token (via a new
   token-to-subject lookup, or via signed JWT claims if we move to
   JWT tokens).
2. Construct an `EvaluateAuthorizationRequest` with
   `resource: "workflow:<namespace>:<name>"`,
   `action: "run"`, and `input: <workflow inputs from request body>`.
3. Short-circuit with HTTP 403 when `allow=false`.
4. Log the matched RBAC roles + Policy rules on allowed requests
   (audit trail via Event Stream — already built).

**Blocked consumer:** DaKasa Bloco 4.2 runtime enforcement at the CD
entrypoint.

---

## Adding entries to this file

When landing a feature whose *consumer side* depends on work in another
repo, capture that dependency here. Each entry should be precise enough
that the adapter team can pick it up without needing a meeting — the
core contract is the handoff.
