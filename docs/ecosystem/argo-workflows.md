# Yggdrasil + Argo Workflows

> TL;DR: Keep your Argo cluster. Register an `integration-argo` adapter.
> Yggdrasil workflow steps dispatch to Argo; you get the Argo runtime
> you already trust plus the Yggdrasil catalog and governance on top.

[Argo Workflows](https://argoproj.github.io/workflows/) is great at
Kubernetes-native pipelines — DAGs, artifacts, parallelism, pod-per-step.
If you already run it, there's no reason to move off. Yggdrasil becomes
the declarative control plane that decides *when* Argo runs and with
*what* inputs, across multiple clusters and environments.

## Composition pattern

```mermaid
flowchart LR
    Manifests[Yggdrasil workflow YAML]
    YGG[Yggdrasil core]
    Adapter[integration-argo adapter]
    Argo[Argo Workflows controller]
    Pods[Per-step pods]

    Manifests --> YGG
    YGG -- step: kind=integration, family=argo --> Adapter
    Adapter -- Argo REST / CRDs --> Argo
    Argo --> Pods
```

A Yggdrasil workflow step with `family: argo` dispatches an Argo
workflow spec as the adapter payload. The adapter submits it, watches
it to completion, and returns the final status (or the logs pointer)
as the Yggdrasil step result.

## Example workflow step

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: workflow
metadata:
  name: deploy-service
  namespace: prod
spec:
  trigger: { mode: manual }
  steps:
    - id: build-and-test
      use:
        kind: integration
        family: argo
        operation: submit_workflow
      with:
        cluster:
          instance_ref: { name: argo-prod, namespace: global }
        workflow_spec:
          # Regular Argo Workflow spec below
          entrypoint: main
          templates:
            - name: main
              steps:
                - - name: build
                    template: build
                - - name: test
                    template: test
            - name: build
              container:
                image: "{{ inputs.builder_image }}"
                args: [build]
            - name: test
              container:
                image: "{{ inputs.builder_image }}"
                args: [test]
        wait_for_completion: true

    - id: promote
      depends_on: [build-and-test]
      use:
        kind: integration
        family: kubernetes
        operation: apply_manifest
      with:
        manifest: { ... }
```

## What this buys you

- **One catalog across clusters.** The `workflow_spec` lives once in
  your Yggdrasil catalog; the `cluster.instance_ref` chooses which
  Argo cluster runs it. Dev, staging, prod — same manifest.
- **RBAC + policy before dispatch.** Yggdrasil's authorization pipeline
  runs before the Argo submit, uniformly for every team.
- **Unified audit.** `workflow.run.step.succeeded` events include the
  Argo run URL, so your audit table shows "Ana triggered deploy-service,
  which dispatched argo/<id>, which succeeded".
- **Composition.** Steps after the Argo submit can apply k8s objects,
  post to GitHub, rotate a secret — all without glue scripts.

## Building `integration-argo`

There's no first-party `integration-argo` in the catalog today — it's
a great candidate for a community integration. Scaffold it with:

```sh
yggdrasil new integration argo --owner your-org
```

Operations to implement at minimum:

| Operation | What it does |
|---|---|
| `submit_workflow` | POST a Workflow spec to Argo, return the run name. Optional `wait_for_completion`. |
| `describe_workflow_run` | GET status + phase + start/finish timestamps. |
| `read_workflow_logs` | Stream logs for a given run. |
| `cancel_workflow_run` | DELETE a running workflow. |

Reference: [Argo Workflows REST API](https://argoproj.github.io/argo-workflows/rest-api/).

## When to prefer Argo vs Yggdrasil workflows

Both can run DAGs, so the decision is about where each shines.

**Use Argo directly (dispatched from Yggdrasil) when you have:**

- Heavy per-step container work (CI builds, data pipelines).
- Artifact passing between steps, S3 / GCS backends.
- Fan-out / fan-in with hundreds of pods.
- Existing Argo-native tooling you don't want to rewrite.

**Use Yggdrasil workflow steps directly when you have:**

- Orchestration across *multiple systems* (apply a k8s manifest, rotate
  a secret, post a Slack message, trigger a github workflow — in that
  order).
- Steps that need the Yggdrasil RBAC / policy / audit story natively.
- Manifest-first flows where the inputs map 1:1 to a Yggdrasil
  `input_schema`.

The typical deployment uses both: Yggdrasil orchestrates across tools,
Argo handles the container-heavy phase inside a step.

## Pitfalls to avoid

- **Don't duplicate retry logic.** Argo has retries, Yggdrasil steps
  have retries — pick one. Usually: leave retries to Argo inside the
  Argo step, set `retry.max_attempts: 1` on the Yggdrasil step itself.
- **Don't pass secrets through both systems.** Inject credentials at
  the Argo side (via Argo secrets) or at the Yggdrasil integration
  instance side (via managed secrets). Never both — you'll rotate one
  and forget the other.
- **Watch the timeout.** Default Yggdrasil step timeout is much shorter
  than a typical Argo workflow. Set
  `timeout_seconds: 3600` or higher on the dispatching step if you
  `wait_for_completion: true`.
