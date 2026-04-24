# Yggdrasil + Temporal

> TL;DR: Temporal is the best durable-execution engine out there. Use it
> as the backend for long-running steps; Yggdrasil gives you the
> declarative manifest catalog and multi-tool orchestration on top.

[Temporal](https://temporal.io) solves a different problem than
Yggdrasil: durable execution of application logic, written as code,
with deterministic replay. Yggdrasil solves declarative orchestration
across tools, with manifest as source of truth. They complement
cleanly — don't pick one, use both where each shines.

## Where each tool wins

| Concern | Temporal | Yggdrasil |
|---|---|---|
| Long-running, stateful workflow (days, weeks) | ✅ deterministic replay | ⚠️ reasonable but not the focus |
| Workflow as code (TS, Go, Java, Python) | ✅ | ❌ (YAML manifests) |
| Workflow as declarative YAML | ❌ | ✅ |
| Versioned manifest catalog across workflows | ❌ | ✅ |
| RBAC + policy before dispatch, across tools | ❌ | ✅ |
| Orchestrate across tools (k8s, aws, github, grafana) | ⚠️ via custom activities | ✅ via integration catalog |
| Audit stream of platform ops | ⚠️ per-namespace | ✅ typed events in Postgres |

## Composition patterns

### 1. Temporal as durable backend for a Yggdrasil step

A Yggdrasil workflow has a step that needs to run for hours or days
(human approval, batch job, external event wait). Instead of
implementing durability in Yggdrasil, dispatch to Temporal.

```yaml
- id: wait-for-approval
  use:
    kind: integration
    family: temporal
    operation: start_workflow
  with:
    namespace: platform
    workflow_type: ApprovalFlow
    workflow_id: "approval-{{ inputs.change_id }}"
    input:
      change_id: "{{ inputs.change_id }}"
      requested_by: "{{ auth.identifier }}"
    wait_for_completion: true
    completion_timeout_seconds: 2592000   # 30 days

- id: apply-change
  depends_on: [wait-for-approval]
  use:
    kind: integration
    family: kubernetes
    operation: apply_manifest
  with:
    manifest: { ... }
```

The `integration-temporal` adapter:

1. Starts the Temporal workflow.
2. Polls (or uses Temporal visibility) until the workflow completes.
3. Returns the result as the Yggdrasil step metadata.

### 2. Yggdrasil catalog as a data source for Temporal activities

Activities written in your codebase fetch `integration_instance`
manifests from Yggdrasil and use the credentials stored there. One
source of truth for credentials, one place to rotate.

```go
// inside a Temporal activity
func applyK8sManifest(ctx context.Context, input ApplyInput) error {
    instance, err := yggdrasil.GetInstance(ctx, "global", input.Cluster)
    if err != nil {
        return err
    }
    // Use instance.Credentials to configure the k8s client
}
```

Temporal handles the durability; Yggdrasil handles the
"which cluster, what credentials" lookup.

### 3. Temporal Cloud / self-hosted, same integration

Yggdrasil doesn't care where your Temporal runs. The
`integration-temporal` adapter takes a `frontend_address` + auth
credential; whether that's your self-hosted cluster or Temporal Cloud
is transparent.

## Building `integration-temporal`

No first-party adapter today — community contribution welcome. Scaffold:

```sh
yggdrasil new integration temporal --owner your-org
```

Operations to implement:

| Operation | Purpose |
|---|---|
| `start_workflow` | Start a workflow by type ID + input. Optional `wait_for_completion`. |
| `describe_workflow_execution` | Fetch run state. |
| `signal_workflow` | Send a typed signal to a running workflow. |
| `query_workflow` | Query workflow state (read-only). |
| `cancel_workflow_execution` | Request cancellation. |

Reference: [Temporal Server API](https://docs.temporal.io/references/sdk-metrics).

## Pitfalls to avoid

- **Don't re-invent Temporal in Yggdrasil.** If a workflow needs
  deterministic replay, retries with state, or weeks-long duration,
  the right answer is Temporal behind a Yggdrasil step.
- **Don't re-invent Yggdrasil in Temporal.** Writing 30 Temporal
  activities that each wrap a tool you could hit via a Yggdrasil
  integration is how code bases bloat. Dispatch the whole multi-step
  flow back to Yggdrasil from a single activity when that makes sense.
- **Namespace mapping.** Temporal has its own namespace concept;
  Yggdrasil has manifest namespaces. They don't have to match, but
  document the convention for your deployment so operators don't
  chase ghosts.
- **Visibility / cost.** Long-running Temporal workflows with short
  polling from Yggdrasil can generate a lot of history events. Prefer
  Temporal's `workflow.completed` event bridged back to Yggdrasil over
  polling where possible.
