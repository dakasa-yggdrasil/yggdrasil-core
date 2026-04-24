# Yggdrasil + Airflow / Dagster / n8n / Zapier

> TL;DR: These are data orchestrators. Yggdrasil is a platform
> orchestrator. When they need to dispatch across *platform* systems
> (k8s, aws, secrets, auth providers), a Yggdrasil integration is the
> clean bridge. When Yggdrasil needs data-pipeline semantics (DAGs with
> backfill, datasets, sensors), hand the work to them via an adapter.

[Apache Airflow](https://airflow.apache.org),
[Dagster](https://dagster.io), [n8n](https://n8n.io), and
[Zapier](https://zapier.com) share a DNA: DAG of tasks where each task
is meaningful *to the data team*. Yggdrasil's DNA is platform
automation — catalogs, integrations, governance, cross-tool glue.

They compose naturally in both directions.

## Yggdrasil triggers data pipelines

**Scenario.** A platform event should kick off a data pipeline —
for example, a new customer signs up and you want to run the
onboarding DAG.

**Pattern.** Yggdrasil workflow → `integration-airflow` (or
`integration-dagster`, etc.) step → external trigger + optional
wait.

```yaml
- id: kick-off-onboarding-dag
  use:
    kind: integration
    family: airflow
    operation: trigger_dag
  with:
    dag_id: customer_onboarding
    run_id: "onboarding-{{ inputs.customer_id }}"
    conf:
      customer_id: "{{ inputs.customer_id }}"
    wait_for_state: success
    timeout_seconds: 1800
```

The adapter uses Airflow's
[stable REST API](https://airflow.apache.org/docs/apache-airflow/stable/stable-rest-api-ref.html)
to trigger and watch. Same model for Dagster's GraphQL API, n8n's
webhook endpoint, or any Zapier webhook trigger.

## Data pipelines call back into Yggdrasil

**Scenario.** An Airflow DAG finishes and needs to emit a platform
event (rotate a secret, update a Grafana dashboard, revoke an access
grant).

**Pattern.** An Airflow task does an HTTP POST to Yggdrasil's
`/api/v1/workflow-runs` endpoint, which dispatches the right
Yggdrasil workflow.

```python
# Airflow task (Python operator)
import requests

def notify_yggdrasil(**context):
    requests.post(
        "https://yggdrasil.internal/api/v1/workflow-runs",
        headers={"Authorization": f"Bearer {os.environ['YGGDRASIL_TOKEN']}"},
        json={
            "workflow": {"namespace": "global", "name": "post-onboarding-cleanup"},
            "inputs": {
                "customer_id": context["dag_run"].conf["customer_id"],
            },
        },
        timeout=30,
    ).raise_for_status()
```

Bi-directional wiring. The platform operator sees "onboarding" as
*one* workflow in Yggdrasil; the data team sees *one* DAG in Airflow.
Each tool owns its half; the integration is the link.

## Building the adapter

None of these first-party adapters exist yet (as of self-hosted v1).
Scaffold one with:

```sh
yggdrasil new integration airflow --owner your-org
```

Operations per engine:

### Airflow (REST API)

| Operation | Purpose |
|---|---|
| `trigger_dag` | POST `/dags/{dag_id}/dagRuns`. |
| `describe_dag_run` | GET `/dags/{dag_id}/dagRuns/{run_id}`. |
| `list_dag_runs` | GET `/dags/{dag_id}/dagRuns`. |
| `pause_dag` / `unpause_dag` | PATCH `/dags/{dag_id}`. |

### Dagster (GraphQL)

| Operation | Purpose |
|---|---|
| `launch_run` | `launchRun` mutation. |
| `describe_run` | `runOrError` query. |
| `terminate_run` | `terminateRun` mutation. |

### n8n (REST or webhook)

| Operation | Purpose |
|---|---|
| `trigger_workflow` | POST to configured webhook or `/executions`. |
| `describe_execution` | GET `/executions/{id}`. |

### Zapier (outbound-only)

Zapier is one-way by nature (inbound webhooks trigger your zaps).
Pattern: `zapier_notify` operation that POSTs to a configured webhook
URL; no `describe_*` possible.

## Pitfalls to avoid

- **Sensor loops.** Don't have Airflow sensors poll Yggdrasil for
  platform state — use Yggdrasil events (outbox) as the integration
  point. Sensor loops are cheap individually but expensive in
  aggregate.
- **Credential duplication.** The adapter should use a *single*
  Yggdrasil integration_instance credential (API key, JWT) scoped to
  just the trigger endpoints. Don't ship a DAG's personal token.
- **Idempotency.** Yggdrasil steps retry; data pipelines don't always
  like being re-triggered. Use `run_id` derived from input (as in the
  example above) so retries deduplicate at the data-tool side.
