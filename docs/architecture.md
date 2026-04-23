# Architecture

This document describes how yggdrasil-core is built and deployed. If
you are evaluating Yggdrasil as a platform, [concepts.md](./concepts.md)
is the better entrypoint — read that first.

## Components

```
                     ┌────────────────────────────────┐
   yggdrasil CLI ──► │            yggdrasil-core       │ ◄── yggdrasil-console (surface)
   adopter browser ─►│  ┌─────────┐   ┌────────────┐   │
                     │  │  HTTP   │   │  Workflow  │   │
                     │  │  API    │   │  engine    │   │
                     │  └────┬────┘   └─────┬──────┘   │
                     │       │              │          │
                     │       ▼              ▼          │
                     │  ┌──────────┐   ┌──────────┐    │
                     │  │ Postgres │   │ RabbitMQ │    │
                     │  └──────────┘   └────┬─────┘    │
                     └──────────────────────┼──────────┘
                                            │ AMQP RPC
                                ┌───────────┼───────────────────────┐
                                ▼           ▼                       ▼
                         integration-    integration-         integration-
                         kubernetes       grafana              rabbitmq
                         (adapter pod)    (adapter pod)        (adapter pod)
```

**yggdrasil-core** is a single Go binary that hosts:

- The HTTP API (REST, `/api/v1/...`).
- The workflow engine that dispatches steps in order.
- The manifest repository (reads and versioned writes against Postgres).
- The third-party auth provider registry.
- The addons registry (startup hooks: postgres, rabbitmq, HTTP, first
  run, scheduler, cleaner, reconciler).

**Postgres** is the single source of truth for all state: manifests,
sessions, events, identities, guardian approvals. The outbox table
(`event_log`) feeds downstream consumers.

**RabbitMQ** is the async transport for integration calls. Every
integration adapter consumes requests from `yggdrasil.adapter.<type>.
execute` and replies on the correlation queue. The engine, not
adapters, is the orchestrator.

**Integration adapters** are independent containers (one per type)
that speak the AMQP contract. They deploy as Kubernetes workloads
in the adopter's cluster — typically installed via `yggdrasil install`.

**Surfaces** are user-facing UIs (the console is the first-party one)
that talk to yggdrasil-core's HTTP API. Surfaces are themselves
registered as manifests.

## Request flow: `yggdrasil install`

1. CLI fetches `yggdrasil-quickstart.yaml` from GitHub (with optional
   `GITHUB_TOKEN` for private repos).
2. CLI collects required inputs via huh TUI, merges them with seeded
   `--input k=v` flags, and POSTs to
   `/api/v1/integrations/install`.
3. `controllers/httpapi/integrations_install.go` validates the spec,
   compiles a concrete `workflow` manifest (resolving provider and
   rendering templates), persists it, and dispatches a run.
4. `controllers/message/workflows.go` orchestrates step execution.
   Each step either:
   - `kind=integration`: resolves the instance, RPCs the adapter over
     AMQP, records the result.
   - `kind=product`: runs the product lifecycle handler in-process.
   - `kind=yggdrasil`: persists a manifest against the core itself
     (used by the `register-instance` step to create the
     integration_instance).
5. Adapter pod applies ServiceAccount + Deployment in the adopter's
   namespace (via `apply_manifest`), registers the instance, and
   runs a smoke test.

## Data flow: manifest writes

```
HTTP POST /api/v1/<kind>s
          │
          ▼
┌──────────────────────────┐
│ consoleCreateManifest…   │  validates shape
│ Request / handleManifest │
│ Create / Upsert…         │
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│ manifestengine           │  kind-specific spec validation
│   NormalizeDocument      │
│   ValidateDocument       │
│   Checksum               │
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│ BeginTx                  │
│   CreateManifestVersionTx│
│   EmitEvent manifest.    │
│     created              │
│ Commit                   │
└──────────┬───────────────┘
           ▼
    (event_log row)
           │
           ▼
   downstream consumers
   (outbox workers)
```

The AMQP `manifest.create` consumer and the workflow step
`kind=yggdrasil, operation=apply_manifest` both funnel into the
same helper (`controllers/message/manifest_persist.go`). This is the
single code path that guarantees every manifest write emits an event.

## Deployment options

### Docker Compose (dev and small self-hosted)

`docker-compose.standalone.yml` brings up Postgres + RabbitMQ +
yggdrasil-core with random passwords and first-run bootstrap. Good
for laptops and tiny deployments. `yggdrasil init` automates the
whole thing.

### Kubernetes via Helm (production)

The chart at `chart/` depends on `bitnami/postgresql` and
`bitnami/rabbitmq` by default, can be switched to external managed
services via `postgresql.enabled=false` + `external.postgres.*`, and
generates a first-run admin secret that survives upgrades.
[deployment.md](./deployment.md) has the full runbook.

### Custom / bare-metal

yggdrasil-core is a single binary. Point `DB_*` and `BROKER_URL` at
your Postgres and RabbitMQ, run `goose up` once to migrate the
schema, then run the binary. The rest of the behavior — first-run
bootstrap, TLS termination, ingress — is whatever the operator wires
up externally.

## Scale and failure model

yggdrasil-core is horizontally scalable; every request is stateless
apart from the DB + broker. A typical production deployment runs 2-3
replicas behind a service. DB failure takes the whole control plane
down; RMQ failure surfaces as step-level failures on integration
calls but does not corrupt state. Adapters reconnect via
`ReliableConnection` (see `commons` package) and survive short
broker outages transparently.
