# Architecture

This document describes how yggdrasil-core is built and deployed. If
you are evaluating Yggdrasil as a platform, [concepts.md](./concepts.md)
is the better entrypoint — read that first.

## Components

```
                     ┌────────────────────────────────┐
   yggdrasil CLI ──► │            yggdrasil-core       │ ◄── surface-console (surface)
   adopter browser ─►│  ┌─────────┐   ┌────────────┐   │
                     │  │  HTTP   │   │  Workflow  │   │
                     │  │  API    │   │  engine    │   │
                     │  └────┬────┘   └─────┬──────┘   │
                     │       │              │          │
                     │       ▼              ▼          │
                     │  ┌──────────┐   Pluggable        │
                     │  │ Postgres │   transport layer  │
                     │  └──────────┘        │           │
                     └──────────────────────┼───────────┘
                                            ▼
                       ┌────────┬───────────┬──────────────┐
                       │        │           │              │
                    HTTP     AMQP/RMQ    gRPC/Kafka/NATS  (plug-in)
                       │        │           │
                       ▼        ▼           ▼
                    integration adapters (independent processes)
```

**yggdrasil-core** is a single Go binary that hosts:

- The HTTP API (REST, `/api/v1/...`) — the public surface for the CLI,
  surfaces, and every integration-caller.
- The workflow engine that dispatches steps in order.
- The manifest repository (reads and versioned writes against Postgres).
- The third-party auth provider registry.
- The addons registry (startup hooks: postgres, optional AMQP broker
  connection, HTTP, first run, scheduler, cleaner, reconciler).

**Postgres** is the single source of truth for all state: manifests,
sessions, events, identities, guardian approvals. The outbox table
(`event_log`) feeds downstream consumers. This is the one
infrastructure dependency that is always required.

**Transport** is how the core reaches adapters. It is **pluggable** —
declared per `integration_type` in its manifest:

- `http_json` — the core POSTs to adapter HTTP endpoints. No broker
  required.
- `rabbitmq` — the core publishes to AMQP queues and awaits replies.
  Opt-in (gated on the `BROKER_URL` env var); if you don't set
  `BROKER_URL`, the RabbitMQ addon skips and the core boots
  broker-free.
- Any other transport (gRPC, Kafka, NATS, SQS, Pub/Sub) plugs in as a
  small switch-case extension. See
  [features/transports.md](./features/transports.md).

A single deployment can mix transports — some adapters HTTP, some
AMQP, simultaneously.

**Integration adapters** are independent processes (typically
Kubernetes workloads) that speak whichever transport they declared.
They deploy into the adopter's infrastructure and are installed via
`yggdrasil install`.

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
   - `kind=integration`: resolves the instance, dispatches to the
     adapter via whichever transport the integration_type declares
     (HTTP / AMQP / pluggable), records the result.
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

The `manifest.create` AMQP consumer (when the AMQP addon is enabled)
and the workflow step `kind=yggdrasil, operation=apply_manifest` both
funnel into the same helper
(`controllers/message/manifest_persist.go`). This is the single code
path that guarantees every manifest write emits an event, regardless
of which transport or interface delivered the request.

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

yggdrasil-core is a single binary. Point `DB_*` at your Postgres, run
`goose up` once to migrate the schema, then run the binary. Optionally
set `BROKER_URL` if any integration uses `transport: rabbitmq` — leave
it unset for pure-HTTP deployments. The rest — first-run bootstrap,
TLS termination, ingress — is whatever the operator wires up
externally.

## Scale and failure model

yggdrasil-core is horizontally scalable; every request is stateless
apart from the DB. A typical production deployment runs 2-3 replicas
behind a service.

DB failure takes the whole control plane down (Postgres is the only
mandatory dependency). Transport failures are scoped:

- **HTTP transport failure** — individual step fails with "adapter
  unreachable"; the rest of the workflow continues.
- **AMQP transport failure** (when enabled) — integrations that
  declared `transport: rabbitmq` fail at dispatch; HTTP-transport
  integrations keep working. Adapters reconnect via
  `ReliableConnection` (see `commons` package) and survive short
  broker outages transparently.

Neither transport failure corrupts state. The catalog is safe; at
most you have a handful of `workflow_run` rows in `running` status
to reconcile after recovery — see
[operations/incident-response.md](./operations/incident-response.md).
