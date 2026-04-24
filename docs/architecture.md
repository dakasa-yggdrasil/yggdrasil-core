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
                     │  ┌──────────┐   rpc.Transport    │
                     │  │ Postgres │   (pluggable RPC)   │
                     │  └──────────┘        │           │
                     └──────────────────────┼───────────┘
                                            ▼
                       ┌────────┬───────────┬──────────────┐
                       │        │           │              │
                     HTTP      AMQP     gRPC/Kafka/NATS/… │
                       │        │           │   (plug-in)  │
                       ▼        ▼           ▼
                    integration adapters (independent processes)
```

**yggdrasil-core** is a single Go binary that hosts:

- The HTTP API (REST, `/api/v1/...`) — the public surface for the CLI,
  surfaces, and every integration-caller.
- The workflow engine that dispatches steps in order.
- The manifest repository (reads and versioned writes against Postgres).
- The third-party auth provider registry.
- The addons registry (startup hooks: postgres, HTTP, RPC transport
  backends, first run, scheduler, cleaner, reconciler).

**Postgres** is the single source of truth for all state: manifests,
sessions, events, identities, guardian approvals. The outbox table
(`event_log`) feeds downstream consumers. This is the one
infrastructure dependency that is always required.

**Transport** is how the core reaches adapters. It is **pluggable** —
every call goes through the `rpc.Transport` interface, declared per
`integration_type` in its manifest. Backends shipped with the core:

- `http_json` — HTTP request/response.
- `rabbitmq` — AMQP request/response (0-9-1).

Any other transport (gRPC, Kafka, NATS, SQS, Pub/Sub) plugs in as a
small switch-case extension implementing `rpc.Transport`. See
[features/transports.md](./features/transports.md).

A single deployment can mix transports simultaneously — one adapter
may use HTTP, another AMQP, another gRPC; the core dispatches each
through the transport its `integration_type` declares.

**Integration adapters** are independent processes (typically
Kubernetes workloads) that implement the `rpc.Transport` their
`integration_type` declares. They deploy into the adopter's
infrastructure and are installed via `yggdrasil install`.

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
     adapter via whichever `rpc.Transport` the integration_type
     declares, records the result.
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

The HTTP API handlers, any RPC transport consumer (the `manifest.create`
handler is exposed through whichever `rpc.Transport` backends the
deployment registers), and the workflow step
`kind=yggdrasil, operation=apply_manifest` all funnel into the same
helper (`controllers/message/manifest_persist.go`). This is the single
code path that guarantees every manifest write emits an event,
regardless of which transport or interface delivered the request.

## Deployment options

### Seed — Docker Compose (dev, CI, small self-hosted)

`docker-compose.standalone.yml` brings up Postgres + yggdrasil-core +
the two bootstrap adapters (integration-kubernetes,
integration-schema-migrations) with random passwords and first-run
bootstrap. `yggdrasil init` automates the whole thing. Good for
laptops, demos, CI, and single-host self-hosted deployments.

### Kubernetes (production) — via `yggdrasil deploy control-plane`

Production Kubernetes install is manifest-first: write a
`control_plane` manifest declaring image/replicas/Postgres/ingress/
transports and apply it through the seed with
`yggdrasil deploy control-plane`. The seed's
`yggdrasil-deploy-control-plane` workflow renders the desired K8s
objects via internal/controlplane and applies them through
integration-kubernetes. No Helm chart. See [deployment.md](./deployment.md)
for the full runbook.

A future Kubernetes Operator (roadmap) watches `control_plane`
manifests and reconciles them continuously — same shape as the
deploy workflow, event-driven instead of one-shot.

### Custom / bare-metal

yggdrasil-core is a single binary. Point `DB_*` at your Postgres, run
`goose up` once to migrate the schema, then run the binary. Each
`rpc.Transport` backend is its own addon — enable the ones you need
via their env vars (each transport docs its own config). The rest —
first-run bootstrap, TLS termination, ingress — is whatever the
operator wires up externally.

## Scale and failure model

yggdrasil-core is horizontally scalable; every request is stateless
apart from the DB. A typical production deployment runs 2-3 replicas
behind a service.

DB failure takes the whole control plane down (Postgres is the only
mandatory dependency). Transport failures are scoped per backend — if
one `rpc.Transport` is unhealthy, integrations that declared that
transport fail at dispatch while integrations on other transports keep
working. Individual dispatches surface as "adapter unreachable" on the
affected step; the rest of the workflow proceeds. Transports that
support reconnect (the AMQP backend uses `ReliableConnection` from the
`commons` package) absorb short outages transparently.

No transport failure corrupts state. The catalog is safe; at most you
have a handful of `workflow_run` rows in `running` status to reconcile
after recovery — see
[operations/incident-response.md](./operations/incident-response.md).
