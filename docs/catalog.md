# Integration catalog

All the `integration-*` repos that ship with Yggdrasil, in the order
you are most likely to install them. Each row names the family, the
providers implementing it, a short description, and the install
command.

## Core infrastructure

### kubernetes

**Family**: deploy and observe Kubernetes objects.
**Providers**: `kubernetes` (server-side apply via client-go).
**When to install**: first. Most other integrations deploy their
adapter pods as Kubernetes workloads.

```sh
yggdrasil install dakasa-yggdrasil/integration-kubernetes --provider kubernetes
```

Operations: `declarative_apply`, `apply_manifest`, `observe_objects`.

### secrets-management

**Family**: store, rotate, and fetch secrets.
**Providers**: `aws-secrets-manager`, `gcp-secret-manager`.
**When to install**: before anything that needs credentials pulled
from a managed store (most adapters for production).

```sh
yggdrasil install dakasa-yggdrasil/integration-secrets-management --provider aws-secrets-manager
```

Operations: `describe_secret`, `create_secret`, `update_secret`,
`rotate_secret`, `destroy_secret`.

### schema-migrations

**Family**: versioned, checksum-guarded SQL migrations.
**Providers**: `goose-postgres` (via `github.com/pressly/goose`).
**When to install**: when you want workflows to manage database
schemas declaratively.

```sh
yggdrasil install dakasa-yggdrasil/integration-schema-migrations --provider goose-postgres
```

Operations: `apply_migrations_spec`, `describe_applied_migrations`,
`rollback_migration`.

### database-admin

**Family**: declarative database / role / grant management.
**Providers**: `postgres-admin`.
**When to install**: alongside schema-migrations when you want
workflows to create databases and rotate roles.

```sh
yggdrasil install dakasa-yggdrasil/integration-database-admin --provider postgres-admin
```

Operations: `ensure_database`, `ensure_role`, `revoke_role`,
`drop_database`.

## Messaging

### rabbitmq

**Family**: queue, exchange, binding, vhost management.
**Providers**: `runtime` (AMQP-level ops), `topology` (declarative
exchanges/queues), `kubernetes` (deploy a RabbitMQ cluster via
operator).

```sh
yggdrasil install dakasa-yggdrasil/integration-rabbitmq --provider topology
```

Operations (topology): `describe_topology`, `apply_topology_spec`.

## Observability

### grafana

**Family**: dashboard, alert, datasource, folder management.
**Providers**: `runtime` (Grafana API ops), `kubernetes` (deploy
Grafana via operator).

```sh
yggdrasil install dakasa-yggdrasil/integration-grafana --provider runtime
```

Operations: `ensure_folder`, `ensure_dashboard`, `ensure_datasource`,
`delete_dashboard`.

## Cloud providers

### aws

**Family**: generic AWS resource management (the family is the
contract; the provider picks the service).
**Providers**: tbd (AWS subservices will land as separate providers).

```sh
yggdrasil install dakasa-yggdrasil/integration-aws
```

### gcp

**Family**: generic GCP resource management.
**Providers**: tbd.

## Source control / CI

### github

**Family**: dispatch GitHub Actions workflows, read PR state,
manage repos.
**Providers**: `github` (REST API).

```sh
yggdrasil install dakasa-yggdrasil/integration-github --provider github
```

Operations: `dispatch_workflow`, `list_workflow_runs`,
`describe_workflow_run`.

## Guardian

### heimdall

**Family**: approval workflow for high-blast-radius changes.
**Providers**: `heimdall` (core-owned guardian).

```sh
yggdrasil install dakasa-yggdrasil/integration-heimdall --provider heimdall
```

Operations: `request_approval`, `describe_approval`, `record_decision`.

## Writing your own

Create a new repo from the `integration-template`:

```sh
git clone https://github.com/dakasa-yggdrasil/integration-template my-integration
```

The template ships with:

- `controllers/message/` — AMQP RPC handlers.
- `internal/adapter/spec.go` — where you define operations.
- `docs/` — YAML quickstart scaffolding.

Read `AGENTS.md` in the template for the full walkthrough.
