# Core concepts

Yggdrasil is a control plane for declarative workflows that call out
to third-party integrations. Everything — the workflows, the
integrations, the products they form, the permissions — is a
**manifest**, versioned, validated, and stored in a single Postgres.

This document names every concept you need to know to read, write,
and operate Yggdrasil.

## Manifests

A manifest is a YAML or JSON document with:

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: <kind>
metadata:
  name: <slug>
  namespace: <namespace>
  labels: {}
spec:
  <kind-specific fields>
```

The shape mirrors Kubernetes intentionally — it is the pattern most
teams recognize. Unlike k8s, Yggdrasil versions every write: applying
a manifest with changes creates a new version, skipping is
checksum-based, and the history is queryable.

### Supported kinds

| Kind | Purpose |
|---|---|
| `integration_family` | Interface contract (operations, shared schemas) shared by many providers |
| `integration_type` | Concrete implementation of a family (kubernetes, aws, github) |
| `integration_instance` | Deployed configuration of a type (credentials, cluster, project) |
| `integration_quickstart` | Adopter-facing "install this with one command" manifest |
| `product` | Group of integrations/workflows shipped together |
| `workflow` | Step-by-step pipeline of operations across integrations |
| `surface` | UI/console that renders subsets of the platform |
| `rbac` | Access-control subject-verb-resource policy |
| `policy` | Runtime policy (rate limits, data residency, etc.) |
| `repository_binding` | Link a source repo to an integration or product |
| `guardian_policy` / `guardian_approval` / `guardian_memory` | Approval workflow and its history |
| `remediation_bundle` / `remediation_contract` | Incident response workflow pieces |
| `resource` | Tracked entity discovered in an integration (a S3 bucket, a Slack channel) |

## Integrations: family, type, instance, provider

The four-layer model is what keeps integrations both flexible and
composable.

1. **Family** defines the *contract*. Example: `schema-migrations`
   says "any implementation exposes `apply_migrations_spec`,
   `describe_applied_migrations`, and `rollback_migration` with these
   input and output shapes". It does not decide how.

2. **Type** is one concrete implementation of a family. Example:
   `schema-migrations-goose-postgres` implements `schema-migrations`
   using `github.com/pressly/goose` against a PostgreSQL DSN. The
   type declares its adapter (queues for AMQP transport, HTTP
   endpoints for HTTP transport, or the equivalent for any other
   registered `rpc.Transport` — see
   [features/transports.md](./features/transports.md)), credential
   schema, and capability set.

3. **Instance** is one deployed configuration of a type. Example: an
   instance of `schema-migrations-goose-postgres` configured with the
   DSN for your staging database. Multiple instances of the same type
   can coexist (one per environment, one per tenant).

4. **Provider** is the generic label adopters use when referring to
   "which implementation of the family" without pinning to a type
   id. Example: inside a quickstart, `--provider goose-postgres` picks
   the provider, and the install flow resolves it to the concrete
   type.

When a workflow step says:

```yaml
use:
  kind: integration
  family: schema-migrations
  operation: apply_migrations_spec
```

the engine resolves family → active type → active instance at
runtime, dispatches the operation through the adapter (over whichever
transport the integration_type declares — HTTP, AMQP, or a pluggable
backend; see [features/transports.md](./features/transports.md)),
and records the step result.

## Workflows and steps

A workflow is a DAG of steps. Each step declares what to call (the
`use` block) and what to pass (the `with` block), plus optional
`depends_on`, `condition`, and `retry`. The engine renders templates
(`{{ inputs.X }}`, `{{ steps.<id>.metadata.<key> }}`) against
runtime inputs before executing the step.

Three step kinds exist today:

- `kind: integration` — dispatch to an integration adapter over the
  transport declared in its `integration_type` (HTTP / AMQP / any
  registered `rpc.Transport` — see [features/transports.md](./features/transports.md)).
- `kind: product` — run a product lifecycle operation (apply,
  observe, uninstall) in-process.
- `kind: yggdrasil` — persist a manifest against the core itself
  in-process. Used by `integration_quickstart` steps to register the
  freshly-installed `integration_instance`.

## integration_quickstart and `yggdrasil install`

A quickstart is a manifest that packages "everything an adopter needs
to start using this integration" — required inputs, target providers,
the Kubernetes objects the adapter pod needs, the integration_instance
to create, plus a smoke test. `yggdrasil install <repo_ref>` fetches
that manifest from GitHub, runs the interactive TUI to collect the
adopter's inputs, and POSTs the whole thing to the server. The server
compiles a workflow and dispatches it. The result is one command,
one form, full install.

## Bootstrap and first-run

On a fresh Postgres, `yggdrasil-core` creates its first admin and
seeds the baseline integration catalog — only when the `YGGDRASIL_
BOOTSTRAP_*` env vars are set and the collaborators table is empty.
This is the gate that makes `yggdrasil init` work as a one-command
bootstrap but still protects a running deployment from accidental
resets.

## Sessions, RBAC, policies

Every operation runs under a session. Sessions are issued by
`/api/v1/auth/login` (password) or
`/api/v1/auth/third-party/start/<provider>` (OAuth/OIDC). Every
write passes through RBAC evaluation (`rbac` manifests) and then
through policy evaluation (`policy` manifests) before landing in the
target repository. Audit events are written to the `event_log` table
and are consumable from the outbox.

## Events

Every state change emits a typed event (`manifest.created`,
`workflow.run.succeeded`, `authorization.denied`, …). Events are
written transactionally with the state change, so a consumer watching
the outbox sees exactly what happened. Integrations, dashboards, and
external systems are all downstream of this stream.
