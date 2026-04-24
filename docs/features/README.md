# Features

Each Yggdrasil feature has its own deep-dive page in this directory.
The pages cover the concept, the wire shape, the evaluation rules, and
the operational gotchas — enough that a new operator can run the
feature in production without reading the source.

## Index

| Feature | Page | One-line summary |
|---|---|---|
| **Manifests** | [manifests.md](./manifests.md) | Versioned, checksum-guarded, event-emitting documents that hold every piece of platform state. |
| **Workflows** | [workflows.md](./workflows.md) | DAG engine with template rendering, retry, per-step audit, three execution kinds. |
| **Integrations** | [integrations.md](./integrations.md) | Family/type/instance/provider model, AMQP contract, install flow. |
| **RBAC** | [rbac.md](./rbac.md) | Subject-action-resource roles + bindings with effective-subject expansion. |
| **Policy** | [policy.md](./policy.md) | Runtime conditions over arbitrary input, deny precedence, audit traces. |
| **Sessions & OAuth/OIDC** | [sessions.md](./sessions.md) | Password + third-party identity, state signing, auto-link by email. |
| **Events & audit** | [events.md](./events.md) | Typed, transactionally emitted stream. Outbox tail. |
| **Surfaces** | [surfaces.md](./surfaces.md) | Replaceable UI/API edges that consume the core's contracts. |
| **Products** | [products.md](./products.md) | Versioned bundles with renderer + target + reconcile. |
| **Secrets** | [secrets.md](./secrets.md) | Managed-secret rotation, `secret://` references, pluggable backends. |

## How to read these pages

Every page follows the same shape:

- **What it is** — one paragraph + a diagram.
- **How it works** — the moving parts, with file references when
  relevant.
- **Wire shape** — request/response or manifest skeleton.
- **Evaluation rules** — what the engine does when it processes the
  feature.
- **Operate it** — what to monitor, what to back up, what fails
  loudly.
- **Pitfalls** — mistakes the team has actually seen.
