# Manifests

The manifest is the unit of platform state in Yggdrasil. Every concept
— a workflow definition, an integration, an RBAC role, an OAuth
provider, a policy, a product, a surface — is a versioned YAML or JSON
document persisted in Postgres.

## What it is

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: <kind>
metadata:
  name: <slug>
  namespace: <namespace>          # default "global"
  description: <free-form text>
  labels:                         # arbitrary catalog discovery labels
    yggdrasil.io/catalog-domain: ...
spec:
  <kind-specific shape>
```

When you `apply` it, the core:

1. **Normalizes** (lowercase the kind/name, default the namespace,
   trim whitespace).
2. **Validates** kind-specific spec (workflow steps, RBAC rules,
   policy conditions, etc.).
3. **Checksums** the normalized document deterministically.
4. **Skips if identical** — same `(kind, namespace, name, checksum)`
   tuple → no new version, no event.
5. **Otherwise persists** a new row in `manifest_version` (immutable),
   updates the active pointer in `manifest`, and emits a
   `manifest.created` event in the same transaction.

## Wire shape

### POST /api/v1/manifests?kind=<kind>

```json
{
  "name": "deploy-service",
  "namespace": "global",
  "description": "Deploy a service through CI",
  "labels": { "owner": "platform" },
  "spec": { /* kind-specific */ }
}
```

Response:

```json
{
  "manifest": {
    "id": "01935e3d-...",
    "kind": "workflow",
    "metadata": {
      "name": "deploy-service",
      "namespace": "global",
      "active": true,
      "labels": { "owner": "platform" }
    },
    "version": 7,
    "checksum": "sha256:..."
  }
}
```

The CLI's `yggdrasil apply -f file.yaml` is a thin wrapper that POSTs
the same shape — multi-doc YAML supported via `---` separators.

### GET /api/v1/manifests?kind=<kind>&namespace=<ns>&name=<name>

Returns `{ "manifests": [...] }` filtered by query params. The CLI's
`yggdrasil get <kind>` uses this directly. Single-result lookups (when
both `namespace` and `name` are set) are how `describe` works.

## Supported kinds

The core today supports these kinds — each has its own deep-dive
elsewhere in this directory:

- `rbac` — see [rbac.md](./rbac.md)
- `policy` — see [policy.md](./policy.md)
- `integration_family`, `integration_type`, `integration_instance`,
  `integration_quickstart` — see [integrations.md](./integrations.md)
- `workflow` — see [workflows.md](./workflows.md)
- `surface` — see [surfaces.md](./surfaces.md)
- `product` — see [products.md](./products.md)
- `resource`, `repository_binding` — used by integrations to register
  discovered entities
- `guardian_policy`, `guardian_approval`, `guardian_memory`,
  `remediation_bundle`, `remediation_contract` — first-class
  manifest kinds for governed approval / remediation flows. The
  core owns the contracts; whichever guardian integration an
  adopter installs owns the closed-loop sweep. Reference
  implementation: Heimdall (commercial — see
  [catalog.md](../catalog.md#guardian-integrations))

## How versioning works

Two tables back this:

- `manifest` — one row per `(kind, namespace, name)`. Holds
  `id`, `active`, and pointers to the latest active version.
- `manifest_version` — append-only row per write. Holds the
  full document JSON, the version number (monotonic per manifest),
  the checksum, and the timestamps.

The active pointer is what readers see by default. Old versions remain
queryable via `?version=N` on the read endpoints — so a roll-back is
literally a re-apply of an older spec, which writes a new version
identical in content to the older one.

The checksum-skip rule means apply is naturally idempotent: re-applying
the same YAML in CI is free.

## Operate it

**Monitor:**

- `manifest.created` event rate per kind. Sudden spikes often mean a
  loop in CI / GitOps reconciler.
- Postgres table sizes for `manifest_version` (grows monotonically) —
  see [operations/scaling.md](../operations/scaling.md) for archival.
- Failed `manifest.create` AMQP messages (when the AMQP path is in
  use). Validation failures are loud.

**Back up:**

Both `manifest` and `manifest_version` are part of the standard
Postgres backup. See
[operations/backup-restore.md](../operations/backup-restore.md).

**Fails loudly when:**

- A spec violates kind-specific validation (e.g. a workflow step with
  an unknown `kind`). Surfaces as an HTTP 400 + structured error;
  the apply does NOT silently succeed.
- A required dependency is missing (e.g. an `integration_instance`
  references a `type_ref` that does not exist). The check happens at
  read time, not write time, so referential integrity bugs surface
  during workflow runs — not on apply.

## Pitfalls

- **Don't store secrets in `spec`.** Use `credentials_ref:
  secret://...` and store the actual value as a managed secret. See
  [secrets.md](./secrets.md).
- **Namespace isn't a tenant.** Yggdrasil namespaces group related
  manifests (e.g. `prod`, `staging`); they don't isolate compute or
  network. Multi-tenant deployments use multiple cores or a
  policy-driven RBAC model — see
  [operations/multi-environment.md](../operations/multi-environment.md).
- **Labels are catalog metadata, not query filters.** They appear in
  list responses but are not indexed. Don't build runtime logic that
  scans labels at request time.
- **Apply order matters for first-time setup.** A `workflow` that
  references a `family: kubernetes` will validate even if the family
  isn't seeded yet — the family lookup happens at *run* time. So
  apply families/types before instances before workflows that use
  them, in that order.
