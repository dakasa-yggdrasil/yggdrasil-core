# Yggdrasil Reconciler — Secret Materializer

**Date:** 2026-04-12
**Status:** Approved
**Scope:** Add a reconciliation engine to yggdrasil-core that materializes managed secrets as Kubernetes native Secrets. Secrets is the first adapter; the interface is generic for future resource kinds.

## Context

Yggdrasil is the single control plane for the DaKasa platform. It already stores managed secrets in PostgreSQL with full CRUD, versioning, rotation, and namespacing. External services (Stripe, EFI, GCS, Firebase, SES, etc.) require credentials injected as K8s Secrets.

Currently there is no bridge between Yggdrasil's managed secrets and K8s. The External Secrets Operator was considered but rejected — Yggdrasil itself should be the operator that "connects the realms."

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Trigger model | Hybrid — reactive on create/update + periodic reconcile loop | Immediate propagation on writes; reconcile loop catches drift and crash recovery |
| Scope | Generic interface, secrets as first adapter | Minimal upfront cost for the interface; avoids rewrite when Products/RBAC materialize later |
| Cluster access | In-cluster default + kubeconfig from managed secrets for remotes | Local cluster works out-of-the-box; remotes added by storing kubeconfig as managed secret |
| Naming convention | Yggdrasil ns/name = K8s ns/name by default; override via metadata.materialize | Zero config for common case, escape hatch for exceptions |
| Delete lifecycle | Mark K8s Secret with annotation on revoke/disable, do not delete | Avoids killing running pods; operator decides when to remove |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   yggdrasil-core                     │
│                                                      │
│  ┌────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │  HTTP API  │───▶│  Reconciler  │───▶│ KubeClient│ │
│  │ (secrets)  │    │  Engine      │    │ Pool      │ │
│  └────────────┘    │              │    │           │ │
│                    │ - on change  │    │ local     │ │
│  ┌────────────┐    │ - every 60s  │    │ remote(s) │ │
│  │ PostgreSQL │◀───│ - per-kind   │    └──────────┘ │
│  │ (source of │    └──────────────┘                  │
│  │  truth)    │                                      │
│  └────────────┘                                      │
└─────────────────────────────────────────────────────┘
```

## Generic Interface

```go
// Materializer converts a Yggdrasil resource into Kubernetes objects.
type Materializer interface {
    // Materialize pushes one resource to the target cluster.
    Materialize(ctx context.Context, target KubeTarget, resource any) error

    // Reconcile syncs all resources of this kind, returns a summary.
    Reconcile(ctx context.Context, target KubeTarget) (ReconcileResult, error)

    // Owns returns a string identifying what this materializer manages (e.g. "secrets").
    Owns() string
}
```

Future materializers (Products, RBAC, Policies) implement this same interface.

## KubeTarget

```go
type KubeTarget struct {
    Name    string                    // "local" or integration instance name
    Client  kubernetes.Interface      // cached client
    IsLocal bool
}
```

- **Local**: `rest.InClusterConfig()` at startup. Zero config.
- **Remote**: kubeconfig read from managed secret `global/kubeconfig-{name}`. Client cached with 5-minute TTL.

## Secret Materializer Flow

### Reactive (on write)

1. `POST /api/v1/secrets` → upsert in PostgreSQL (existing code)
2. If `status=active`, call `secretMaterializer.Materialize()` inline
3. Resolve target: `metadata.materialize.target` or default `"local"`
4. Resolve K8s ns/name: `metadata.materialize.namespace` / `metadata.materialize.name`, fallback to managed secret's own ns/name
5. Create or update K8s Secret with:
   - `data`: managed secret `.Data` (base64-encoded by K8s client)
   - Label: `yggdrasil.io/managed-by: yggdrasil-core`
   - Annotations: `yggdrasil.io/secret-version`, `yggdrasil.io/source-namespace`, `yggdrasil.io/source-name`, `yggdrasil.io/last-synced`
6. Return materialization result in HTTP response

### Reconciliation loop

1. Goroutine started at server boot. Interval: `RECONCILE_INTERVAL` env (default 60s).
2. List all managed secrets where `status=active`.
3. For each, check K8s Secret:
   - If absent → create
   - If present but `yggdrasil.io/secret-version` annotation differs → update
   - If present and version matches → skip
4. Log drift detected (created/updated counts).
5. Only touches K8s Secrets with label `yggdrasil.io/managed-by: yggdrasil-core` — never deletes, never modifies unmanaged secrets.

### On revoke/disable

1. `POST /api/v1/secrets/{ns}/{name}/revoke` or `/disable` (existing code)
2. After DB update, patch K8s Secret annotations:
   - `yggdrasil.io/status: revoked` or `disabled`
   - `yggdrasil.io/revoked-at: <timestamp>`
3. Do NOT delete the K8s Secret — operator decides when to remove.

## K8s Secret Shape

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dakasa-hall-secrets
  namespace: dakasa
  labels:
    yggdrasil.io/managed-by: yggdrasil-core
  annotations:
    yggdrasil.io/secret-version: "3"
    yggdrasil.io/source-namespace: dakasa
    yggdrasil.io/source-name: dakasa-hall-secrets
    yggdrasil.io/last-synced: "2026-04-12T17:30:00Z"
type: Opaque
data:
  DATABASE_URL: <base64>
  BROKER_URL: <base64>
  STRIPE_API_KEY: <base64>
```

## New HTTP Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/secrets/{ns}/{name}/materialize` | Materialize one secret immediately |
| `POST` | `/api/v1/secrets/materialize-all` | Materialize all active secrets |
| `GET` | `/api/v1/reconciler/status` | Last reconcile timestamp, counts, errors |

## New Files

```
reconciler/
  types.go            — Materializer interface, KubeTarget, ReconcileResult
  kubeclient.go       — KubeClientPool (local InCluster + remote from managed secrets)
  secret_adapter.go   — SecretMaterializer implements Materializer
  loop.go             — Reconciliation goroutine (periodic + event channel)
  handler.go          — HTTP handlers for materialize endpoints
```

## New Dependencies

```
k8s.io/client-go     — Kubernetes API client
k8s.io/api           — K8s object types (corev1.Secret)
k8s.io/apimachinery  — meta types, schema, labels
```

## RBAC

ServiceAccount `yggdrasil` needs a ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: yggdrasil-reconciler
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: yggdrasil-reconciler
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: yggdrasil-reconciler
subjects:
  - kind: ServiceAccount
    name: yggdrasil
    namespace: dakasa
```

ClusterRole (not namespaced Role) because Yggdrasil materializes secrets across namespaces (dakasa, infra).

## Integration with Existing Code

- `handleManagedSecretCreate` — after `repository.UpsertManagedSecret()`, call `reconciler.MaterializeSecret()`
- `handleManagedSecretRotate` — after rotate, call `reconciler.MaterializeSecret()`
- `handleManagedSecretDisable` / `handleManagedSecretRevoke` — after DB update, call `reconciler.MarkSecret()`
- `NewServer()` — start reconcile loop goroutine, initialize KubeClientPool
- `Server` struct — add `reconciler *reconciler.Engine` field

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `RECONCILE_INTERVAL` | `60s` | Reconciliation loop period |
| `RECONCILE_ENABLED` | `true` | Enable/disable the reconcile loop |
| `KUBE_IN_CLUSTER` | `true` | Use in-cluster config for local target |

## Testing

- Unit tests: mock `kubernetes.Interface` via `k8s.io/client-go/kubernetes/fake`
- Integration test: verify managed secret → K8s Secret round-trip
- Reconcile test: create managed secret, delete K8s Secret, verify reconcile recreates it

## Out of Scope

- Multi-cluster remote targets (interface supports it, but no adapter yet — only local target implemented)
- Product/RBAC/Policy materializers (future — same Materializer interface)
- AWS Secrets Manager sync (Yggdrasil IS the source of truth, not AWS SM)
- Encryption at rest for managed secrets in PostgreSQL (future concern)
