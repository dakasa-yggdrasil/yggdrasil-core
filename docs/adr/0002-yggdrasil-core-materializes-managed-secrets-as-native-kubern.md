# ADR-0002: yggdrasil-core materializes managed secrets as native Kubernetes Secrets via a built-in reconciler (no External Secrets Operator)

- **Status:** Accepted
- **Date:** 2026-04-12
- **Deciders:** unknown
- **Scope:** yggdrasil-core (reconciler engine, cluster-facing)
- **Supersedes:** —
- **Superseded by:** —

## Context

Yggdrasil is the single control plane for the DaKasa platform and already stores managed secrets in PostgreSQL with full CRUD, versioning, rotation, and namespacing. External services (Stripe, EFI, GCS, Firebase, SES, etc.) need those credentials injected as native Kubernetes Secrets for pods to consume, but no bridge existed between Yggdrasil's managed secrets and the cluster. The External Secrets Operator — a standard off-the-shelf solution for this exact problem — was considered and rejected: Yggdrasil is meant to be the operator that "connects the realms," and introducing ESO would mean the platform's single control plane no longer owns the last mile of its own secret distribution.

## Decision

Build a generic reconciliation engine directly into yggdrasil-core:

- Define a `Materializer` interface (`Materialize`, `Reconcile`, `Owns`) as the extension point; `SecretMaterializer` is the first (not only intended) implementation, targeting `corev1.Secret`. Future resource kinds (Products, RBAC, Policies) can plug into the same engine without a rewrite.
- **Hybrid trigger model:** reactive materialization fires inline on every managed-secret create/rotate/disable/revoke (`materializeAfterWrite` → non-blocking channel send, immediate propagation), plus a periodic `Engine.Run` reconcile loop (default 60s, `RECONCILE_INTERVAL` env) that catches drift or an out-of-band deleted Secret — reactive alone can't heal a K8s Secret deleted out-of-band or recover from a crash.
- **Cluster access via `KubeClientPool`:** the local target uses `rest.InClusterConfig()` with zero config; remote clusters are added purely by storing a kubeconfig as a managed secret (`global/kubeconfig-{name}`), cached 5 minutes — multi-cluster stays "Yggdrasil is the source of truth" without new infra.
- **Naming:** Yggdrasil `namespace/name` maps 1:1 to K8s `namespace/name` by default; `metadata.materialize.{target,namespace,name}` on the managed secret is an explicit override escape hatch (e.g. to materialize a `global`-namespace secret into a service-specific K8s Secret name) — zero config for the common case.
- **Non-destructive delete lifecycle:** on `revoked`/`disabled` status the K8s Secret is annotated (`yggdrasil.io/status`, `yggdrasil.io/revoked-at`) but never deleted — removing a live Secret out from under running pods is judged worse than leaving a stale-but-marked one; an operator decides when to physically remove it.
- **Ownership scoping:** every managed Secret carries label `yggdrasil.io/managed-by: yggdrasil-core`; the reconciler only ever reads/writes/marks Secrets carrying that label, never touching unmanaged Secrets in the same namespace. Version convergence is tracked via annotation `yggdrasil.io/secret-version`, compared against the managed secret's `Version` to decide create/update/skip.
- New endpoints: `POST /api/v1/secrets/{ns}/{name}/materialize` (force one), `POST /api/v1/secrets/materialize-all`, `GET /api/v1/reconciler/status`.
- RBAC is a cluster-scoped `ClusterRole`/`ClusterRoleBinding` (not namespaced), because materialization crosses namespaces (`dakasa`, `infra`, etc.) by design. The reconciler addon is optional/non-fatal — if Postgres or the in-cluster kube client aren't available, Yggdrasil still starts, just without materialization.

## Consequences

- Yggdrasil-core's blast radius now includes direct cluster-wide `client-go` write access to Secrets — a reconciler bug is a cluster-wide secret-integrity risk, not scoped to one namespace.
- Non-destructive deletes mean K8s Secret count only grows over a managed secret's lineage unless an operator manually prunes revoked/disabled ones — there is no automatic garbage collection.
- Remote multi-cluster targets are architecturally supported (`KubeTarget.IsLocal=false` + kubeconfig-as-managed-secret) but explicitly **not implemented/exercised** beyond the local in-cluster path at decision time — remote is a stub in the interface, not a working path.
- Any future resource kind needing cluster materialization (Products, RBAC, Policies) has a ready-made `Materializer` interface to implement, at the cost of a slightly more abstract `Materializer`/`KubeTarget` layer than a secrets-only implementation would need.
- Encryption at rest for managed secrets in PostgreSQL, and syncing to AWS Secrets Manager, are both explicitly out of scope — Yggdrasil is treated as the source of truth, not a mirror of AWS SM.

## Related
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/plans/2026-04-12-reconciler-secret-materializer.md`
- scratch: `/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-04-12-reconciler-secret-materializer-design.md`
