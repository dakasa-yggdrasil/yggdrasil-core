# End-to-end walkthrough: self-hosted Yggdrasil against a kind cluster

This runbook walks through the full bootstrap + deploy flow on a local
machine, from empty filesystem to a yggdrasil-core control plane
running inside a kind Kubernetes cluster that was itself deployed by
the seed control plane. It is the canonical validation of everything
Fases 1-5 + 7-9 built: the seed compose, the `control_plane` manifest
kind, the renderer, the deploy workflow, the `yggdrasil deploy` CLI.

Expected duration on a warm machine: **8-12 minutes**.

## Prerequisites

- **macOS or Linux host** with at least 4 GB free RAM and 10 GB disk.
- **Docker daemon** (Docker Desktop, colima, orbstack). On macOS:
  `brew install colima && colima start --cpu 4 --memory 8`.
- **kind** — `brew install kind` (macOS) or
  `go install sigs.k8s.io/kind@latest`.
- **kubectl** — `brew install kubectl` or ship with kind.
- **yggdrasil CLI** — build from this repo:
  `go install github.com/dakasa-yggdrasil/yggdrasil/cmd/yggdrasil@latest`.

Verify:

```sh
docker version --format '{{.Server.Version}}'    # any recent version works
kind version
kubectl version --client
yggdrasil version
```

## Step 1 — Spin up a kind cluster

```sh
kind create cluster --name yggdrasil-e2e
kubectl cluster-info --context kind-yggdrasil-e2e
```

This is the cluster the **production** control plane will land in.
Not the seed — the seed still lives in docker compose.

`kubectl get nodes` should show one node: `yggdrasil-e2e-control-plane`
in `Ready` state.

## Step 2 — Bring up the seed

```sh
mkdir -p ~/yggdrasil-e2e && cd ~/yggdrasil-e2e
yggdrasil init
```

What `yggdrasil init` does, step by step:

1. Writes `./yggdrasil/docker-compose.yml` + `./yggdrasil/.env` with
   random passwords.
2. `docker compose up -d` brings up postgres + yggdrasil-core +
   integration-kubernetes + integration-schema-migrations. All four
   services run HTTP-only by default (no broker).
3. Waits for `http://localhost:9080/readyz` to be green (~10s).
4. Logs in as the bootstrap admin, persists a context named `local`
   in `~/.yggdrasil/config.yaml`.
5. POSTs the two topology-specific `integration_instance` manifests
   (`yggdrasil-core-kubernetes`, `yggdrasil-core-schema-migrations`).

You should see a banner with the generated admin password. Save it
somewhere — the seed's events + manifests are behind that login.

**Validation:**

```sh
yggdrasil status                          # expect health=ok, ready=ok
yggdrasil get integration_instance        # expect 2 entries
```

## Step 3 — Register the kind cluster as an integration_instance

The seed's `integration-kubernetes` adapter talks to a cluster via a
kubeconfig. The standalone compose mounts `~/.kube/config` into the
adapter container, but inside the container that path is
`/root/.kube/config`. We need a second `integration_instance`
pointing at the kind cluster context specifically.

```yaml
# kind-cluster.yaml
apiVersion: yggdrasil.io/v1alpha1
kind: integration_instance
metadata:
  name: kind-yggdrasil-e2e
  namespace: global
  description: kind cluster used for the E2E walkthrough.
spec:
  type_ref:
    namespace: global
    name: kubernetes
  endpoint: http://integration-kubernetes:8081
  config:
    in_cluster: false
    kubeconfig_path: /root/.kube/config
    context: kind-yggdrasil-e2e
    default_namespace: yggdrasil
    field_manager: yggdrasil
```

```sh
yggdrasil apply -f kind-cluster.yaml
```

**Validation:** the adapter's describe-handshake should now include
the new instance.

```sh
yggdrasil describe integration_instance kind-yggdrasil-e2e
```

## Step 4 — Define the control_plane manifest

```yaml
# control-plane.yaml
apiVersion: yggdrasil.io/v1alpha1
kind: control_plane
metadata:
  name: e2e
  namespace: global
spec:
  image: ghcr.io/dakasa-yggdrasil/yggdrasil-core:latest
  replicas: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      memory: 512Mi
  postgres:
    mode: bundled
    bundled:
      storage: 1Gi
  ingress:
    enabled: false
  kubernetes:
    namespace: yggdrasil
    cluster_ref:
      namespace: global
      name: kind-yggdrasil-e2e
```

Storage `1Gi` is deliberately tiny for kind. No Ingress — we port-
forward directly to the core Service once it's up.

## Step 5 — Deploy

```sh
yggdrasil deploy control-plane -f control-plane.yaml \
  --kubernetes-instance kind-yggdrasil-e2e
```

This applies the manifest, dispatches the
`yggdrasil-deploy-control-plane` workflow, and prints each step as it
completes. Expected output (elapsed time in italics):

```
✓ applied control_plane global/e2e
→ dispatching workflow yggdrasil-deploy-control-plane
workflow status: succeeded
  ✓ render                                succeeded  (control_plane.render)
  ✓ apply-infra                           succeeded  (declarative_apply)
  ✓ wait-infra                            succeeded  (observe_objects)
  ✓ migrate                               succeeded  (apply_migrations_spec)
  ✓ apply-core                            succeeded  (declarative_apply)
  ✓ wait-core                             succeeded  (observe_objects)
```

Total wall time: 3-5 minutes on a kind cluster with warm image cache.
First run pulls images — add 2-3 min.

## Step 6 — Verify the production control plane is alive

```sh
kubectl --context kind-yggdrasil-e2e get all -n yggdrasil
```

Expected:

```
NAME                                   READY   STATUS    RESTARTS   AGE
pod/yggdrasil-postgres-0               1/1     Running   0          2m
pod/yggdrasil-core-7d...               1/1     Running   0          1m

NAME                         TYPE        CLUSTER-IP      PORT(S)
service/yggdrasil-postgres   ClusterIP   None            5432/TCP
service/yggdrasil-core       ClusterIP   10.96.X.X       9080/TCP

NAME                            READY
deployment.apps/yggdrasil-core  1/1

NAME                                      READY
statefulset.apps/yggdrasil-postgres       1/1
```

Port-forward the production core:

```sh
kubectl --context kind-yggdrasil-e2e -n yggdrasil \
  port-forward svc/yggdrasil-core 9090:9080
```

In another terminal:

```sh
curl http://localhost:9090/readyz    # should return "ready"
```

The production control plane is now an **independent** yggdrasil-core
with its own Postgres, reachable on :9090. The seed on :9080 is still
running — it's what you'd keep around to reconcile control-plane
changes over time.

## Step 7 — Repeat the apply to prove idempotence

Edit `control-plane.yaml` bumping `spec.replicas` from 1 → 2, then:

```sh
yggdrasil deploy control-plane -f control-plane.yaml \
  --kubernetes-instance kind-yggdrasil-e2e
```

The workflow re-runs, `apply-core` bumps the Deployment to 2 replicas
(server-side apply, unchanged objects no-op), and `wait-core` confirms
both pods become Ready. No Postgres reconciliation — that
StatefulSet is already settled and the `infra` phase fast-forwards.

## Step 8 — Clean up

```sh
kind delete cluster --name yggdrasil-e2e
cd ~/yggdrasil-e2e && docker compose -f ./yggdrasil/docker-compose.yml down -v
rm -rf ~/yggdrasil-e2e
rm -f ~/.yggdrasil/config.yaml
```

## Troubleshooting

### `apply-infra` step fails with "no instance for family=kubernetes"

The `integration_instance` from Step 3 was not applied (or `name` in
`--kubernetes-instance` doesn't match what Step 3 declared). Re-run
`yggdrasil get integration_instance` and confirm one is named
`kind-yggdrasil-e2e`.

### Pods stuck in `ImagePullBackOff`

The control_plane spec's `spec.image` references
`ghcr.io/dakasa-yggdrasil/yggdrasil-core:latest` which may not exist
yet (until the adopter has CI that publishes it). Swap for a tag you
know exists, or `docker pull` + `kind load docker-image` a locally-
built binary:

```sh
docker build -t ghcr.io/dakasa-yggdrasil/yggdrasil-core:e2e ./yggdrasil-core
kind load docker-image ghcr.io/dakasa-yggdrasil/yggdrasil-core:e2e --name yggdrasil-e2e
# then edit control-plane.yaml: spec.image = ...yggdrasil-core:e2e
```

### `wait-infra` times out

The default workflow retries observe_objects 12× at 10s intervals (120s
total). If Postgres is slow to start, bump `retry.max_attempts` on the
workflow step — but first check `kubectl describe pod -n yggdrasil
yggdrasil-postgres-0` for the real cause.

### `integration-kubernetes` can't reach the kind API

The adapter container reaches the kind cluster via the mounted
kubeconfig. The kubeconfig's server URL is `https://127.0.0.1:<random>`
which points at the HOST's loopback, not the container's. On macOS:

- colima's docker context handles this correctly because the kind
  container + integration-kubernetes container share a network.
- Docker Desktop: may need the kubeconfig patched to use
  `host.docker.internal` — `kind get kubeconfig --name yggdrasil-e2e
  | sed 's|https://127.0.0.1|https://host.docker.internal|' >
  ~/.kube/kind.yaml` and point `config.kubeconfig_path` at that file.

## What this validates

- The seed boots with zero adopter config.
- `integration_instance` seeding from Step 3 works end-to-end.
- The `control_plane` manifest is validated by the core
  (`manifest/control_plane.go`).
- The renderer produces a valid K8s bundle
  (`internal/controlplane/render.go`).
- The `yggdrasil-deploy-control-plane` workflow orchestrates apply →
  wait → migrate → apply-core → wait-core correctly.
- `integration-kubernetes`'s `declarative_apply` is idempotent (Step
  7 proves re-apply converges).
- The core image runs in-cluster against its own Postgres and serves
  the HTTP API.

## What this does NOT validate

- Ingress. Step 4 sets `ingress.enabled: false` so the walkthrough
  doesn't need a cluster ingress controller.
- AMQP transport. Everything is HTTP — if you need to validate AMQP,
  declare a `transport: [{ kind: amqp, mode: bundled, ... }]` in the
  spec and observe the extra StatefulSet.
- The operator's continuous reconcile. This walkthrough does a
  one-shot deploy; the operator (`cmd/operator`) runs the same
  workflow in a loop. To validate that path, deploy the operator
  alongside the production control plane and edit the `control_plane`
  manifest — the operator picks up the new version automatically.
- External registries / OCI install. `yggdrasil install oci://...`
  is tested in isolation; a full E2E with a published OCI artifact
  is the obvious follow-up.
