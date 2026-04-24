# Getting started

Ten minutes from nothing to a running Yggdrasil control plane with a
working workflow. Pick the path that matches your machine; the rest
of the document is the same.

## Option A — Standalone on your laptop (recommended to try it out)

Requires Docker Desktop (or the Docker Engine) with Compose v2, and
the `yggdrasil` CLI on your `$PATH`. If you do not have the CLI yet,
install from releases or build from source:

```sh
go install github.com/dakasa-yggdrasil/yggdrasil/cmd/yggdrasil@latest
```

Run:

```sh
yggdrasil init
```

That's it. The init command:

1. Writes `./yggdrasil/docker-compose.yml` + `./yggdrasil/.env` with random
   passwords.
2. Runs `docker compose up -d` — brings up Postgres + yggdrasil-core
   (HTTP-only by default). The compose file also declares a RabbitMQ
   service under the `amqp` profile, off by default; opt in only if
   you use AMQP-transport integrations (see
   [features/transports.md](./features/transports.md)).
3. Waits for `/readyz` to come green.
4. Logs in as the freshly-created admin and saves a context in
   `~/.yggdrasil/config.yaml` so every subsequent command just works.
5. Prints the admin password — save it somewhere before you lose the
   terminal.

Verify:

```sh
yggdrasil status
```

You should see `health: ok`, `ready: ok`.

## Option B — Attach to an existing yggdrasil-core

You already brought up `yggdrasil-core` via Helm (see
[deployment.md](./deployment.md)) or any other mechanism. Tell the CLI
where it lives:

```sh
yggdrasil login --server https://yggdrasil.internal --username admin
```

The CLI prompts for the password and stores a named context under
`~/.yggdrasil/config.yaml`.

## Install your first integration

All the integration work uses a single command. Kubernetes is the
typical first pick because most of the other integrations deploy
their adapters as Kubernetes workloads.

```sh
yggdrasil install dakasa-yggdrasil/integration-kubernetes --provider kubernetes
```

The CLI fetches that repo's `yggdrasil-quickstart.yaml`, asks you for
any required inputs (kubeconfig path, namespace, etc.), and POSTs an
install request. The server compiles a workflow, dispatches the
workflow run, and creates the adapter pod plus the registered
instance on the other end.

## Apply a manifest

Create `hello-workflow.yaml`:

```yaml
apiVersion: yggdrasil.io/v1alpha1
kind: workflow
metadata:
  name: hello
  namespace: default
spec:
  trigger:
    mode: manual
  steps:
    - id: say-hi
      use:
        kind: integration
        family: kubernetes
        operation: describe_installation_state
      with:
        namespace: default
```

Apply it:

```sh
yggdrasil apply -f hello-workflow.yaml
```

List what you just created:

```sh
yggdrasil get workflow
```

## Stream a workflow run

Dispatch the workflow (via the web console, via API, or via a
schedule manifest). The CLI will stream each step as it lands:

```sh
yggdrasil logs <run-id>
```

## Next steps

- Read [concepts.md](./concepts.md) to understand manifests, families,
  providers, instances, and workflows.
- Browse [catalog.md](./catalog.md) for the available integration
  families.
- For a production deployment, read [deployment.md](./deployment.md)
  (Helm, TLS, external Postgres, RBAC).
- To add GitHub or Google sign-in, see
  [docs/auth-providers/](./auth-providers/).
