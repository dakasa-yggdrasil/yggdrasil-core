# Extending Yggdrasil

Build your own integration or surface in 30 minutes.

Yggdrasil is plugin-first by design. The core handles the workflow engine,
the manifest catalog, auth, and policy. Everything that talks to a real
system out there — a SaaS, a cloud, a database — is a plugin. There are
two kinds:

- **Integrations** — outbound adapters that execute operations (AMQP RPC
  with the core). Think `integration-kubernetes`, `integration-aws`,
  `integration-grafana`.
- **Surfaces** — inbound edges that render a UI or expose a narrow HTTP
  API on top of the core's contracts. Think `surface-console`, `surface-auth`.

Both have official templates and a one-command scaffold. The walkthrough
below ships an integration; the surface flow is nearly identical (same
command with `surface` instead of `integration`).

## Before you start

- `yggdrasil` CLI on your PATH
  ([install](https://github.com/dakasa-yggdrasil/yggdrasil/releases)).
- `git`, `go` 1.25+, Docker (or colima/podman).
- A running `yggdrasil-core` to install into. `yggdrasil init` gives you
  one on localhost in ~1 minute. See
  [getting-started.md](./getting-started.md).

## Step 1 — Scaffold

```sh
yggdrasil new integration datadog --owner acme-eng
```

Output:

```
✓ scaffold ready

  directory: /home/you/integration-datadog
  module:    github.com/acme-eng/integration-datadog
  project:   integration-datadog

Next steps:
  cd integration-datadog
  go test ./...
  # edit internal/adapter/spec.go and add your operations
  git commit -am "initial commit"
  gh repo create --public --push
```

What just happened:

1. The CLI did a shallow clone of
   [`integration-template`](https://github.com/dakasa-yggdrasil/integration-template).
2. Stripped the template's git history (fresh repo, no inherited baggage).
3. Rewrote every reference to `integration-template` → `integration-datadog`
   and the template module path → `github.com/acme-eng/integration-datadog`.
4. Initialized a new git repo and staged everything.

The scaffold is **compilable on the spot** — `go test ./...` runs green
without a single line of your own code.

## Step 2 — Understand the layout

```
integration-datadog/
├── main.go                       # AMQP consumer entrypoint
├── controllers/message/          # RPC handlers (describe / execute / health)
├── internal/adapter/
│   ├── spec.go                   # describe contract + operation switch
│   └── spec_test.go              # unit tests with a fake executor
├── internal/protocol/            # local copy of the wire contracts
├── internal/runtime/             # lifecycle + graceful shutdown
├── examples/                     # sample integration_type + instance manifests
├── yggdrasil-quickstart.yaml     # one-command install for adopters
├── .github/workflows/release.yml # multi-arch ghcr.io publish on tag
├── Dockerfile
├── Taskfile.yml
└── docker-compose.{yml,standalone.yml}
```

**The only file you usually need to edit** is
`internal/adapter/spec.go`. That's where operations, the Describe
contract, and the Execute switch live. Everything else is boilerplate
that stays consistent across the catalog.

## Step 3 — Declare your first operation

Open `internal/adapter/spec.go`. Replace the template's starter
operations with your own:

```go
const (
    Provider       = "datadog"
    AdapterVersion = "1.0.0"

    OperationEnsureMonitor = "ensure_monitor"
    OperationDeleteMonitor = "delete_monitor"

    QueueDescribe = "yggdrasil.adapter.datadog.describe"
    QueueExecute  = "yggdrasil.adapter.datadog.execute"
)

var SupportedExecuteOperations = []string{
    OperationEnsureMonitor,
    OperationDeleteMonitor,
}
```

Add the Execute case:

```go
func Execute(ctx context.Context, req protocol.AdapterExecuteIntegrationRequest) (protocol.AdapterExecuteIntegrationResponse, error) {
    switch req.Operation {
    case OperationEnsureMonitor:
        return ensureMonitor(ctx, req)
    case OperationDeleteMonitor:
        return deleteMonitor(ctx, req)
    default:
        return protocol.AdapterExecuteIntegrationResponse{}, fmt.Errorf("unsupported operation %q", req.Operation)
    }
}
```

Implement `ensureMonitor` + `deleteMonitor` against the Datadog SDK.
Tests live right next door in `spec_test.go` — stub the SDK client, run
`go test ./...`, iterate.

## Step 4 — Register a family (only once, by the publisher)

Every integration belongs to a **family** — the contract multiple
providers can implement. If your integration is the first implementation
of a family nobody ships yet, publish a short family manifest that
declares the shared operation set:

```yaml
# family.yaml
apiVersion: yggdrasil.io/v1alpha1
kind: integration_family
metadata:
  name: monitoring
  namespace: global
spec:
  display_name: Monitoring
  description: Alerting rules, dashboards, monitors across backends.
  operations:
    - name: ensure_monitor
    - name: delete_monitor
```

```sh
yggdrasil apply -f family.yaml
```

If you're implementing an existing family (say `kubernetes` or
`secrets-management`), skip this — the family is already registered and
your provider just has to match the operation names.

## Step 5 — Ship and register a type manifest

Point adopters at your concrete implementation:

```yaml
# integration_type.yaml
apiVersion: yggdrasil.io/v1alpha1
kind: integration_type
metadata:
  name: monitoring-datadog
  namespace: global
  labels:
    yggdrasil.io/catalog-domain: monitoring
    yggdrasil.io/catalog-section: operations
    yggdrasil.io/catalog-entry: datadog
spec:
  provider: datadog
  adapter:
    transport: rabbitmq
    version: "1.0.0"
    queues:
      describe: yggdrasil.adapter.datadog.describe
      execute:  yggdrasil.adapter.datadog.execute
    timeout_seconds: 30
  capabilities: [describe, execute]
  credential_schema:
    mode: inline
    required: [api_key, app_key]
    properties:
      api_key:  { type: string, secret: true }
      app_key:  { type: string, secret: true }
```

```sh
yggdrasil apply -f integration_type.yaml
```

## Step 6 — Customize the quickstart manifest

The scaffold already includes `yggdrasil-quickstart.yaml` with TODO
markers. Replace the placeholders so any adopter can install your
integration with:

```sh
yggdrasil install acme-eng/integration-datadog --provider default
```

The quickstart drives the interactive TUI, the compiled workflow, and
the smoke test. See one of the reference integrations for inspiration,
for example
[`integration-kubernetes/yggdrasil-quickstart.yaml`](https://github.com/dakasa-yggdrasil/integration-kubernetes/blob/main/yggdrasil-quickstart.yaml).

## Step 7 — Publish

```sh
cd integration-datadog
gh repo create dakasa-yggdrasil/integration-datadog --public --push  # or your own owner
git tag v0.1.0 && git push --tags
```

The included `release.yml` workflow builds a multi-arch image and
publishes it to `ghcr.io/<owner>/integration-datadog:v0.1.0` +
`:latest`. From that moment, anyone can run:

```sh
yggdrasil install acme-eng/integration-datadog
```

and get a working adapter deployed into their cluster.

## Writing a surface

Same flow, different command:

```sh
yggdrasil new surface admin-dashboard --owner acme-eng
```

Surfaces are simpler: no AMQP consumer, no family manifest, no operation
catalog. They're just HTTP/UI edges that talk to the core's HTTP API.
Register one with a `surface` manifest (see
[concepts → surfaces](./concepts.md#surfaces)) and the core knows it
exists.

## Naming and catalog conventions

The catalog groups integrations by (`domain`, `section`, `entry`):

- `domain` = what the integration is about (`monitoring`, `kubernetes`,
  `aws`, …)
- `section` = `installations` or `operations`
- `entry` = the concrete implementation (`datadog`, `cloudwatch`, …)

Publish these as labels on your `integration_type`:

```yaml
metadata:
  labels:
    yggdrasil.io/catalog-domain: monitoring
    yggdrasil.io/catalog-section: operations
    yggdrasil.io/catalog-entry: datadog
```

Read more: [concepts → plugin catalog convention](./concepts.md#plugin-catalog-convention).

## Testing your plugin before publishing

Run the adapter against your `yggdrasil init` stack without publishing:

```sh
# In the plugin directory
docker build -t integration-datadog:dev .

# Point the Yggdrasil broker at your local adapter
docker run --rm --network yggdrasil_default \
  -e BROKER_URL="$(docker compose -p yggdrasil exec yggdrasil-core printenv BROKER_URL)" \
  integration-datadog:dev
```

Dispatch a workflow step that targets your operation and watch the run
via `yggdrasil logs <run-id>`.

## Contributing back

If your integration targets a public backend, we'd love to upstream it:

1. Open a PR proposing `integration-<name>` into the
   [`dakasa-yggdrasil`](https://github.com/dakasa-yggdrasil) org.
2. Include passing `go test ./...` and a smoke test exercising one
   operation end-to-end.
3. The maintainers will review and cut the first release from
   `ghcr.io/dakasa-yggdrasil/integration-<name>`.

Private / proprietary integrations stay in your org and still install
through `yggdrasil install <your-org>/integration-<name>`.

## Resources

- [Concepts](./concepts.md) — manifest kinds, family/type/instance/provider
- [Architecture](./architecture.md) — where your adapter fits
- [CLI reference](./cli.md) — every command
- [Catalog](./catalog.md) — what's already shipped
- [integration-template](https://github.com/dakasa-yggdrasil/integration-template) — the scaffold source
- [surface-template](https://github.com/dakasa-yggdrasil/surface-template) — the surface scaffold source
