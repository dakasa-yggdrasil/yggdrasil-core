# CLI reference

The `yggdrasil` CLI is the primary way humans interact with a
self-hosted control plane outside of a browser.

## Global behavior

**Configuration file**: `~/.yggdrasil/config.yaml` (override with
`YGGDRASIL_CONFIG` env var). Contains one or more named contexts
(server URL + bearer token + collaborator slug) plus a
`current_context` pointer. Created by `init` and `login`.

**Active context**: resolved in this order:

1. `YGGDRASIL_CONTEXT` env var
2. `current_context` from the config file
3. The only context, when exactly one exists

## Commands

### `yggdrasil init`

Bootstrap a new self-hosted stack.

```
yggdrasil init [--dir <path>]            # standalone docker-compose
yggdrasil init --server <url>            # attach to existing server
```

Flags:

| Flag | Purpose |
|---|---|
| `--dir` | Directory for compose+env files. Default `./yggdrasil`. |
| `--server` | Skip compose; just log in to an existing server. |
| `--admin-username` | Default `admin`. |
| `--admin-password` | Empty → random (printed on success). |
| `--admin-email` | Optional. |
| `--core-image` | Container image override. |
| `--port` | Host port bind. Default 9080. |
| `--context` | Context name in `config.yaml`. Default `local`. |

### `yggdrasil login`

Exchange credentials for a session token and save a context.

```
yggdrasil login --server https://yggdrasil.example.com --username admin
```

If `--password` is omitted, the CLI prompts for it (unless
`--non-interactive`).

### `yggdrasil apply -f <file>`

Create a new manifest version. Accepts multi-document YAML
(`---` separated). Reads from stdin with `-f -`.

```
yggdrasil apply -f my-workflow.yaml
cat bundle.yaml | yggdrasil apply -f -
```

Returns `created <kind> <namespace>/<name> (version N)` per document.

### `yggdrasil get <kind> [<name>]`

List or fetch manifests.

```
yggdrasil get workflow                      # all workflows, all namespaces
yggdrasil get workflow -n prod              # filter by namespace
yggdrasil get workflow deploy-service -n prod   # one specific
yggdrasil get integration_instance -o yaml  # raw YAML for piping
```

Flags:

| Flag | Purpose |
|---|---|
| `-n`, `--namespace` | Filter by namespace. |
| `-o` | Output format: `table` (default), `yaml`, `json`. |
| `--active-only` | Return only `metadata.active=true` manifests. |

### `yggdrasil describe <kind> <name>`

Full YAML dump of one manifest. Equivalent to `get <kind> <name> -o yaml`.

```
yggdrasil describe workflow deploy-service
```

### `yggdrasil logs <run-id>`

Stream a workflow run's step results. Follows until terminal unless
`-f=false`.

```
yggdrasil logs 01932a8c-1234-7abc-def0-123456789012
```

Flags:

| Flag | Default |
|---|---|
| `-f` | `true` |
| `--interval` | `2` (seconds between polls) |
| `--timeout` | `600` (seconds) |

### `yggdrasil status`

Current context, server URL, and a health probe.

```
yggdrasil status
```

### `yggdrasil version`

Prints the CLI version (and VCS revision if built from source).

### `yggdrasil auth provider ...`

Manage OAuth/OIDC providers.

```
yggdrasil auth provider list
yggdrasil auth provider get github
yggdrasil auth provider apply -f docs/auth-providers/github.example.yaml
yggdrasil auth provider delete github
```

See [docs/auth-providers/](./auth-providers/) for example payloads.

### `yggdrasil install <repo_ref>`

Quickstart-install an integration from a repo that carries a
`yggdrasil-quickstart.yaml`. This is the primary "add an
integration" command.

```
yggdrasil install dakasa-yggdrasil/integration-kubernetes --provider kubernetes
yggdrasil install my-org/private-integration --github-token $TOKEN
```

Flags:

| Flag | Purpose |
|---|---|
| `--provider` | Pick a provider without the TUI. |
| `--input k=v` | Pre-fill a quickstart input (repeatable). |
| `--dry-run` | Compile the workflow, don't dispatch. |
| `--non-interactive` | No TUI; fail if inputs are missing. |
| `--github-token` | For private quickstart repos. |

## Workspace-dev commands

Used by contributors checking out the yggdrasil monorepo — not
relevant to adopters.

```
yggdrasil integrations list|install|remove|tui|installed
yggdrasil surfaces list|install|remove|installed|scaffold|activate|deactivate
```

## Exit codes

- `0` — success.
- `1` — generic failure (validation, HTTP error, network).
- `2` — unsupported subcommand / bad flags.

Servers return typed errors in the JSON response body; the CLI
surfaces `server returned HTTP XXX: <detail>` when it can parse the
body, or the raw payload otherwise.

## Environment variables

| Var | Used by |
|---|---|
| `YGGDRASIL_CONFIG` | Override config file path. |
| `YGGDRASIL_CONTEXT` | Override active context. |
| `YGGDRASIL_URL` | Fallback server URL for `install` when no context. |
| `YGGDRASIL_WORKFLOW_RUN_TOKEN` | Fallback bearer for `install`. |
| `GITHUB_TOKEN` | Used by `install` to fetch private quickstart manifests. |
