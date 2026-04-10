# Plugin Catalog

Yggdrasil groups integrations into a plugin catalog by domain instead of treating each adapter as a
flat list item.

The catalog shape is:

1. domain
2. section
3. entry

`integration_type` manifests publish their catalog position through metadata labels:

- `yggdrasil.io/catalog-domain`
- `yggdrasil.io/catalog-section`
- `yggdrasil.io/catalog-entry`

## Why this convention exists

The repository name and the concrete plugin name should stay honest. For example,
`rabbitmq-on-kubernetes` clearly says what it is. But that explicit name alone is not a great
catalog UX.

The catalog fixes that by grouping explicit plugins under one shared domain:

- `rabbitmq`
  - `installations`
    - `kubernetes` -> `rabbitmq-on-kubernetes`
  - `operations`
    - `api` -> `rabbitmq`

- `grafana`
  - `installations`
    - `kubernetes` -> `grafana-on-kubernetes`
  - `operations`
    - `api` -> `grafana`

- `github`
  - `operations`
    - `api` -> `github`

- `gcp`
  - `operations`
    - `api` -> `gcp`

This gives Yggdrasil one clear rule:

- the plugin name says what the worker really is
- the catalog groups workers into the domain view users expect

## Section convention

Current canonical sections:

- `installations`
- `operations`

Use `installations` when the plugin knows how to place a domain on a substrate, such as
Kubernetes.

Use `operations` when the plugin knows how to operate that domain after it exists, such as runtime
APIs, governance, or day-2 actions.

## Entry convention

`catalog-entry` identifies the variant inside a section.

Recommended values:

- substrate name for installation plugins, such as `kubernetes`
- control surface for operation plugins, such as `api`

## Querying the catalog

The current catalog can already be built from `manifest.list` because the core supports label
filters.

Examples:

- `domain = rabbitmq`
- `domain = rabbitmq, section = installations`
- `domain = github, section = operations`

The core now also exposes a dedicated catalog API over RabbitMQ:

- `yggdrasil-core.integration.catalog.list`
- `yggdrasil-core.integration.catalog.get`

That means consumers no longer need to know the underlying label conventions just to browse the
catalog.
