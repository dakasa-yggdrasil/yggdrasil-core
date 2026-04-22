# Bootstrap Integrations

This directory stores bootstrap manifests for ecosystem plugins that `yggdrasil-core` can consume.

Current bootstrap integrations are already organized around the plugin catalog convention.

Current catalog view:

- `aws`
  - `operations/api` -> `aws-integration-type.json`
- `gcp`
  - `operations/api` -> `gcp-integration-type.json`
- `heimdall`
  - `operations/guardian` -> `heimdall-integration-type.json`
- `github`
  - `operations/api` -> `github-integration-type.json`
- `grafana`
  - `family` -> `grafana-integration-family.json`
  - `operations/api` -> `grafana-integration-type.json` (provider: `grafana`)
  - `installations/kubernetes` -> `grafana-kubernetes-integration-type.json` (provider: `grafana-kubernetes`)
- `kubernetes`
  - `operations/api` -> `kubernetes-integration-type.json`
- `rabbitmq`
  - `family` -> `rabbitmq-integration-family.json`
  - `operations/api` -> `rabbitmq-integration-type.json` (provider: `rabbitmq`)
  - `installations/kubernetes` -> `rabbitmq-kubernetes-integration-type.json` (provider: `rabbitmq-kubernetes`)
  - `operations/topology` -> `rabbitmq-topology-integration-type.json` (provider: `rabbitmq-topology`, declarative queues/exchanges/bindings via Management API; non-destructive by default — `input.purge_removed=true` to delete orphans)

Current bootstrap instances:

- `aws-platform.json`
  - covers `S3`, `ECR`, `Secrets Manager`, `Route53`, `SES` and `SNS`
- `kubernetes-platform-prod.json`
- `github-caller.json`
- `heimdall-guardian.json`
  - covers ecosystem health, remediation planning, and cost optimization
- `gcp-platform.json`
- `grafana-platform-api.json`
- `grafana-on-kubernetes-platform-prod.json`
- `rabbitmq-platform-api.json`
- `rabbitmq-on-kubernetes-platform-prod.json`

These manifests describe how the core can reach the adapters over RabbitMQ RPC. They do not deploy the adapter workers themselves.

Lightweight Heimdall support now lives directly on `integration_type.spec.guardian_support`.
If an integration declares that block, the core can map provider runtime details
into canonical guardian signals without needing a provider-specific Heimdall path.
If the integration omits it, Heimdall still sees the generic runtime state, but
that provider does not get lightweight remediation support.

Some integrations can also act as optional discovery sources. The first generic
convention is `catalog_discover`, which lets the core ask an integration
instance for candidate plugins or surfaces. This is intentionally provider
agnostic:

- GitHub can implement it
- GitLab can implement it
- filesystem or OCI scanners can implement it later

The intended flow is:

1. an installation-focused integration such as RabbitMQ generates or reconciles desired objects
2. the Kubernetes target integration applies and observes those objects in the target cluster
