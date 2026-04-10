# Integration Adapter v1

This contract defines the generic RabbitMQ adapter protocol used by
`yggdrasil-core` when talking to an integration plugin through:

- `describe`
- `execute`

Queues are declared by the adapter itself in the `describe` response.

Important:

- This is a wire contract.
- Plugins should keep their own local types.
- `yggdrasil-core/model` is an internal implementation detail, not an SDK.

Primary schema: [schema.json](/Users/dakasa/projects/yggdrasil-core/docs/contracts/integration-adapter/v1/schema.json)
