# Integration Adapter v1

This contract defines the generic RPC adapter protocol used by
`yggdrasil-core` when talking to an integration plugin through:

- `describe`
- `execute`

The protocol is transport-agnostic — the same JSON envelope flows over
HTTP, AMQP, or any registered `rpc.Transport` (see
[features/transports.md](../../../features/transports.md)). The adapter
declares its addressing (queues for AMQP, endpoints for HTTP, etc.) in
the `describe` response.

Important:

- This is a wire contract.
- Plugins should keep their own local types.
- `yggdrasil-core/model` is an internal implementation detail, not an SDK.

Primary schema: [schema.json](/Users/dakasa/projects/yggdrasil-core/docs/contracts/integration-adapter/v1/schema.json)
