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

An adapter that implements an `integration_family` includes both
`family_ref` and `implemented_operations` in its `describe` response. The Core
carries those fields into the live `integration_type` spec during manifest
sync, preserving family-targeted workflow resolution.

Important:

- This is a wire contract.
- Plugins should keep their own local types.
- `yggdrasil-core/model` is an internal implementation detail, not an SDK.

## Reserved sensitive-output metadata

The following top-level `execute.metadata` keys are owned by the Core workflow
runtime and must not be accepted from public or direct integration callers:

- `supports_sensitive_output_paths`
- `sensitive_output_sink`
- `sensitive_input_lease`

The Core adds the first two only for a statically validated producer whose
immediately following step is the sole exact consumer and resolves to
an integration type in the `secrets-management` family that implements
`ensure_secret`. `sensitive_output_sink` v1 identifies the producer step, sink
step, one top-level source output path, and the fixed sink input path
`secret.generation.manual.value`. It never contains the secret value.
The sink input must also contain a concrete `secret.secret_id` and the literal
`secret.generation.strategy: manual`; a generated strategy is not an authorized
destination for a leased value.

An eligible producer returns the generated string under `output` and declares
exactly the Core-authorized path through
`metadata.sensitive_output_paths`. Missing, extra, duplicate, malformed,
non-string, or unresolvable declarations fail closed. The raw result never
enters the general workflow step context. An authorized source field returned
without a declaration also fails closed; a source-free ordinary/no-op response
creates no lease.

The Core adds `sensitive_input_lease` only to the designated sink call. For that
call, adapters must not echo the manual value in output, errors, logs, resources,
adoption responses, or mutation events. The Core independently discards the
adapter response, emits a value-free receipt, and removes HTTP bodies and AMQP
messages from observable errors. The receipt requires exact operation/capability
and one of the explicit statuses `created`, `updated`, or `unchanged`.

This v1 lease supports one adjacent sink and one top-level string only. It does
not authorize fan-out, conditions, nested or derived paths, or a second
consumer. The producer has one attempt; only the idempotent sink may retry. A
declared sensitive response outside an authorized workflow producer call fails
generically and returns no adapter output. See ADR-0016 and the workflow feature
contract for the runtime rules. The Core privately pins the preauthorized sink
instance/type ID and version and rejects catalog drift before dispatch.

Primary schema: [schema.json](/Users/dakasa/projects/yggdrasil-core/docs/contracts/integration-adapter/v1/schema.json)
