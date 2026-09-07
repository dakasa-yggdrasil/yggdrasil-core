# ADR-0016: Constrain provider-generated secrets to one-step private leases

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow execution and integration adapter transport
- **Supersedes:** [ADR-0012](0012-keep-sensitive-integration-outputs-transient-between-workflow-steps.md)
- **Superseded by:** -

## Context

ADR-0012 kept an adapter response containing a one-time provider secret in the
general in-memory workflow step context. Public responses were redacted, but all
later steps could still render the original value. A malformed declaration also
redacted only the public copy while leaving the raw result in that shared
context.

A secret-store adapter may reflect its input in an HTTP body, AMQP error message,
or success response. Those values can reach the step error, asynchronous
`workflow_runs.result`, and operator-facing logs unless the Core applies a
separate error and response policy to the sink call. Arbitrary metadata on the
public integration execute API also lets a caller forge any handshake that is
not explicitly reserved.

Stripe webhook signing secrets require a narrower lifetime. The provider returns
the value once, one exact `secrets-management/ensure_secret` step consumes it,
and no general workflow context or durable evidence needs the plaintext.

## Decision

The Core uses a private one-step lease for an eligible provider-generated secret.
The lease is an unexported, per-run runtime object containing only the producer
step ID, sink step ID, the preauthorized sink instance/type identity and version,
one top-level source path, one fixed sink input path, and the extracted string
value. It is not part of a model, template context, request metadata, event,
trace, or serializable result.

Before calling a producer, the Core may issue a v1 handshake only when all of
these rules hold in actual topological execution order:

1. Producer and sink are adjacent integration steps.
2. The sink depends on exactly the producer.
3. Neither step has `condition` or `for_each`.
4. The producer has exactly one attempt; v1 never repeats a create after an
   ambiguous or lost response. The sink may retry its idempotent write.
5. Producer operation/capability agree, and sink operation/capability both
   normalize to `ensure_secret`.
6. The resolved sink integration type declares family `secrets-management` and
   implements `ensure_secret`. Instance names are not evidence of family
   membership.
7. `secret.secret_id` renders to a concrete non-empty string and
   `secret.generation.strategy` is the literal `manual`.
8. `secret.generation.manual.value` is exactly one template of the form
   `{{ steps.<producer>.metadata.output.<top-level-path> }}`.
9. No second template consumer references that source path, including a parent
   object or an equivalent path with whitespace around segments.

The Core derives the source path from the sink template and injects these
reserved producer metadata keys:

- `supports_sensitive_output_paths`
- `sensitive_output_sink`

The sink receives the reserved `sensitive_input_lease` metadata key. Public and
direct integration execute requests that contain any of these keys are rejected
before adapter dispatch.

A response that declares `sensitive_output_paths` is accepted only inside an
authorized producer call. Public/direct and other internal execute paths fail
with a generic contract error and return no adapter output.

When a producer declares `metadata.sensitive_output_paths`, the declaration must
be a non-empty list with exactly the one authorized top-level path. The path must
resolve to a non-empty string in `metadata.output`. Missing, extra, duplicate,
malformed, non-string, mismatched, or unresolvable declarations fail with the
stable `sensitive_output_contract_violation` error. The complete output and all
untrusted adapter metadata are discarded on failure. If an authorized producer
returns the authorized source field without any declaration, it also fails
closed. A source-free ordinary/no-op response remains compatible and creates no
lease.

For an accepted declaration, the Core extracts the string into the private
lease, replaces it in a copied result, recursively removes exact echoes from
adapter metadata, and stores only the safe copy in the general workflow context
and public response. The raw step result is never assigned to
`WorkflowExecutionContext.Steps`.

Only the designated next sink gets an overlay while rendering its input. The
Core renders that input once, verifies the leased string occurs only at the
authorized path, and reuses the same rendered input for retries of that sink.
It also verifies the rendered `secret_id`, manual strategy, and exact
preauthorized sink instance/type ID and version before dispatch. Conditions,
fan-out, integration selection, and later steps always see the redacted context.

Eligible producer calls and leased sink calls use detail-free transport errors.
HTTP failure bodies and AMQP adapter messages are discarded. A sink success
response is also discarded. Only an explicit response for the requested
operation/capability with status `created`, `updated`, or `unchanged` produces a
fixed receipt containing successful status and lease version. Empty, malformed,
or generic-success responses fail closed. The lease and rendered input
references are cleared after success, failure, cancellation, or panic
propagation. Workflow completion with an unconsumed lease fails generically.

This is an application-level reachability and serialization guarantee. Go does
not provide physical zeroization for immutable strings already copied in heap or
transport buffers, so this decision does not claim cryptographic memory erasure.

## Consequences

- Within the Core, a provider-generated webhook secret can reach exactly one
  validated secret sink without appearing in workflow output, persisted errors,
  `workflow.run.completed` payloads, or general template state. Adapter-owned
  mutation events still require a secret-safe SDK projector before the
  end-to-end invariant is enabled.
- A guarded producer receives no handshake when adjacency, dependency, family,
  operation, template shape, or single-consumer validation fails, so it can
  refuse provider mutation before creating a one-time value.
- Existing unmarked adapter output keeps its prior behavior except that an
  authorized producer cannot return its authorized source field unmarked. This
  v1 contract does not migrate broader workflows that intentionally read,
  generate, rotate, or reuse secret values across multiple steps.
- Sink output is receipt-only even if the adapter echoes the input in output or
  metadata.
- Detail-free producer and sink errors trade provider diagnostics for
  containment. Operators retain the failing workflow and step identity, but not
  the provider response body or message.
- A process crash after provider creation and before sink completion can lose the
  one-time value. Provider idempotency and explicit recovery remain required.

## Related

- ADR-0015 (redacts sensitive workflow inputs before asynchronous persistence)
- Integration Adapter v1 contract
- Workflow feature contract, sensitive integration outputs section
