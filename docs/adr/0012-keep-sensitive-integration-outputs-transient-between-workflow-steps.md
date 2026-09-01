# ADR-0012: Keep sensitive integration outputs transient between workflow steps

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow execution and integration adapter contract
- **Supersedes:** —
- **Superseded by:** —

## Context

Some provider APIs return a generated secret exactly once when creating a
resource, such as a webhook signing key. A workflow must be able to pass that
value to its next secret-store step, but the existing engine copied every
adapter output into the synchronous response, `workflow_runs.result`, and the
`workflow.run.completed` event. Adapter metadata could identify sensitive
paths, but the core did not enforce that declaration.

Returning the secret directly from a standalone capability invocation remains
necessary for the one-time creation contract. Persisting the same secret as a
workflow result or event is not necessary and broadens its exposure.

## Decision

Treat `metadata.sensitive_output_paths` on an integration step response as an
enforced workflow boundary. Keep the original output only in the in-memory
execution context so later steps in the same run may store it through a
`credentials_ref`-backed secret provider. Redact the declared paths from the
public workflow response before it can be returned or persisted. Completion
events are derived only from that public response and must not receive the
private execution context.

Paths are relative to `metadata.output` and accept dot notation or JSON
Pointer notation. If a declaration is malformed or cannot be resolved, redact
the complete output fail-closed.

## Consequences

- Provider-generated secrets can be transferred to a secret store without a
  durable plaintext copy in workflow history.
- Downstream steps may reference the original value during the same process
  execution; callers and operators see `[REDACTED]` in the final result.
- Adapter authors must mark every generated-secret path. Unmarked output is
  unchanged for compatibility.
- A process crash before the secret-store step may lose a one-time secret. The
  provisioning workflow must destroy/recreate or otherwise recover the
  provider resource explicitly; durable workflow history is not a secret
  recovery mechanism.

## Related

- Integration adapter contract: provider-generated secrets and
  `credentials_ref`
