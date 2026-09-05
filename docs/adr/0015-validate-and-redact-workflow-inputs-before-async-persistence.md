# ADR-0015: Validate and redact workflow inputs before async persistence

- **Status:** Accepted
- **Date:** 2026-09-04
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow dispatch and durable run evidence
- **Supersedes:** —
- **Superseded by:** —

## Context

Asynchronous dispatchers created a `workflow_runs` row before the workflow
engine resolved the manifest or validated its input schema. Invalid requests
therefore became durable evidence before eventually failing in the background.
The same ordering also stored plaintext input values that a workflow schema had
already classified as `secret` or `sensitive`.

The execution engine still needs the original value in process memory because
a workflow step may render it through `{{ inputs.<name> }}`. Persisting that
value is not required for the current run. Existing workflows also rely on the
JSON Schema default that undeclared properties remain allowed unless the schema
explicitly closes them.

## Decision

Every in-process asynchronous workflow producer must resolve the workflow,
validate its manifest and merged inputs, and only then create the durable run
row. `input_schema.additionalProperties: false` closes the top-level input map
and rejects keys absent from `input_schema.properties`; an omitted or true
value preserves the existing open-map behavior.

Preparation creates separate execution and evidence representations. The
execution request keeps the original merged values in memory. The evidence
copy preserves the caller-supplied input shape but replaces each value whose
declared property has `secret: true` or `sensitive: true` with `[REDACTED]`
before it reaches `workflow_runs.inputs`.

## Consequences

- Invalid closed-schema inputs fail before a pending run is persisted.
- HTTP, webhook, scheduler, event-trigger, and Heimdall-inbox producers share
  the same ordering and redaction boundary.
- Existing schemas stay open unless they explicitly set
  `additionalProperties: false`.
- Current execution can render sensitive values, but durable history cannot be
  used to recover or replay them. Today no async producer rehydrates execution
  from `workflow_runs.inputs`: the GET and ops paths are read-only, the stale
  cleaner cancels a run orphaned by process restart, and the ops retry/replay
  endpoints do not dispatch stored inputs. A retry must supply the sensitive
  value again, and a process crash before the relevant step requires explicit
  recovery.
- A future durable resume/retry implementation must treat `[REDACTED]` as
  non-replayable and require a freshly supplied value or a resolvable secret
  reference; it must not pass the marker to workflow templates.
- Secret references remain preferable to secret-valued workflow inputs.
- This boundary covers the top-level `inputs` copy. Caller-controlled metadata,
  source event payloads, and adapter errors/outputs have their own contracts and
  must not be used to smuggle the same secret around the redaction boundary.
- Pattern, enum, and maximum-length enforcement are separate compatibility
  changes; this decision does not silently activate them for existing flows.

## Related

- ADR-0012 (applies the same transient-value boundary to integration outputs)
