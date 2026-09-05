# ADR-0017: Enforce workflow string pattern and maximum length at ingress

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow input validation
- **Supersedes:** —
- **Superseded by:** —

## Context

Workflow input properties reused `IntegrationSchemaProperty`, which exposed
`pattern` and `MaxLength` as presentation metadata. Runtime workflow validation
enforced types and `minLength`, but it did not apply either of those two
constraints. The workflow authoring convention also used JSON Schema's
`maxLength` spelling while the shared integration model decoded only the legacy
`max_length` key. A manifest could therefore appear to bound a digest,
identifier, or namespace while the Core accepted an arbitrary string.

RBAC identifies who may run a workflow, but it cannot make an unconstrained
string safe. Policy conditions are an additional authorization layer rather
than a substitute for structural input validation. Machine callers especially
need the authored input boundary to run before durable evidence or adapter
dispatch.

## Decision

The workflow ingress validator enforces `pattern` and `maxLength` for every
present string property after defaults and request inputs are merged and before
a run is persisted or dispatched.

- `pattern` uses Go's RE2-compatible regular expressions. It follows JSON
  Schema search semantics; authors use `^` and `$` when the entire value must
  match. Invalid expressions make the workflow manifest invalid and also fail
  closed if an unvalidated in-memory spec reaches runtime validation.
- `maxLength` counts Unicode code points, not UTF-8 bytes. Negative values and
  a `minLength` greater than `maxLength` make the manifest invalid.
- Workflow JSON accepts canonical `maxLength`. The historical `max_length`
  spelling remains accepted so existing integration-shaped producers do not
  break; declaring both with different values is rejected as ambiguous.
- These constraints remain string-only. Their presence on non-string
  properties keeps the prior no-op behavior, preserving the shared integration
  schema contract.

## Consequences

- A workflow can safely constrain content-addressed image digests and bounded
  identifiers at the same pre-persistence boundary as type, required, and
  closed-map validation.
- Existing workflow manifests without these fields behave exactly as before.
  Existing manifests that already authored them now reject values outside the
  declared contract; that is the intended activation of an advertised boundary.
- Integration credential/config validation and its serialized `max_length` UI
  contract are unchanged.
- Pattern matching does not add PCRE-only features because Go regular
  expressions deliberately exclude backtracking constructs.

## Related

- ADR-0015 (validate and redact workflow inputs before async persistence)
- ADR-0016 (scope machine principals by route, workflow, and run ownership)
