# ADR-0024: Fail workflows loudly on final-state assertion drift

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / workflow manifest validation and in-process workflow execution
- **Supersedes:** none
- **Superseded by:** none

## Context

A workflow step condition decides whether a step should run. A false condition
records the step as skipped and allows downstream execution to continue. That
behavior is correct for optional branches, but it cannot prove that a final
readback matches the intended state.

Control-plane workflows often apply an object and then observe it. A successful
read alone proves only that the object was readable. If the workflow expresses
the desired-state comparison as a condition, drift can turn the validation step
into a successful skip and leave the whole run green. The engine needs a
read-only operation whose failure is a workflow failure and whose evidence does
not persist the compared values.

## Decision

Add `assert` as an in-process `yggdrasil` workflow operation.

1. The operation accepts a closed `with` object containing only `equal` and
   `nonempty` arrays. At least one check is required. Every check has a
   non-empty name, and names are unique across both arrays.
2. An `equal` check contains exactly `name`, `actual`, and `expected`. It uses
   `reflect.DeepEqual` after workflow template rendering, with no type or string
   coercion.
3. A `nonempty` check contains exactly `name` and `value`. Strings, arrays,
   slices, and maps pass only when their length is greater than zero. Nil,
   empty, and scalar values fail.
4. Manifest validation rejects malformed assertion shapes before registration.
   Execution parses the rendered shape again so an internal caller cannot
   bypass the closed contract.
5. The first failed check fails the workflow step. Errors identify only the
   check name. Success metadata contains only names and counts. Compared values,
   response headers, and secret material are never copied into assertion errors
   or metadata.
6. The operation performs no database or provider mutation. Workflow authors
   use it after readback steps when final-state drift must stop the run.

## Consequences

- A final readback can now prove exact desired state and fail the run on drift.
- Workflow authors must choose `condition` for optional execution and `assert`
  for required invariants.
- Exact equality exposes type drift instead of silently coercing it.
- Assertions provide durable pass or fail evidence without persisting the
  inspected values.

## Related

- ADR-0015 (validates workflow inputs before durable async persistence)
- ADR-0016 (keeps provider-generated secrets in private one-step leases)
- ADR-0023 (gates emergency workflow dispatch with an exact allowlist)
