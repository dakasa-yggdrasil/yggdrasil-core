# ADR-0020: Accept audit trace references only from a well-formed traceparent

- **Status:** Accepted
- **Date:** 2026-09-21
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / audit_events writers
- **Supersedes:** none
- **Superseded by:** none

## Context

`audit_events` (migration 00017) stores `trace_id VARCHAR(64)` and
`span_id VARCHAR(32)` so an audit row can be joined to a distributed trace.
The HTTP writers take that reference from the inbound `traceparent` header,
which the caller chooses. ADR-0019 made the directory machine-read writer
accept only a well-formed W3C header, but the two older writers still copied
the raw header into `trace_id`: `recordAudit` (manifest create and delete,
warnings persistence, workflow template instantiation) and
`recordAuthAuditSync` (the closed `auth.*` set: login, MFA, session, and
password outcomes).

A header longer than 64 characters makes Postgres reject the whole INSERT
(`value too long for type character varying(64)`, verified against Postgres
16 with migration 00017 applied). Both writers are fire-and-forget, so the
rejection is only a warning in the log and the row of the very action being
audited is lost. A caller could erase its own `auth.login.*` or `auth.mfa.*`
line by sending a 65 character header. Three copies of the same rule would
also drift.

## Decision

One parser, `internal/tracecontext.ParseTraceparent`, is the only source of
`trace_id` and `span_id` for every `audit_events` writer in the HTTP API. It
returns the trace-id and parent-id of a header in the W3C form
`version-traceid-parentid-flags` (lowercase hex, version other than the
reserved `ff`, non-zero ids) and empty strings for anything else: absent,
malformed, uppercase, trailing fields, reserved version, all-zero ids, or
oversized. A value that does not parse is dropped, never truncated and never
stored, so the header alone can never make the database reject an audit row.

- `controllers/httpapi.requestTraceIDs` wraps the parser for the HTTP
  writers and tolerates a nil request. `recordAudit`, `recordAuthAuditSync`,
  and the directory machine-read writer all take their reference from it.
- The row shape is unchanged: a valid header fills both columns, anything
  else leaves both NULL. No other column is derived from the header.
- The parser rejects exactly what the directory parser of ADR-0019 rejected;
  its cases moved to the shared package with it.

## Consequences

- An oversized or malformed `traceparent` no longer suppresses the audit row
  of a login, an MFA verification, a manifest write, or a template
  instantiation. sqlmock tests pin that a 200 character header lands the row
  with empty trace columns and that a valid header fills them.
- A caller that used `traceparent` to carry a non-W3C correlation value loses
  it from `audit_events`. Such values were already rejected when longer than
  64 characters and are now dropped at every length. `X-Correlation-ID` on
  the ops routes is unaffected: the ops middleware stores it in the unbounded
  `correlation_id` column and never in `trace_id`.
- The OIDC audit writer records no trace reference today and is not changed
  by this decision.

## Related

- ADR-0019 (scope directory machine principals to exact collaborator read routes)
