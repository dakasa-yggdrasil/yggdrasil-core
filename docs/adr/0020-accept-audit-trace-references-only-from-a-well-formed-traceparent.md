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

`recordAudit` reads a second caller-controlled header the same way: the
optional `X-Yggdrasil-Actor`, which lets a caller declare the actor its row is
attributed to, was copied raw into `actor VARCHAR(255) NOT NULL`. A 256
character value is rejected by Postgres exactly like the oversized trace
reference (verified the same way), so every caller allowed on
`POST /api/v1/manifests`, `DELETE /api/v1/manifests/{id}`, and the workflow
template instantiation route could erase the audit line of its own write.
No client in the DaKasa workspace sends that header; the server is its only
reader.

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
- The declared actor follows the same rule. `recordAudit` stores the
  `X-Yggdrasil-Actor` value only when it is in the vocabulary
  `model.AuditEvent` documents, `user:<id>` or `service:<name>` (ASCII
  `[A-Za-z0-9._:@/-]` after the prefix), and at most 255 characters, the
  width of `actor`. Any other value, including an oversized one, is dropped
  and the row is attributed to the actor derived from the credential
  (`service:bearer-token` or `anonymous`), never truncated and never stored.

## Consequences

- An oversized or malformed `traceparent` no longer suppresses the audit row
  of a login, an MFA verification, a manifest write, or a template
  instantiation, and an oversized or malformed `X-Yggdrasil-Actor` no longer
  suppresses the row of a manifest write or a template instantiation. sqlmock
  tests pin that a 200 character trace header and a 256 character actor
  header land the row with empty trace columns and the credential-derived
  actor, that a valid trace header fills both trace columns, and that the
  same holds through the asynchronous `recordAudit` entry point the handlers
  call.
- A caller that used `traceparent` to carry a non-W3C correlation value loses
  it from `audit_events`. Such values were already rejected when longer than
  64 characters and are now dropped at every length. A caller that declared
  an actor outside the `user:` / `service:` vocabulary is now recorded as its
  credential instead; no client in the workspace did.
- The declared actor is still not verified against the credential: a caller
  may attribute its row to any `user:<id>` it names. This decision bounds the
  value to what the column holds; attribution stays as it was.
- The ops audit middleware `withOpsAudit`, which would read
  `X-Correlation-ID` into `correlation_id`, is not attached to any route
  (`controllers/httpapi/ops_audit_middleware.go` is marked `//nolint:unused`
  and nothing calls it). The live ops writer, `recordOpsAuditDenied`
  (`ops.permission.denied`), reads no request header. `correlation_id` is
  `TEXT` but its btree index `audit_events_correlation_idx` (migration 00031)
  rejects values of about 2.7 KB or more (`index row size ... exceeds btree
  version 4 maximum 2704`, verified against Postgres 16), and the server sets
  no `MaxHeaderBytes` below that, so attaching the middleware requires the
  same bounding of that header first.
- The OIDC audit writer (`controllers/oidc/audit.go`) derives its actor from
  the token's collaborator and records no trace reference; it reads no
  request header and is not changed by this decision.

## Related

- ADR-0019 (scope directory machine principals to exact collaborator read routes)
