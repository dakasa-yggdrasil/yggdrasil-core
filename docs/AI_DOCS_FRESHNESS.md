# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: aebbce16934a4c75eafe06670786dd2026041526
verified_diff_sha256: 5695dec94f7db072888d38e2a30823e74b25bdd85063d83d345999d253100cd9
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the audit trace reference contract (ADR-0020): every audit_events writer in the HTTP API (recordAudit, recordAuthAuditSync, and the directory machine-read writer) now takes trace_id and span_id only from a well-formed W3C traceparent through the shared internal/tracecontext parser, so an oversized or malformed header is dropped instead of making Postgres reject the login, MFA, or manifest audit row; docs/security.md gained an Audit trail section, the ADR index lists 0020, and .ai/ai_context.json and docs/REPO_SUMMARY.generated.md were regenerated.
