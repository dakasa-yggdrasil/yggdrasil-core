# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 3266a87c576a8fc6b7d8c8bc6ab724a80368fcf5
verified_diff_sha256: a63f5ca5dbd4bdb593728deb12b90bdb650e4f8e047eb081c91b2ebb44974641
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the audit trace reference contract (ADR-0020) after the findings round: every audit_events writer in the HTTP API (recordAudit, recordAuthAuditSync, and the directory machine-read writer) takes trace_id and span_id only from a well-formed W3C traceparent through the shared internal/tracecontext parser, and recordAudit now stores the declared X-Yggdrasil-Actor only as user:<id> or service:<name> within the 255 character actor column, otherwise the row is attributed to the credential, so neither header can make Postgres reject the login, MFA, or manifest audit row; docs/security.md lists the four httpapi writers plus the OIDC writer and says withOpsAudit is not attached and correlation_id is bounded by its btree index, the ADR index lists 0020, and .ai/ai_context.json and docs/REPO_SUMMARY.generated.md were regenerated.
