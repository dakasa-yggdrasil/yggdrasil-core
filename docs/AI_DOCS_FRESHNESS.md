# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f4fa9b573bb6803c70db015e2bc59b979e492d47
verified_diff_sha256: acc1a0ab6e9b19448e7b2dc33937d23dd84c4a9a9874034cb6a0c78c95af0291
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the directory machine principal contract (ADR-0019) after the adversarial review: the directory claim is decided before the public pass-through on every request (public, non-canonical, and unknown routes are refused and audited; the mux redirect is kept only for callers that are not directory attempts), the directory.machine_read row is written synchronously and fail-closed (no outcome without its row; trace ids only from a well-formed W3C traceparent; principal_id bounded to 247), effective actions use the RBAC membership predicate (active team, starts_at/ends_at window) shared with the RBAC subject resolver, and database failures answer a fixed 500 internal.error. The second fix round changed no behavior: ADR-0019 now says the audit row accompanies a refusal only when the credential matched a configured principal (a dedicated header matching no principal is the plain 401 with nothing to attribute), and the absent/inactive 404 test pins Content-Type application/problem+json next to the integration.not_found code because the Social client requires both byte for byte. Console routes are unchanged for human callers. Regenerated .ai/ai_context.json and docs/REPO_SUMMARY.generated.md.
