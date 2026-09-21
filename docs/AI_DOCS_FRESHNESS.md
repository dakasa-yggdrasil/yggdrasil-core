# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: a064227af33bc363efb182dbed03827fb7e86e60
verified_diff_sha256: a9f0025039826786926959a91e25a4052c3074539463c3c45ef5e55143735cb6
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the directory machine principal contract (ADR-0019) after the adversarial review: the directory claim is decided before the public pass-through on every request (public, non-canonical, and unknown routes are refused and audited; the mux redirect is kept only for callers that are not directory attempts), the directory.machine_read row is written synchronously and fail-closed (no outcome without its row; trace ids only from a well-formed W3C traceparent; principal_id bounded to 247), effective actions use the RBAC membership predicate (active team, starts_at/ends_at window) shared with the RBAC subject resolver, and database failures answer a fixed 500 internal.error. Console routes are unchanged for human callers. Regenerated .ai/ai_context.json and docs/REPO_SUMMARY.generated.md.
