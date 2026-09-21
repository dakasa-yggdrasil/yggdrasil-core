# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: c728edab734bbcc7200b3e3b506b8d0b1dee2123
verified_diff_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reviewed the /metrics documentation rebased onto main after #51 and #52: docs/operations/observability.md states the endpoint and scrape contract the code proves and catalogs the 24 families rendered by handleMetrics (types, closed label sets, call sites, recommended expressions), with yggdrasil_directory_audit_failures_total now on main; documentation only.
