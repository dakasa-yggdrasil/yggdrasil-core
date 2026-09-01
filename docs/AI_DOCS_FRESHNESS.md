# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: e9be81d1839b1be13a53ce91cd8d979417ec201e
verified_at: 2026-09-01
by: Codex sensitive-output security audit
note: Reconciled transient workflow secret redaction and route-scoped adapter event publishing.
