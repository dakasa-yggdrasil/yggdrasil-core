# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f0029ca17a8bd063e23d553398468c737044d1e4
verified_at: 2026-09-01
by: Codex integration instance policy audit
note: Reconciled generic and typed integration instance write validation, including credential policy and hydrated schemas.
