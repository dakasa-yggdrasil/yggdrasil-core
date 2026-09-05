# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f90ff11a836a769130057dcdfe98c713353cbed3
verified_at: 2026-09-05
by: machine-principal authorization hardening
note: Reconciled hash-only workflow and event principals, exact scopes, mandatory workflow authorization, forced async ownership and panic safety, route isolation, expiring mutation-only bridges, and quarantine of the generic deploy emitter.
