# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 5ef5501857bd4862675326346653ef91932ba02a
verified_at: 2026-09-09
by: Codex
note: Reconciled the live-baseline authorization hotfix with the full nullable team-email projection, active membership filters, ancestor expansion, and fail-closed behavior. No migration, workflow, credential, dependency, or authorization-policy change is included.
