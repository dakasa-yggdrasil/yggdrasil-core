# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 1570001687ebb59d7c68b21fecda32fd36da49dd
verified_at: 2026-08-05
by: rollout (docs-freshness convention)
note: Establishes the stamp. Not yet AI-reconciled.
