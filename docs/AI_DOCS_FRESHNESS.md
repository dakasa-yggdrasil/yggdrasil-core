# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 1e0641146b79bb9e26682af42d45278d17918eae
verified_diff_sha256: 7b706309fa87aef2cdfc5d1e5f31a6bf607abdb2eb62212263f25d1b79231ceb
reconciler_schema: 1
verified_at: 2026-09-09
by: Codex
note: Reconciled the nullable team email projection in human authorization subject expansion, active-membership filters, ancestor preservation, and fail-closed lookup behavior. No auth policy or schema changes.
