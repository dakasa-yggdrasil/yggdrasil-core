# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 17e0f3dc3d4ade90f3ef24bb877b5bd314e42a44
verified_diff_sha256: a790be3fc499672b400e9e2086f8c00e2fda9a9b4757369263660b59f63d130a
reconciler_schema: 1
verified_at: 2026-09-06
by: Codex
note: Reconciled exact machine-principal authorization, run ownership, workflow input bounds, the private one-step sensitive-output lease, and the merged ADR numbering.
