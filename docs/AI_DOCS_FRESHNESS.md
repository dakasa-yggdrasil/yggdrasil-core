# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: c05f5960a9a8e5c7204e8d80503241175756ef54
verified_diff_sha256: fc0624654b6b97761275a61fe19b8fdf5a10d2cfe1d21318a0355a664ec67ac3
reconciler_schema: 1
verified_at: 2026-09-26
by: Codex
note: Reconciled the exact emergency dispatch lock after independent review. ADR-0023, workflow, deployment, and security docs cover the process-wide gate, paused ingress, external mutation freeze, queue proof, fixed unlock, and separate AWS adapter and ECR policy windows. Generated AI context was refreshed from the source commit. No production rollout is claimed.
