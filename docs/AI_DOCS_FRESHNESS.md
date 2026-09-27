# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: da3b25694e450862cf4e3d91183d5a48273f55a3
verified_diff_sha256: 5e5f55a2139cd2a767930c8fee983d8233e4145c614270d95a19def979544632
reconciler_schema: 1
verified_at: 2026-09-26
by: Codex
note: Reconciled the exact emergency dispatch lock after independent review and kept the active-workflow CI fixture valid so the allowlist assertion reaches the gate. ADR-0023, workflow, deployment, and security docs cover the process-wide gate, paused ingress, external mutation freeze, queue proof, fixed unlock, and separate AWS adapter and ECR policy windows. Generated AI context was refreshed from the source commit. No production rollout is claimed.
