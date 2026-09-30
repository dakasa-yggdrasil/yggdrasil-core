# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 60d4f5aa5cb2fb54f99573e8316016d235feff4c
verified_diff_sha256: 4de239e8a312274a506438de399a37c2ba52744b1a42a32e464f309fbdf6004f
reconciler_schema: 1
verified_at: 2026-09-30
by: Codex
note: Reconciled scheduled workflow terminal status and completion event documentation against the scheduler fix. The event now carries the persisted scheduled run ID after finalization; no production rollout is claimed.
