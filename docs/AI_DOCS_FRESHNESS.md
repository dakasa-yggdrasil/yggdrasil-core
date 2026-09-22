# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: be89ef9f6d9c4bd8ddf5e2c20b21e3d7e0bd8beb
verified_diff_sha256: 09cf3002eb3ffa2f824b489d9107566fd5a57241cb22f2fa13a76eb26de5d5c4
reconciler_schema: 1
verified_at: 2026-09-22
by: Codex
note: Reconciled deployment.md with the mandatory PostgreSQL-backed native OIDC protocol gate. Real external identity-provider login remains a separate acceptance step; no production rollout is asserted.
