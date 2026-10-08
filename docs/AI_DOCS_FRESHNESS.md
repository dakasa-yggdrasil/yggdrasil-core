# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 9b63c2849f30b9a613d0463456c268685c57993a
verified_diff_sha256: 7c005b0ffa640d3a556f5d44b510081d7bea92d1a5a037eee6afae6fd83ade8c
reconciler_schema: 1
verified_at: 2026-10-08
by: Codex
note: Reconciled contact OTP MFA and API contracts against current main plus the implementation diff. Contact possession, declared directory assurance, provider acceptance and actual receipt are distinct. Recovery requires independent proof. CI is the only test environment; provider activation remains a deployment step.
