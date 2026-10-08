# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 5981a6b1fd14a586535af74e3715671de4ac5c94
verified_diff_sha256: b0c02ff7da34c8944008642c6c5c726efff956f69fb3fa0f30b04df7f02bd989
reconciler_schema: 1
verified_at: 2026-10-08
by: Codex
note: Reviewed contact OTP MFA plus the readiness correction. Factor removal counts only configured contacts and decryptable SMS recipients; possession, directory declarations, provider acceptance and human receipt remain separate. CI runs the tests. No production activation is claimed.
