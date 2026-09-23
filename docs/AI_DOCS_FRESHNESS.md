# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: b14370b52ee765f02f49bd6738b52ecbb5693129
verified_diff_sha256: b51fffd3aa592d557ab17d2bc46bc5f0aead55f164b96a35ea06abf512d4c37d
reconciler_schema: 1
verified_at: 2026-09-23
by: Claude
note: Reconciled security.md (access links and account recovery journeys, reset email delivery variables) and error_codes.md (password policy, reset token and MFA reasons) with the setup/reset/forgot handlers. No production rollout is claimed.
