# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: b290c94f99bf199bb7bb03720c7394dcc1026f3b
verified_diff_sha256: f527888f5fbd1f95e3225641a59a8ecf8f9aacbbd2b972c4b324b52f20b5bc0e
reconciler_schema: 1
verified_at: 2026-09-23
by: Claude
note: Reconciled security.md (access links, recovery journeys, reset_mfa password wipe, section 13 fan-out, reset status rule and attempt reservation, issuance lock, recovery flag, created_by) and error_codes.md (policy, reset token and MFA reasons) with the credential handlers after four review rounds. No production rollout is claimed.
