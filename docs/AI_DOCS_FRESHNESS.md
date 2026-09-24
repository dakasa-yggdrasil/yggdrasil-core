# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 54c08ec375370e534f2414684bce0347e7abb40c
verified_diff_sha256: c5ca7f37379d22aa913785ebcc422d5ba2b90c9bd8d0e6cc4e337a12b7eba229
reconciler_schema: 1
verified_at: 2026-09-23
by: Claude
note: Reconciled security.md (access links, recovery journeys, reset_mfa password wipe, section 13 fan-out, reset status rule and attempt reservation, issuance lock, recovery flag, created_by) and error_codes.md (policy, reset token and MFA reasons) with the credential handlers after four review rounds. No production rollout is claimed.
