# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 9e5e2b2b89a55dbf376c338392aa5935c8ebc4aa
verified_diff_sha256: 4e9cc0f81a467370438d476e22b15233300c93cd79cc0ab7c53439e4b449c276
reconciler_schema: 1
verified_at: 2026-10-10
by: Codex
note: Reconciled automatic contact OTP with the explicit owner requirement: saved email/phone require no registration, opt-in or contact factor row. Actual password+OTP proof still precedes sessions. Setup and forced password changes support contact-only accounts; recent session proof is server-issued, short-lived and consumed with the password update. Federated provider auth remains separate. CI only; no production activation. TOTP confirmation is independent of shared MFA posture and commits current-seed proof, recovery codes and enrollment-link consumption atomically.
