# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 6295de17e49f5ab53bafe88c3e680fc3a247f082
verified_diff_sha256: e8e2a4c3353af4e18a741d1aea5ff3c6c4da1fa4907cc7180d3a5d4f9601302b
reconciler_schema: 1
verified_at: 2026-10-10
by: Codex
note: Reconciled automatic contact OTP with the explicit owner requirement: saved email/phone require no registration, opt-in or contact factor row. Actual password+OTP proof still precedes sessions. Setup and forced password changes support contact-only accounts; recent session proof is server-issued, short-lived and consumed with the password update. Federated provider auth remains separate. CI only; no production activation.
