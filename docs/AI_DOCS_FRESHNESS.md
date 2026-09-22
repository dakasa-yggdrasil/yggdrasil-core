# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 1ba55fda95bbf2d4b445b3c04decfcb0f55270c7
verified_diff_sha256: 4a3e8ce6b085b31dc7c46ba2a57c6a55be33d2b6a1cc0dc1071a41900bb54de3
reconciler_schema: 1
verified_at: 2026-09-22
by: Codex
note: Reconciled deployment.md with native HTTP loopback classification, mandatory S256 PKCE, exact authorization redirects and the deliberately unchanged loopback logout behavior. This fixes the authorization path described by ADR-0011 without changing its Decision. No production rollout is claimed.
