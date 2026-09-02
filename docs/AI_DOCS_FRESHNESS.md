# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: a99134588c2f7db43dd7636abf65a827085b10e8
verified_at: 2026-09-02
by: Codex confidential OIDC lifecycle audit
note: Reconciled owner-native mounted-file bootstrap, input-free readback verification, and PKCE enforcement for confidential clients.
