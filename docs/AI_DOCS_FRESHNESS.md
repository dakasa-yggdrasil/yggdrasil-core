# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: f290b2a3151310bb9c4cad0c0ffa71fe6526c8e3
verified_at: 2026-08-25
by: local repository reconciliation
note: Reconciled declarative PKCE-only public OIDC client bootstrap and deployment guidance.
