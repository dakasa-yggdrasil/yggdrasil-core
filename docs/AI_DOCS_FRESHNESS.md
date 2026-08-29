# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 8db53232e4a2a73d65b78d617182ced154b63126
verified_at: 2026-08-29
by: Codex feature-linked audit
note: Reconciled fail-closed RBAC and CSRF, approval immutability, scoped workflow identities, and manifest-backed dispatch authorization.
