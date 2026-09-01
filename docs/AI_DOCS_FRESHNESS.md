# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 841906015b51edcefa66a1d43deef8fd09efe07b
verified_at: 2026-09-01
by: Codex Didit capability allowlist audit
note: Reconciled the exact create-only webhook secret recovery naming exemption; no broader prose changed.
