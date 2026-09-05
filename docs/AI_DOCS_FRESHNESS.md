# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 6f83ab03d8c931c11ebc785bf782a2cdb219a83a
verified_at: 2026-09-05
by: managed-secret HTTP read hardening
note: Reconciled docs/features/secrets.md and docs/operations/security-hardening.md with metadata-only managed-secret views that expose key names but never raw values or value-derived masks.
