# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 0bf4e7213e7881282d3f4b187e4cbfd7f44db9de
verified_at: 2026-09-05
by: AMQP dependency security reconciliation
note: Reconciled the changelog with the v1.13.0 frame-allocation bound and confirmed Core's amqp.Dial call sites do not opt into the new experimental automatic recovery behavior.
