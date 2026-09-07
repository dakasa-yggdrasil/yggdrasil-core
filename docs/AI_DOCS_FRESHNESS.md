# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: de81ef641904c791754063e628a41abbab798a74
verified_diff_sha256: d49f29e2f4416687fb5436adcb1299e8ee0a654daa14c6dc6f70434b7b78a2c4
reconciler_schema: 1
verified_at: 2026-09-06
by: Codex
note: Reconciled the explicit Kubernetes pod_exec capability naming exception after merging current machine-principal authorization.
