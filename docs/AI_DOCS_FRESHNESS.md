# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 2dab0c1fcdbb8117a218cf78f4f59ce56cdd59ec
verified_diff_sha256: 07820a3a569cd845a5ef4a0c7d586542f2c2ee9aa3ecf83decef981209d8a21b
reconciler_schema: 1
verified_at: 2026-09-05
by: machine-principal and workflow input boundary hardening
note: Reconciled hash-only machine principals, exact workflow authorization and run ownership, plus pre-persistence enforcement of workflow string pattern and maxLength constraints while preserving the integration max_length contract.
