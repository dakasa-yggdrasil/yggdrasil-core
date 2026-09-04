# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: ff33edd8f25cb2ef2b6a1e1bca93197551c77a4e
verified_at: 2026-09-04
by: workflow templating pass-through generalisation
note: Reconciled docs/api-reference/openapi.md with the generalised {{ }} pass-through: any token whose leading segment is not a Yggdrasil context root (inputs/steps/metadata/auth/workflow/each) ships back verbatim, so declarative_apply can carry Grafana/Prometheus ConfigMap blobs; a bad path under a real root still fails loudly.
