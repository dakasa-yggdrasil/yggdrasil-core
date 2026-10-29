# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: ebaddb28f00cfd492fcf32612da9dc65e816a783
verified_diff_sha256: 7a9ee2553cbcaf304ac4554c735bc7ad85c3909605f5c27d3aecccb18c10acf6
reconciler_schema: 1
verified_at: 2026-10-29
by: Giomaster
note: Reconciled the live Tartaro effective actions change after review. ADR-0085 retires the materialized tartaro_actions trait (sync route, console trait and drift fields, migration script and committed binary) and supersedes ADR-0009; ADR-0086 records the shared authorization predicate, the active-record policy (a collaborator who is not active gets empty sets on the console variant and 404 on the directory variant), the god_mode verdict, the permission-catalog wildcard expansion that fails closed, the god_mode key added to the minimal directory projection with its strict-decoder rollout precondition, and the suspend session lifecycle follow-up. docs/security.md, CLAUDE.md, the CHANGELOG (breaking labels, older directory bullet corrected) and the ADR index match the code. Static checks only (gofmt, go build, go vet); tests run in CI. No deployment or production change.
