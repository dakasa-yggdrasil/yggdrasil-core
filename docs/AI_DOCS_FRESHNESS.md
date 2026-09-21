# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 7c8e64ad094c6a34fb453edf70972d57c5a68bfd
verified_diff_sha256: 77e78d6a8d6ae215a8041a1ae1b9fd5718736017de54d120273c7f6417c6fa22
reconciler_schema: 1
verified_at: 2026-09-21
by: Claude
note: Reconciled the Core #50 follow-ups and their review round, rebased on the ADR-0020 shared traceparent parser: the directory machine inventory is loaded and validated once in New and held on the Server (rotation takes effect at the next boot, a malformed inventory can only refuse the boot), every directory.machine_read outcome withheld for a failed audit write is counted in yggdrasil_directory_audit_failures_total{reason=store_unconfigured|insert_timeout|insert_failed} on /metrics, the alert rule YggdrasilDirectoryAuditWithheld ships in monitoring/prometheus/yggdrasil-directory-audit-alerts.yaml with a test that binds it to the rendered family and reason set, ADR-0019 says the operator loads that rule like the sibling files instead of claiming an alert exists, the CHANGELOG Unreleased entry records the boot-time inventory, the counter and the rule, and .ai/ai_context.json and docs/REPO_SUMMARY.generated.md were regenerated.
