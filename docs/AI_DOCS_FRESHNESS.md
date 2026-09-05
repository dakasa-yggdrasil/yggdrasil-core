# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 63bf59b209679dadaaa4af967b574dea52336730
verified_at: 2026-09-04
by: workflow input persistence hardening
note: Reconciled ADR-0015 and docs/features/workflows.md with pre-insert workflow validation, explicit additionalProperties false enforcement, and durable redaction of top-level secret or sensitive inputs while retaining the execution copy only in memory.
