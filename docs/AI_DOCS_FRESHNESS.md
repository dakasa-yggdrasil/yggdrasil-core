# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: ca920b98b031fbb55752f96a455d4d6c9c2630bc
verified_diff_sha256: 9001bfaea294fc4e26c9b7c9802fdb47ba0891212e0f3b24c5870378b6e96153
reconciler_schema: 1
verified_at: 2026-10-06
by: Codex
note: Rechecked exact sensitive grants against canonical active manifest versions after CI exposed a schema assumption and a test import. Declared contact, provisional access/recovery, snapshot and cutover contracts remain current. No deployment or live contact/grant mutation is claimed.
