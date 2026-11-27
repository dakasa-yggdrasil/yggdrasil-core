# AI docs freshness stamp

verified_at_commit: 50ea03c0fa8ac1402295f31dd3cde696a1ffa285
verified_diff_sha256: 24f9cf01bb9eb5800d4bda2ea193bc7e432338d08456dbc4fd65b7e6cd5fd52c
reconciler_schema: 1

Reviewed the expired original-command closure against the existing one-send
arbiter, private command context, original custody, Attempt and event history.
Only a revision-one reserved child with no physical birth, Node or original
return can close after its immutable deadline. SQL retains the original
context and forbids later fabricated custody, substituted final birth fields,
reopening or history deletion. Schema116 rollback restores the exact schema115
Attempt guard only when no retained closure exists.

The complete Source census preserves all897 inherited facts and adds the one
new production file, totaling898 under unchanged v2 bounds. Four CI-only
PostgreSQL roots cover the real clock/deadline, exposed sends, concurrent
closure, private custody, scope gates and immutable rollback. Required schema
readback includes the new table. Independent whole review has no open finding.

Only cheap static checks and deterministic Source/reconciliation/context
generators ran locally. Tests, compilation and analysis remain in CI. This
Source does not install a controller or perform provider/network/Node actions.
