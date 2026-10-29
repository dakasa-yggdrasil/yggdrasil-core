# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: 0e34f954efe547380b276dcc978fb60081f3dc7a
verified_diff_sha256: ba9cc2db78140b8dcdd4f1dcd171a49e2be66712574f0cde562c55d842d0c068
reconciler_schema: 1
verified_at: 2026-10-29
by: Giomaster
note: Reconciled the collaborator session lifecycle change after review. ADR-0087 records that a collaborator who can no longer sign in (only active signs in, collaboratorstate.CanSignIn) loses every session and gets no token: ResolveAuthSession refuses the session and each caller treats it as unauthenticated (401 with a cleared cookie on the console gate and /auth/session, 401 on /auth/verify, active:false on introspection, interactive login on SSO and SAML reuse), the human JWT branches re-read the subject and refuse a token issued at or before a global session_revocation row, the OIDC provider refuses to honor requests, save or exchange codes and mint tokens (refresh answers invalid_grant), provider introspection, userinfo and Core refresh-token introspection refuse such a subject, only an open authorization request (not consumed, inside its 10 minute lifetime) resumes, terminations and reactivations close bound requests and their codes, every status writer goes through the status session policy in the same transaction, a repeated /offboard terminates again (source offboard_repeat), and back-channel fires after the commit on HTTP, AMQP and the status clock. ADR-0086 is not edited. The ADR index, the CHANGELOG, docs/security.md, docs/features/sessions.md and the session counter note in docs/operations/observability.md match the code; CLAUDE.md does not describe the session lifecycle and needs no change. Static checks only (gofmt, go build, go vet); tests run in CI. No deployment or production change.
