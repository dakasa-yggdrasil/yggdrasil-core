# AI docs freshness stamp

Records the commit an AI (or agent-assisted human) last reconciled these docs at.
The docs-freshness CI reads it: a PR that bumps it is trusted and the AI is skipped
(economy path). See the "Docs freshness" rule in AGENTS.md / CLAUDE.md.

Before a PR: update stale docs, set verified_at_commit to your branch tip.
On arrival: if this is behind the code you touch, reconcile the docs FIRST.

verified_at_commit: cbea3a101cb27dc5de071f984382d897c417cefa
verified_diff_sha256: 8d38c4a946b7eed1d4482ed46cc35ec1f3a1adba360e72c1fd857f53e368c8ad
reconciler_schema: 1
verified_at: 2026-10-29
by: Giomaster
note: Reconciled the collaborator session lifecycle change. ADR-0087 records that a collaborator who can no longer sign in (only active signs in, collaboratorstate.CanSignIn) loses every session and gets no token: ResolveAuthSession refuses the session (so SSO reuse falls back to the interactive login), the console gate JWT branch and ForwardAuth path 1 re-read the subject, the OIDC provider refuses to honor requests, save or exchange codes and mint tokens (refresh answers invalid_grant), every status writer goes through UpdateCollaboratorTx, which terminates once in the same transaction or revokes leftovers on reactivation, the offboard handler no longer keeps its own fan-out, and back-channel fires after the commit on HTTP, AMQP and the status clock. ADR-0086 is not edited. The ADR index, the CHANGELOG, docs/security.md, docs/features/sessions.md and the session counter note in docs/operations/observability.md match the code; CLAUDE.md does not describe the session lifecycle and needs no change. Static checks only (gofmt, go build, go vet); tests run in CI. No deployment or production change.
