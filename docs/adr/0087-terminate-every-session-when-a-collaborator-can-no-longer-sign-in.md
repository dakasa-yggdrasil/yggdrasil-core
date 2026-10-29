# ADR-0087: Terminate every session when a collaborator can no longer sign in

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / collaborator sessions, SSO session reuse, OIDC token issuance and every collaborator status writer
- **Supersedes:** none (closes the session lifecycle follow-up recorded in ADR-0086)
- **Superseded by:** none

## Context

Every login path that opens a session (password and passkey login,
third-party callback, self-service reset, contact OTP) admits only a
collaborator whose status is `active`, one of the five values the
`collaborators_status_check` constraint allows (`pending_start`, `active`,
`on_leave`, `suspended`, `offboarded`). Nothing rechecked the status after
the login:

- `repository.ResolveAuthSession` checked the session row, not the
  collaborator. A session opened while active kept working after a suspend,
  a long leave or an offboard that did not revoke it, and every caller
  trusted it: the console gate, `/auth/session`, the ForwardAuth
  `/auth/verify`, introspection, SAML and the SSO bridges.
- SSO reuse (`/auth/third-party/start` with `auth_request_id`, the OIDC login
  bridge, the SAML IdP) completes an OIDC login from an existing Core
  session, so a suspended human could keep obtaining relying party tokens.
- The human JWT branches of the console gate and of the surface ForwardAuth
  accepted an access JWT for its whole lifetime (15 minutes, or a per-client
  override up to 24 hours) after a status change.
- Only the offboard handler terminated sessions, with its own inline copy of
  the fan-out. Suspend, unsuspend, PATCH, AMQP `collaborator.update`, absence
  start and end, re-onboard and the status clock only set the status, and the
  offboard copy did not revoke OIDC refresh tokens.
- Core access tokens carry `iat` = mint time and no `sid`. The Tartaro
  services keep an iat-aware subject denylist (`iat <= revoked_at`), which
  accepts any token minted after the revocation, so a revocation means
  nothing while Core keeps minting for the subject.

ADR-0086 made the Tartaro effective actions answer nothing for a
collaborator who is not active, and recorded this session lifecycle gap as
a follow-up.

## Decision

A collaborator who can no longer sign in has no live session and gets no
token from Core, whatever path wrote the status:

1. **One predicate.** `collaboratorstate.CanSignIn(status)` is true only for
   `active` (case and surrounding whitespace tolerated, which the constraint
   cannot store). The password login, the third-party callback and the
   self-service reset use it.
2. **Session validity.** `ResolveAuthSession` refuses a session whose current
   collaborator cannot sign in with the unwrapped `ErrAuthSessionNotFound`, so
   every caller answers 401 and clears the cookie. It reads the collaborator
   it already read; nothing caches a session or its collaborator across
   requests, so the refusal applies on the next request.
3. **Human JWT branches.** The console gate JWT branch and ForwardAuth path 1
   (when `sub` is set) re-read the subject in the single read the phone
   profile rule already made and answer 401 when it cannot sign in. The
   workflow and machine branches are unchanged.
4. **OIDC mint gate.** `repository.RequireIssuableSubject` reads status and
   phone profile in one statement: status first
   (`ErrCollaboratorCannotSignIn`), then the phone profile. The provider
   applies it before honoring an authorization request (including one
   pre-bound at creation), saving a code, exchanging a code (before the code
   is consumed, so a refusal does not burn it), and minting access and
   refresh tokens. The refresh grant answers `invalid_grant` for such a
   subject.
5. **SSO reuse** needs no code of its own: it resolves the session through
   `ResolveAuthSession`, so it falls back to the interactive login, whose
   callback refuses anyone who cannot sign in.
6. **One termination primitive.** `repository.TerminateCollaboratorSessionsTx`
   revokes every console session and OIDC refresh token, writes one global
   `session_revocation` row and emits `collaborator.session.terminated`
   (idempotency key `session.terminated.<revocation id>`), in the caller's
   transaction. Credential replacement (setup re-access, reset, MFA reset)
   and status changes share it.
7. **The status choke point is the repository.** `UpdateCollaboratorTx` runs
   the session policy after the version-checked UPDATE, in the same
   transaction, and `UpdateCollaborator` wraps it in its own transaction, so
   every status writer applies it (suspend, unsuspend, PATCH on both routes,
   AMQP `collaborator.update`, absence start and end, offboard, re-onboard,
   both branches of the status clock):
   - status unchanged (same-status or non-status write): nothing;
   - the new status cannot sign in: one termination, reason `offboarded` for
     `offboarded` and `admin_revoked` otherwise, metadata `{source:
     "collaborator_status_change", from_status, to_status}`. Every change to a
     status that cannot sign in terminates, including `suspended` to
     `offboarded` and `offboarded` to `pending_start`;
   - the new status can sign in (reactivation): leftover sessions and refresh
     tokens are revoked with no revocation row, event or back-channel, so a
     reactivation never revives a session opened before it.
   Concurrent writers are serialized by the version check (the loser gets
   `ErrConcurrentUpdate` and rolls back), the termination commits or rolls
   back with the status, and a termination failure fails the status write.
   The offboard handler drops its inline copy and emits exactly one
   `session.terminated`.
8. **Back-channel after commit.** When a write set a status that cannot sign
   in, RFC 8417 back-channel logout fires after the commit: on the HTTP
   status writers, on the AMQP consumer and on auto-offboards of the status
   clock, through `BackchannelDispatcherFromEnv` (nil unless
   `YGGDRASIL_OIDC_ISSUER` is set). Dispatch is idempotent and single-shot.

No migration, no new revocation reason and no new event: the
`collaborator.session.terminated` payload contract is unchanged, and its
reactors have no reason filter. Machine principals (directory, event
publish, auth-admin, deploy, workflow) never resolve a session and are
untouched.

## Consequences

- A suspended, on-leave, offboarded or not-yet-started collaborator is
  refused on the next request by every session, reuse and mint path,
  including sessions opened before this change, which are swept at their
  next status change. No `session.terminated` is emitted retroactively for a
  collaborator who was already not active when this change ships.
- Visible behavior changes: a long absence (`on_leave`) now ends sessions,
  while vacation keeps the status `active` and does not; re-onboarding emits
  a `session.terminated`; on offboard, `session.terminated` precedes
  `collaborator.offboarded` in the transaction and the revocation metadata
  becomes `{source, from_status, to_status}` (nothing read
  `offboard_reason`).
- Every `UpdateCollaborator` call, including the reconcile loop's trait
  writes, now runs in a transaction, and every refresh grant costs one
  extra read. A failed termination blocks the status change, including a
  status clock tick (fail closed).
- Back-channel reaches only clients with an `oidc_session_links` row, which
  only the refresh-token path creates. A relying party without
  `offline_access` (the Tartaro panel today) gets no back-channel: its own
  session ends at its next silent re-auth, within one access-token lifetime
  (15 minutes, or a per-client override up to 24 hours), and its Core console
  calls fail at once (item 3). Services that consume the
  `collaborator.session.terminated` reactors revoke their own sessions when
  the event is delivered. Dispatch has no retry or outbox.
- The status clock's first tick at boot can run before the OIDC signing key
  is ensured; its dispatch then fails and is logged, after the refresh tokens
  were already revoked.
- A login that races a status change can write a session or token after the
  revocation; items 2 to 4 refuse it and the next status change sweeps it.
- Follow-ups, outside this decision: `DELETE` of a collaborator (the cascade
  removes the rows and emits nothing); admin revoke-sessions still leaves
  refresh tokens alive; PATCH and status clock offboards still write no
  `collaborator.offboarded` event or offboard lifecycle row; `prompt` and
  `max_age` are ignored; an `id_token_hint` can pre-bind a request for an
  active subject; `POST /api/v1/auth/third-party/login`; reaching relying
  parties without `offline_access` by back-channel (creating links on
  `CreateAccessToken`); userinfo has no status check; outstanding setup,
  reset and enroll links are not invalidated (none of them mints a session
  for a collaborator who cannot sign in).

## Related

- ADR-0086 (records the session lifecycle follow-up this decision closes)
- ADR-0085 (live Tartaro effective actions)
