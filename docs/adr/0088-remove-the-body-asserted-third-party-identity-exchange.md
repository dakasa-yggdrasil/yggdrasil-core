# ADR-0088: Remove the body-asserted third-party identity exchange

- **Status:** Accepted
- **Date:** 2026-10-29
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / third-party authentication (`/api/v1/auth/third-party/*`)
- **Supersedes:** none (closes the `POST /api/v1/auth/third-party/login` follow-up recorded in ADR-0087)
- **Superseded by:** none

## Context

Core had two kinds of third-party login:

- The browser flow. `GET /api/v1/auth/third-party/start/{provider}` signs a
  state cookie and redirects to the provider. `GET
  /api/v1/auth/third-party/callback/{provider}` verifies that state, exchanges
  the provider's authorization code with the provider's token endpoint, reads
  the provider's userinfo, and only then calls
  `repository.AuthenticateWithThirdPartyIdentity` with the provider, subject
  and email the provider returned.
- `POST /api/v1/auth/third-party/login`. Its handler decoded
  `model.LoginWithThirdPartyIdentityRequest` from the request body (provider,
  subject, email, `auto_link_by_email`, claims, session metadata) and passed
  it straight to `repository.AuthenticateWithThirdPartyIdentity`, which treats
  its input as an identity a provider already verified.

The route was public. `/api/v1/auth/*` is outside the console gate
(`requiresAuthenticatedConsoleAPI`), the `/api/v1/auth/third-party/` prefix is
exempt from CSRF, the route had no rate limit, and `TestNoUngatedMutatingRoutes`
listed it as an intended pre-session route. Any anonymous caller could:

- send `auto_link_by_email: true` with the e-mail of any active collaborator
  and any subject: Core linked a new third-party identity for that subject to
  the collaborator and opened a session;
- send the provider and subject of an identity that was already linked: Core
  opened a session for its collaborator.

`createThirdPartyAuthSession` checks only that MFA is enrolled
(`mfa_enrolled_at`); it never asks for a factor, because in the browser flow
the provider is the authentication. So a collaborator with MFA enrolled got a
session at once, and the session carried their full authority: the console,
and SSO session reuse on third-party start, which completes OIDC logins for
relying parties.

A collaborator without MFA enrolled was exposed too. That includes a
collaborator who signs in with e-mail or SMS codes from saved contacts, which
needs no factor enrollment. For them the route returned the enroll-required
answer (428), and that answer carried a fresh MFA enroll link for the
collaborator, valid for seven days, together with the collaborator record.
The factor enroll routes accept that link without a session, so the caller
could enroll an authenticator of their own; repeating the request then
opened a session. On the auto-link path the identity is linked before the
MFA check, so the link stays after the 428. Before MFA enrollment was
enforced on this path (May 2026), the route opened a session with no MFA
condition at all. Every active collaborator was therefore exposed for the
whole life of the route, not only those with MFA enrolled.

On 2026-10-29 production answered `400 third-party provider is required` to
an empty body, so the handler was reachable. A read-only check found two
third-party identities in production, both with provider `google`, created
on 2026-05-15 and 2026-06-10, with numeric subjects in the shape Google
issues. That is weak evidence. The route let the caller choose both the
provider and the subject, so a forged link can have the same shape, and on
the subject path the route overwrote the identity's e-mail, claims, display
name and `last_authenticated_at` with caller values. The identity table also
shows only the links that exist now, and the subject path, with or without
the enroll link, adds no identity row. Whether the route was abused is still
open; see the follow-up audit under Consequences.

No first-party client needs the route. The console never offers it. The
known callers are the `surface-auth` reverse proxy, which listed it among the
paths it forwards, and a smoke script in the `yggdrasil` CLI repository that
used exactly the auto-link shape. ADR-0087 recorded the route as an open
follow-up.

## Decision

1. Remove `POST /api/v1/auth/third-party/login` and its handler. Core has no
   route that opens a session from a provider, subject or e-mail the caller
   supplies. Third-party login is only the browser flow: `GET
   /api/v1/auth/third-party/start/{provider}` and `GET
   /api/v1/auth/third-party/callback/{provider}`, both unchanged. Every method
   and spelling of the removed path now falls through to the mux, which
   answers 404 without reading the database or setting a cookie.
2. Keep `repository.AuthenticateWithThirdPartyIdentity` and
   `model.LoginWithThirdPartyIdentityRequest`. The browser callback is their
   only caller and builds the request from the provider's own token exchange
   and userinfo. A future caller must do the same: take the identity from a
   provider exchange Core performed itself, never from the request.
3. Skip the one-release deprecation window of the API stability contract.
   The route is a security exposure, not a contract to migrate, and its known
   callers (a proxy path list and a smoke step) change in their own
   repositories.
4. Until a Core without the route runs in production, the production ingress
   refuses it: a rule in front of production Core answers 403 to every
   spelling of the path (letter case, repeated slashes, an encoded slash, a
   trailing slash) before the request reaches Core, and every other route
   keeps working. The rule is removed once the live production Core no
   longer registers the route. That is checked on the content of the source
   revision named by the running image's revision label: its
   `controllers/httpapi/server.go` registers no `third-party/login` route,
   and a route census kept at that revision, if any, no longer lists it. It
   is not checked by commit ancestry, because the production build can carry
   this change as a port with a different commit, and not against a catalog
   pin or the merge of this change.
5. Guard against a return. The route leaves the `TestNoUngatedMutatingRoutes`
   allowlist, so registering it again without a gate fails CI. A unit test
   drives the real router and requires 404 or 405, no cookie and no database
   access for the removed path, and that start and callback still reach their
   handlers. A PostgreSQL gate in the native OIDC integration workflow proves
   against the migrated schema that the removed path links and signs in
   nobody, and that the browser flow still links an active collaborator by
   e-mail, signs the linked identity in again and refuses a forged state.

## Consequences

- Breaking for any client that still calls the route: it gets 404. The
  `surface-auth` proxy drops the path, and the CLI smoke drops the step,
  because its browser OIDC check through a mock provider already covers
  third-party login.
- Production Core keeps the handler until the next production Core
  candidate, which must include this change. The ingress rule is the control
  in the meantime; removing it before that image is live reopens the
  exposure. A candidate built from another branch must port the whole
  change: the code, any generated route census that branch keeps, and the
  PostgreSQL step of Decision 5, which otherwise runs only on `main`.
- The CSRF exemption for the `/api/v1/auth/third-party/` prefix now covers
  only GET routes, which the CSRF middleware does not check. It is left as
  is.
- Follow-up, outside this decision: audit whether the route was used while
  it was public, over the whole window from the first production deployment
  to the ingress rule. The audit rests on what was recorded:
  - Core's request log lines (`http request served`) for the removed path,
    within the log store's retention. No first-party client calls it, so
    every 200 (a session) or 428 (an enroll link) is suspect, and other
    statuses show probing.
  - Sessions whose metadata has `auth_method: third_party`, grouped by the
    server-set `third_party_identity` provider and subject, against the
    identities that exist. The `auth_flow` value is not evidence: the route
    copied caller-supplied session metadata, so a caller could have set
    `browser_callback` themselves.
  - MFA enroll tokens issued in the window (collaborator, creation time,
    consumption time), authenticator confirmations, first `mfa_enrolled_at`
    values and passkeys added in the window, matched against the enroll
    links the legitimate flows issued. Start with the collaborators who own
    the two Google identities: their subjects are global provider ids that
    may be known outside DaKasa.
  - Each third-party identity's stored e-mail, claims and display name
    compared with the real provider account, and the provider's own sign-in
    or OAuth audit for Core's client matched against each third-party
    session.

  Two kinds of record cannot help. The session `remote_addr` and
  `ip_address` values are the TCP peer, which behind the ingress is the
  ingress itself for every session, so Core recorded no client address for
  these logins. Core defines a third-party login audit event, but no handler
  emits it, so the audit event store holds no trail of them. Recording the
  forwarded client address on sessions and emitting that audit event are
  separate follow-ups.

## Related

- ADR-0087 (records this route as a follow-up of the session lifecycle; this decision closes it)
- ADR-0003 (Core as DaKasa's OIDC provider, mediating third-party login)
