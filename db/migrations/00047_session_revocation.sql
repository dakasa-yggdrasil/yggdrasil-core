-- +goose Up
-- +goose StatementBegin

-- §13 INTEGRATION_CONTRACT: session lifecycle is centrally authoritative.
-- This table records every revocation event so that downstream consumers
-- (RFC 7662 introspection callers, RFC 8417 back-channel logout dispatch,
-- audit/security review) can answer "is this collaborator's session valid
-- right now, regardless of the underlying token format?" with a single
-- lookup.
--
-- The row is the authoritative revocation marker. Either:
--   - session_jti points at a specific auth_sessions.id and only that
--     session is revoked (logout from one device); or
--   - session_jti is NULL and the row revokes EVERY active session for
--     the collaborator since revoked_at (admin revoke, password rotation,
--     offboarding).
--
-- Introspection logic: a token is active when (a) the underlying session
-- row is active AND (b) no session_revocation row exists for the
-- (collaborator_id, session_jti) pair with revoked_at >= iat. The session
-- table alone is insufficient because OIDC issues stateless JWT access
-- tokens whose lifetime survives the session DELETE — the audit gap fixed
-- here (cf. controllers/oidc/storage.go:498 "we cannot recall them").
CREATE TABLE IF NOT EXISTS public.session_revocation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    -- When NULL: revoke ALL sessions issued before revoked_at.
    -- When set: revoke this specific session only.
    session_jti UUID NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Stable machine-readable strings. Add to the CHECK list when adding a
    -- new revocation source.
    reason VARCHAR(32) NOT NULL CHECK (reason IN (
        'logout',
        'admin_revoked',
        'password_rotated',
        'offboarded',
        'session_expired',
        'mfa_reset'
    )),
    -- Populated by the RFC 8417 dispatcher when every registered OIDC client
    -- with an active session for this collaborator has either acknowledged
    -- the logout_token or its dispatch has failed past retry. NULL while
    -- dispatch is pending or no OIDC clients had to be notified.
    broadcast_completed_at TIMESTAMPTZ NULL,
    -- Free-form context for forensics (originating IP, user-agent, admin id
    -- of the revoker, etc.). Kept JSONB so we don't pay column add overhead
    -- every time we want to enrich the log.
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS session_revocation_collaborator_idx
    ON public.session_revocation (collaborator_id, revoked_at DESC);

CREATE INDEX IF NOT EXISTS session_revocation_jti_idx
    ON public.session_revocation (session_jti)
    WHERE session_jti IS NOT NULL;

-- §13 INTEGRATION_CONTRACT: OIDC clients that opt in to RFC 8417
-- back-channel logout publish a HTTPS URL where yggdrasil-core POSTs a
-- signed logout_token whenever the user's session terminates. Clients
-- that haven't opted in (legacy consumers) fall back to RFC 7662
-- introspection per request.
ALTER TABLE public.oidc_clients
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT;

-- Sessions ↔ OIDC client mapping: every time the OIDC OP issues a token
-- pair for a user against a client, we record the pair so the back-channel
-- dispatcher knows where to send the logout_token. The row is removed
-- when the underlying auth_session is revoked OR when the OIDC refresh
-- chain rotates out.
CREATE TABLE IF NOT EXISTS public.oidc_session_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES public.oidc_clients(client_id) ON DELETE CASCADE,
    -- The yggdrasil auth_session that backs this OIDC client session.
    -- Null when the OIDC token was issued outside an auth_sessions context
    -- (third-party SSO direct, future flow). NULL rows still receive
    -- back-channel logout when the collaborator has a global revocation.
    session_id UUID NULL REFERENCES public.auth_sessions(id) ON DELETE CASCADE,
    -- RFC 8417 sid claim — surfaced in the logout_token so the client can
    -- correlate. We mint a UUID per (collaborator, client, session) tuple.
    sid UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Marks the row inactive once a back-channel logout has been
    -- successfully dispatched (or after a definitive failure). We keep
    -- the row for audit and only purge via the periodic cleanup addon.
    terminated_at TIMESTAMPTZ NULL,
    UNIQUE (collaborator_id, client_id, sid)
);

CREATE INDEX IF NOT EXISTS oidc_session_links_lookup_idx
    ON public.oidc_session_links (collaborator_id)
    WHERE terminated_at IS NULL;

CREATE INDEX IF NOT EXISTS oidc_session_links_session_idx
    ON public.oidc_session_links (session_id)
    WHERE session_id IS NOT NULL AND terminated_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.oidc_session_links;
ALTER TABLE public.oidc_clients DROP COLUMN IF EXISTS backchannel_logout_uri;
DROP TABLE IF EXISTS public.session_revocation;

-- +goose StatementEnd
