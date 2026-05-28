-- +goose Up
-- +goose StatementBegin
--
-- Audit 2026-05-27 A10: per-client OIDC access-token TTL override.
--
-- The global AccessTokenLifetime constant (controllers/oidc/storage.go:31)
-- defaults to 15 minutes, which is reasonable now that §13 RFC 8417
-- back-channel logout makes session revocations propagate in <5s.
-- High-trust clients (privileged surfaces, ops-grade tools) may still
-- want shorter TTLs so a leaked JWT is even less useful.
--
-- This column is the per-client opt-in: NULL means "use the global
-- default"; a positive integer means "issue access tokens with exactly
-- this TTL in seconds". CHECK guards against pathological values
-- (negative or absurdly large lifetimes). Min 60s prevents misconfigured
-- clients from minting 1-second tokens nobody can use; max 1 day
-- prevents accidentally widening past sane bounds.

ALTER TABLE public.oidc_clients
    ADD COLUMN IF NOT EXISTS access_token_lifetime_seconds INTEGER NULL;

ALTER TABLE public.oidc_clients
    DROP CONSTRAINT IF EXISTS oidc_clients_access_token_lifetime_chk;

ALTER TABLE public.oidc_clients
    ADD CONSTRAINT oidc_clients_access_token_lifetime_chk
        CHECK (
            access_token_lifetime_seconds IS NULL
            OR (access_token_lifetime_seconds >= 60 AND access_token_lifetime_seconds <= 86400)
        );

COMMENT ON COLUMN public.oidc_clients.access_token_lifetime_seconds IS
    'Per-client AccessTokenLifetime override in seconds (audit 2026-05-27 A10). NULL = use global default (controllers/oidc/storage.go::AccessTokenLifetime). Bounded [60, 86400].';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.oidc_clients DROP CONSTRAINT IF EXISTS oidc_clients_access_token_lifetime_chk;
ALTER TABLE public.oidc_clients DROP COLUMN IF EXISTS access_token_lifetime_seconds;
-- +goose StatementEnd
