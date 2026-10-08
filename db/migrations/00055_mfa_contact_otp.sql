-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.auth_mfa_contact_factors (
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    contact_binding TEXT NOT NULL CHECK (contact_binding <> ''),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collaborator_id, channel)
);

CREATE TABLE IF NOT EXISTS public.auth_mfa_contact_challenges (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    purpose TEXT NOT NULL CHECK (purpose IN ('enroll', 'login')),
    context_binding TEXT NOT NULL CHECK (context_binding <> ''),
    contact_binding TEXT NOT NULL CHECK (contact_binding <> ''),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    consumed_at TIMESTAMPTZ NULL,
    delivered_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Failed sends remain in this table and consume the same sending budget.
CREATE INDEX IF NOT EXISTS auth_mfa_contact_challenges_quota_idx
    ON public.auth_mfa_contact_challenges (collaborator_id, channel, created_at DESC);
CREATE INDEX IF NOT EXISTS auth_mfa_contact_challenges_created_idx
    ON public.auth_mfa_contact_challenges (created_at);

-- A -> B -> A must never restore email proof from the first declaration.
-- Every writer holds the collaborators row lock, also the first lock in the
-- OTP repositories, so recipient replacement and proof are serialized.
CREATE OR REPLACE FUNCTION public.invalidate_changed_email_mfa()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF LOWER(BTRIM(NEW.primary_email)) IS DISTINCT FROM LOWER(BTRIM(OLD.primary_email)) THEN
        DELETE FROM public.auth_mfa_contact_factors
        WHERE collaborator_id=NEW.id AND channel='email';
        UPDATE public.auth_mfa_contact_challenges SET consumed_at=NOW()
        WHERE collaborator_id=NEW.id AND channel='email' AND consumed_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS collaborators_changed_email_mfa ON public.collaborators;
CREATE TRIGGER collaborators_changed_email_mfa
    AFTER UPDATE OF primary_email ON public.collaborators
    FOR EACH ROW EXECUTE FUNCTION public.invalidate_changed_email_mfa();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS collaborators_changed_email_mfa ON public.collaborators;
DROP FUNCTION IF EXISTS public.invalidate_changed_email_mfa();
DROP TABLE IF EXISTS public.auth_mfa_contact_challenges;
DROP TABLE IF EXISTS public.auth_mfa_contact_factors;
-- +goose StatementEnd
