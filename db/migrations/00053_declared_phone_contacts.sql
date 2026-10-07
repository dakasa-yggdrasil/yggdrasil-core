-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS phone_profile_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS public.collaborator_phone_contacts (
    collaborator_id UUID PRIMARY KEY REFERENCES public.collaborators(id) ON DELETE CASCADE,
    phone_ciphertext BYTEA NOT NULL,
    phone_dek BYTEA NOT NULL,
    assurance TEXT NOT NULL DEFAULT 'declared' CHECK (assurance = 'declared'),
    declaration_source TEXT NOT NULL CHECK (declaration_source IN ('self_profile', 'operator_assertion')),
    declared_by TEXT NOT NULL CHECK (declared_by <> ''),
    declared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A private read projection preserves existing collaborator SELECT/scan
-- contracts. The typed column is authoritative; callers cannot spoof or clear
-- it by PATCHing metadata. The scanner removes this key before serialization.
CREATE OR REPLACE FUNCTION public.project_collaborator_phone_requirement()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.metadata := (NEW.metadata - '_yggdrasil_phone_profile_required') ||
        jsonb_build_object('_yggdrasil_phone_profile_required', NEW.phone_profile_required);
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS collaborators_phone_requirement ON public.collaborators;
CREATE TRIGGER collaborators_phone_requirement
    BEFORE INSERT OR UPDATE ON public.collaborators
    FOR EACH ROW EXECUTE FUNCTION public.project_collaborator_phone_requirement();
-- This newly reserved private boolean must also agree with its authoritative
-- column on old rows whose formerly generic metadata could contain the key.
-- No contact values or personal_data are inspected or backfilled.
UPDATE public.collaborators
SET metadata = (metadata - '_yggdrasil_phone_profile_required') ||
    jsonb_build_object('_yggdrasil_phone_profile_required', phone_profile_required)
WHERE metadata->'_yggdrasil_phone_profile_required' IS DISTINCT FROM
    to_jsonb(phone_profile_required);
-- Existing rows keep the default FALSE; no phone or generic personal_data is
-- imported, modified, hashed or declared verified by this migration.
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS collaborators_phone_requirement ON public.collaborators;
DROP FUNCTION IF EXISTS public.project_collaborator_phone_requirement();
DROP TABLE IF EXISTS public.collaborator_phone_contacts;
UPDATE public.collaborators SET metadata=metadata - '_yggdrasil_phone_profile_required'
WHERE metadata ? '_yggdrasil_phone_profile_required';
ALTER TABLE public.collaborators DROP COLUMN IF EXISTS phone_profile_required;
-- +goose StatementEnd
