-- +goose Up
-- +goose StatementBegin

-- Adds an optional team email so integrations (Google Workspace groups,
-- Slack channel email integration, notification targets) can resolve a
-- canonical contact per team. NULL = unset (no integration writes use it).
--
-- Format validation is enforced at the model layer (RFC 5322 simplified),
-- not via CHECK constraint, so legacy rows with empty strings are accepted.
ALTER TABLE public.teams
    ADD COLUMN IF NOT EXISTS email TEXT NULL;

-- Index for reverse lookups (find team by email — useful for inbound
-- routing scenarios). Allows duplicates because legacy data + alias use
-- cases may overlap.
CREATE INDEX IF NOT EXISTS teams_email_idx
    ON public.teams (email)
    WHERE email IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS teams_email_idx;
ALTER TABLE public.teams DROP COLUMN IF EXISTS email;
-- +goose StatementEnd
