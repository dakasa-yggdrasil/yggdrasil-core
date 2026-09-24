-- +goose Up
-- +goose StatementBegin

-- created_by was always NULL until setup links started recording the admin
-- who issued them. It was also the only foreign key to collaborators with no
-- ON DELETE action, and nothing prunes auth_credential_tokens, so recording
-- an admin would have blocked deleting that admin forever. Attribution also
-- lives in the event log actor and the audit row, so losing it here on
-- delete is fine, the same way granted_by and updated_by behave.
ALTER TABLE public.auth_credential_tokens
    DROP CONSTRAINT IF EXISTS auth_credential_tokens_created_by_fkey,
    ADD CONSTRAINT auth_credential_tokens_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES public.collaborators(id) ON DELETE SET NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.auth_credential_tokens
    DROP CONSTRAINT IF EXISTS auth_credential_tokens_created_by_fkey,
    ADD CONSTRAINT auth_credential_tokens_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES public.collaborators(id);
-- +goose StatementEnd
