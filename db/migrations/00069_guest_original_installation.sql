-- +goose Up
-- Empty immutable confirmation records. No new principal or permission.
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_installations (
 preregistration_id uuid PRIMARY KEY REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire)>0 AND octet_length(original_wire)<=65536),
 confirmation_sha256 text NOT NULL CHECK(length(confirmation_sha256)=64),
 recorded_at timestamptz NOT NULL
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_guest_original_installation_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable original Guest installation'; END $$;
-- +goose StatementEnd
CREATE OR REPLACE TRIGGER capacity_guest_original_installation_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_original_installations FOR EACH ROW EXECUTE FUNCTION public.capacity_guest_original_installation_immutable();

-- +goose Down
DROP TABLE IF EXISTS public.capacity_guest_original_installations;
DROP FUNCTION IF EXISTS public.capacity_guest_original_installation_immutable();
