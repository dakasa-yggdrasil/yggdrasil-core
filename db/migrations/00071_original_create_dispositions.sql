-- +goose Up
-- A disposition closes an independently read historical lifetime. The owning
-- accepted grant/state/settlement remain unchanged and permanently retained.
CREATE TABLE public.capacity_original_create_dispositions (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL UNIQUE REFERENCES public.capacity_mutation_grants(id),
 preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 original_grant_sha256 text NOT NULL CHECK(original_grant_sha256 ~ '^[0-9a-f]{64}$'),
 original_preregistration_sha256 text NOT NULL CHECK(original_preregistration_sha256 ~ '^[0-9a-f]{64}$'),
 disposition_sha256 text NOT NULL UNIQUE CHECK(disposition_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 disposition_record jsonb NOT NULL CHECK(jsonb_typeof(disposition_record)='object'),
 recorded_at timestamptz NOT NULL,
 closed_generation bigint NOT NULL CHECK(closed_generation BETWEEN 1 AND 9007199254740991),
 closed_fencing_token bigint NOT NULL CHECK(closed_fencing_token BETWEEN 1 AND 9007199254740991),
 UNIQUE(id,grant_id),
 CHECK(disposition_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(disposition_sha256=encode(sha256(original_wire),'hex')),
 CHECK((disposition_record->>'schema') IS NOT DISTINCT FROM 'original_accepted_create_disposition_v1'),
 CHECK((disposition_record->>'id') IS NOT DISTINCT FROM id::text),
 CHECK((disposition_record->>'grant_id') IS NOT DISTINCT FROM grant_id::text),
 CHECK((disposition_record->>'preregistration_id') IS NOT DISTINCT FROM preregistration_id::text),
 CHECK((disposition_record->>'original_grant_sha256') IS NOT DISTINCT FROM original_grant_sha256),
 CHECK((disposition_record->>'original_preregistration_sha256') IS NOT DISTINCT FROM original_preregistration_sha256),
 CHECK(closed_generation IS NOT DISTINCT FROM (disposition_record->>'closed_generation')::bigint),
 CHECK(closed_fencing_token IS NOT DISTINCT FROM (disposition_record->>'closed_fencing_token')::bigint),
 CHECK(recorded_at IS NOT DISTINCT FROM (disposition_record->>'recorded_at')::timestamptz)
);
ALTER TABLE public.capacity_mutation_grants ADD COLUMN original_disposition_id uuid;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_original_disposition_matching_grant_fk
 FOREIGN KEY(original_disposition_id,id) REFERENCES public.capacity_original_create_dispositions(id,grant_id);
-- +goose StatementBegin
CREATE FUNCTION public.guard_original_create_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR SHARE;
 SELECT * INTO STRICT p FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 IF p.create_grant_id<>g.id OR g.original_disposition_id IS NOT NULL
 OR g.state<>'settled' OR (g.grant_record->'settlement'->>'outcome') IS DISTINCT FROM 'accepted'
 OR (g.grant_record->'settlement'->>'transport_completed') IS DISTINCT FROM 'true'
 OR NEW.original_grant_sha256<>encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
 OR p.original_wire IS NULL OR NEW.original_preregistration_sha256<>encode(sha256(p.original_wire),'hex')
 OR p.original_deadline>=clock_timestamp()
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id)
 THEN RAISE EXCEPTION 'original create disposition identity or closed original boundary refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER original_create_disposition_insert BEFORE INSERT ON public.capacity_original_create_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_original_create_disposition_insert();
-- +goose StatementBegin
CREATE FUNCTION public.immutable_original_create_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'original create disposition is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER original_create_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_original_create_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_original_create_disposition();
-- +goose StatementBegin
CREATE FUNCTION public.guard_original_create_disposition_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d public.capacity_original_create_dispositions;
BEGIN
 IF OLD.original_disposition_id IS NOT NULL THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'disposed original grant is immutable'; END IF;
 ELSIF NEW.original_disposition_id IS NOT NULL THEN
  IF (to_jsonb(NEW)-'original_disposition_id') IS DISTINCT FROM (to_jsonb(OLD)-'original_disposition_id')
  THEN RAISE EXCEPTION 'disposition cannot rewrite original grant'; END IF;
  SELECT * INTO STRICT d FROM public.capacity_original_create_dispositions WHERE id=NEW.original_disposition_id AND grant_id=OLD.id;
  IF d.original_grant_sha256<>encode(sha256(convert_to(OLD.grant_record::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'disposition original grant digest changed'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER original_create_disposition_pointer BEFORE UPDATE ON public.capacity_mutation_grants
 FOR EACH ROW EXECUTE FUNCTION public.guard_original_create_disposition_pointer();
DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.capacity_original_create_dispositions)
 THEN RAISE EXCEPTION 'cannot remove admitted original create dispositions'; END IF; END; $$;
-- +goose StatementEnd
DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled');
DROP TRIGGER original_create_disposition_pointer ON public.capacity_mutation_grants;
DROP FUNCTION public.guard_original_create_disposition_pointer();
ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT capacity_original_disposition_matching_grant_fk;
ALTER TABLE public.capacity_mutation_grants DROP COLUMN original_disposition_id;
DROP TABLE public.capacity_original_create_dispositions;
DROP FUNCTION public.guard_original_create_disposition_insert();
DROP FUNCTION public.immutable_original_create_disposition();
