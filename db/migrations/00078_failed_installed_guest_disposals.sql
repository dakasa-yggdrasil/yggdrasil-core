-- +goose Up
-- An explicit administrative admission, an owning scheduled claim, and an
-- actual versioned Guest retirement/native-absence terminal are separate immutable original records.
CREATE TABLE public.capacity_guest_failed_installed_disposals (
 id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN ('requested','claimed','quiescent','terminal')),
 namespace text NOT NULL,
 environment text NOT NULL,
 domain text NOT NULL,
 dimension text NOT NULL,
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object' AND original_record=convert_from(original_wire,'UTF8')::jsonb),
 record_sha256 text NOT NULL CHECK(record_sha256=encode(sha256(original_wire),'hex')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,stage),
 UNIQUE(preregistration_id,stage),
 CHECK((original_record->>'schema'='failed_installed_guest_disposal_v1') IS TRUE),
 CHECK((original_record->>'id'=id::text) IS TRUE),
 CHECK((original_record->>'stage'=stage) IS TRUE),
 CHECK((original_record->>'preregistration_id'=preregistration_id::text) IS TRUE),
 CHECK((original_record->>'namespace'=namespace) IS TRUE),
 CHECK((original_record->>'environment'=environment) IS TRUE),
 CHECK((original_record->>'domain'=domain) IS TRUE),
 CHECK((original_record->>'dimension'=dimension) IS TRUE),
 CHECK((original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$') IS TRUE),
 CHECK((original_record->>'blocked_guest_source' ~ '^[0-9a-f]{40}$') IS TRUE),
 CHECK((original_record->>'blocked_profile_sha256' ~ '^[0-9a-f]{64}$') IS TRUE),
 CHECK((original_record->>'installation_sha256' ~ '^[0-9a-f]{64}$') IS TRUE),
 CHECK((original_record->>'enrollment_sha256' ~ '^[0-9a-f]{64}$') IS TRUE),
 CHECK((jsonb_typeof(original_record->'original_intent')='object' AND jsonb_typeof(original_record->'original_run')='string' AND jsonb_typeof(original_record->'last_failed_run')='string' AND jsonb_typeof((original_record->>'original_run')::jsonb)='object' AND jsonb_typeof((original_record->>'last_failed_run')::jsonb)='object') IS TRUE),
 CHECK(original_record ?& ARRAY['schema','id','stage','namespace','environment','domain','dimension','preregistration_id','issuer','actual_core_source','original_intent','original_run','last_failed_run','installation_sha256','enrollment_sha256','blocked_guest_source','blocked_profile_sha256','useful_capacity_before','business_effects_preserved','retirement_mode']),
 CHECK((original_record - ARRAY['schema','id','stage','namespace','environment','domain','dimension','preregistration_id','issuer','actual_core_source','original_intent','original_run','last_failed_run','installation_sha256','enrollment_sha256','blocked_guest_source','blocked_profile_sha256','useful_capacity_before','business_effects_preserved','retirement_mode','admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer'])='{}'::jsonb),
 CHECK((original_record->>'retirement_mode' IN ('original_production_v2','legacy_guest548_original_v1')) IS TRUE),
 CHECK(((original_record->>'retirement_mode'='legacy_guest548_original_v1')=(original_record->>'blocked_guest_source'='548734eef627404f10b5117e0ec7f27582ae9048')) IS TRUE),
 CHECK((original_record->>'useful_capacity_before'='0' AND original_record->>'business_effects_preserved'='true') IS TRUE)
);
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_installed_disposal_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_failed_installed_disposals;
BEGIN
 IF NEW.stage='requested' THEN
  IF NEW.original_record ?| ARRAY['admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'requested disposal has no claim or terminal'; END IF;
 ELSE
  SELECT * INTO STRICT admission FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage='requested';
  IF (NEW.original_record->>'admission_sha256'=admission.record_sha256) IS NOT TRUE OR
     (NEW.original_record - ARRAY['stage','admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer']) <> (admission.original_record-'stage') OR
     jsonb_typeof(NEW.original_record->'claimed_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'disposal admission lineage mismatch'; END IF;
  IF NEW.stage IN('quiescent','terminal') THEN
   PERFORM 1 FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage=CASE WHEN NEW.stage='quiescent' THEN 'claimed' ELSE 'quiescent' END AND original_record->'claimed_intent'=NEW.original_record->'claimed_intent';
   IF NOT FOUND OR (NEW.original_record->>'retirement_request_id' ~ '^[0-9a-f-]{36}$' AND NEW.original_record->>'native_poweroff_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE THEN RAISE EXCEPTION 'terminal disposal requires original claim and retirement'; END IF;
   IF NEW.stage='terminal' THEN
    PERFORM 1 FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage='quiescent' AND original_record->>'retirement_request_id'=NEW.original_record->>'retirement_request_id' AND original_record->>'native_poweroff_sha256'=NEW.original_record->>'native_poweroff_sha256';
    IF NOT FOUND THEN RAISE EXCEPTION 'terminal changed original quiescence'; END IF;
   END IF;
   IF NEW.stage='quiescent' AND NEW.original_record ?| ARRAY['observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'quiescence is not absence'; END IF;
   IF NEW.stage='terminal' AND (jsonb_typeof(NEW.original_record->'observation')='object' AND NEW.original_record->>'observation_sha256' ~ '^[0-9a-f]{64}$' AND length(NEW.original_record->>'terminal_issuer') BETWEEN 1 AND 256) IS NOT TRUE THEN RAISE EXCEPTION 'terminal requires actual readonly observation'; END IF;
  ELSIF NEW.original_record ?| ARRAY['retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'claim has no terminal credit';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER failed_installed_disposal_chain BEFORE INSERT ON public.capacity_guest_failed_installed_disposals FOR EACH ROW EXECUTE FUNCTION public.guard_failed_installed_disposal_chain();
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_installed_disposal_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'failed installed disposal record is immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER failed_installed_disposal_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_failed_installed_disposals FOR EACH ROW EXECUTE FUNCTION public.guard_failed_installed_disposal_immutable();
-- +goose Down
DROP TABLE public.capacity_guest_failed_installed_disposals;
DROP FUNCTION public.guard_failed_installed_disposal_immutable();
DROP FUNCTION public.guard_failed_installed_disposal_chain();
