-- +goose Up
-- Empty, Source-only append-only records. Installing this schema grants no
-- production capability, active registry, provider profile or write authority.
-- +goose StatementBegin
CREATE FUNCTION public.source_recovery_cleanup_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable source recovery cleanup evidence'; END $$;
-- +goose StatementEnd
CREATE TABLE public.capacity_source_recovery_cleanup_challenges (
 nonce_sha256 text PRIMARY KEY CHECK(length(nonce_sha256)=64),
 parent_grant_id uuid NOT NULL,
 preregistration_id uuid NOT NULL,
 namespace text NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 fencing_token bigint NOT NULL CHECK(fencing_token>0),
 epoch_wire bytea NOT NULL,
 prepared_at timestamptz NOT NULL,
 UNIQUE(parent_grant_id,generation,fencing_token,nonce_sha256)
);
CREATE TABLE public.capacity_source_recovery_cleanup_reads (
 nonce_sha256 text PRIMARY KEY REFERENCES public.capacity_source_recovery_cleanup_challenges(nonce_sha256),
 native_wire bytea NOT NULL,
 failure_wire bytea NOT NULL,
 epoch_wire bytea NOT NULL,
 epoch_sha256 text NOT NULL UNIQUE CHECK(length(epoch_sha256)=64)
);
CREATE TABLE public.capacity_source_recovery_cleanup_effect_permits (
 child_grant_id uuid NOT NULL,
 phase text NOT NULL CHECK(phase IN ('signal','unlink')),
 request_wire bytea NOT NULL,
 request_sha256 text NOT NULL UNIQUE CHECK(length(request_sha256)=64),
 nonce_sha256 text NOT NULL UNIQUE CHECK(length(nonce_sha256)=64),
 permit_wire bytea NOT NULL,
 permit_sha256 text NOT NULL UNIQUE CHECK(length(permit_sha256)=64),
 checked_at timestamptz NOT NULL,
 PRIMARY KEY(child_grant_id,phase)
);
CREATE TRIGGER source_recovery_challenge_immutable BEFORE UPDATE OR DELETE ON public.capacity_source_recovery_cleanup_challenges FOR EACH ROW EXECUTE FUNCTION public.source_recovery_cleanup_immutable();
CREATE TRIGGER source_recovery_read_immutable BEFORE UPDATE OR DELETE ON public.capacity_source_recovery_cleanup_reads FOR EACH ROW EXECUTE FUNCTION public.source_recovery_cleanup_immutable();
CREATE TRIGGER source_recovery_effect_immutable BEFORE UPDATE OR DELETE ON public.capacity_source_recovery_cleanup_effect_permits FOR EACH ROW EXECUTE FUNCTION public.source_recovery_cleanup_immutable();
-- +goose Down
DROP TABLE public.capacity_source_recovery_cleanup_effect_permits;
DROP TABLE public.capacity_source_recovery_cleanup_reads;
DROP TABLE public.capacity_source_recovery_cleanup_challenges;
DROP FUNCTION public.source_recovery_cleanup_immutable();
