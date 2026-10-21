-- +goose Up
-- Empty immutable original source records only. No synthetic grant, enrolled
-- member, app effect, useful-capacity proof, role or production approval.
CREATE TABLE IF NOT EXISTS public.capacity_guest_notify_canary_challenges (
 id uuid PRIMARY KEY,
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 record_challenge_id uuid NOT NULL REFERENCES public.capacity_guest_notify_canary_challenges(id),
 phase text NOT NULL CHECK(phase IN ('publish','read')),
 policy_id uuid NOT NULL REFERENCES public.manifests(id),
 workflow_id uuid NOT NULL REFERENCES public.manifests(id),
 generation bigint NOT NULL CHECK(generation>0),
 fence bigint NOT NULL CHECK(fence>0),
 executor_id text NOT NULL CHECK(length(executor_id) BETWEEN 1 AND 256),
 lease_owner text NOT NULL CHECK(length(lease_owner) BETWEEN 1 AND 256),
 challenge_sha256 text NOT NULL UNIQUE CHECK(challenge_sha256 ~ '^[0-9a-f]{64}$'),
 nonce_sha256 text NOT NULL UNIQUE CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 32768),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 original_deadline timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL,
 CHECK(phase<>'publish' OR record_challenge_id=id),
 CHECK(original_deadline>(original_record->>'issued_at')::timestamptz AND original_deadline<=(original_record->>'issued_at')::timestamptz+interval '5 seconds'),
 CHECK(original_deadline=(original_record->>'original_deadline')::timestamptz),
 CHECK(original_record->>'schema' IN ('guest_notify_business_canary_challenge_v1','guest_notify_business_canary_publish_challenge_v1'))
);
CREATE INDEX IF NOT EXISTS capacity_guest_notify_canary_member_time ON public.capacity_guest_notify_canary_challenges(preregistration_id,phase,recorded_at);
CREATE TABLE IF NOT EXISTS public.capacity_guest_notify_canary_nonces (
 challenge_id uuid PRIMARY KEY REFERENCES public.capacity_guest_notify_canary_challenges(id),
 guest_nonce_sha256 text NOT NULL UNIQUE CHECK(guest_nonce_sha256 ~ '^[0-9a-f]{64}$'),
 nonce_wire bytea NOT NULL CHECK(octet_length(nonce_wire) BETWEEN 1 AND 16384),
 final_challenge_wire bytea NOT NULL CHECK(octet_length(final_challenge_wire) BETWEEN 1 AND 32768),
 final_challenge_sha256 text NOT NULL UNIQUE CHECK(final_challenge_sha256 ~ '^[0-9a-f]{64}$'),
 original_transport jsonb NOT NULL CHECK(jsonb_typeof(original_transport)='object'),
 recorded_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_notify_canary_sends (
 challenge_id uuid PRIMARY KEY REFERENCES public.capacity_guest_notify_canary_challenges(id),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 possible_send_at timestamptz NOT NULL,
 original_deadline timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL,
 CHECK(original_deadline>possible_send_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_notify_canary_returns (
 challenge_id uuid PRIMARY KEY REFERENCES public.capacity_guest_notify_canary_challenges(id),
 outcome text NOT NULL CHECK(outcome IN ('accepted','held')),
 return_sha256 text NOT NULL CHECK(return_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea CHECK(octet_length(original_wire) BETWEEN 1 AND 65536),
 original_transport jsonb NOT NULL CHECK(jsonb_typeof(original_transport)='object'),
 business_observation jsonb CHECK(jsonb_typeof(business_observation)='object'),
 recorded_at timestamptz NOT NULL,
 CHECK(outcome<>'accepted' OR original_wire IS NOT NULL)
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_guest_notify_canary_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable original Guest Notify canary'; END $$;
-- +goose StatementEnd
CREATE OR REPLACE TRIGGER capacity_guest_notify_challenge_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_notify_canary_challenges FOR EACH ROW EXECUTE FUNCTION public.capacity_guest_notify_canary_immutable();
CREATE OR REPLACE TRIGGER capacity_guest_notify_nonce_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_notify_canary_nonces FOR EACH ROW EXECUTE FUNCTION public.capacity_guest_notify_canary_immutable();
CREATE OR REPLACE TRIGGER capacity_guest_notify_send_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_notify_canary_sends FOR EACH ROW EXECUTE FUNCTION public.capacity_guest_notify_canary_immutable();
CREATE OR REPLACE TRIGGER capacity_guest_notify_return_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_notify_canary_returns FOR EACH ROW EXECUTE FUNCTION public.capacity_guest_notify_canary_immutable();
-- +goose Down
-- Original possible-send identities remain permanent through app rollback.
SELECT 1;
