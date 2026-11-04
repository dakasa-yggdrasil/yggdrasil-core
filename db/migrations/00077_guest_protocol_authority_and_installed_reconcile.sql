-- +goose Up
-- Actual implementation build and stable signed Guest-v1 authority are distinct.
-- Each row is inserted atomically with its issue, never via best-effort logging.
CREATE TABLE public.capacity_guest_authority_issues (
 issue_kind text NOT NULL CHECK(issue_kind ~ '^[a-z_]{1,64}$'),
 issue_id uuid NOT NULL,
 issuer_actual_source_commit text NOT NULL CHECK(issuer_actual_source_commit ~ '^[0-9a-f]{40}$'),
 protocol_authority_source_commit text NOT NULL CHECK(protocol_authority_source_commit ~ '^[0-9a-f]{40}$'),
 compatibility_map_sha256 text NOT NULL CHECK(compatibility_map_sha256 ~ '^[0-9a-f]{64}$'),
 profile text NOT NULL CHECK(profile IN('notify-aws-elastic','notify-hetzner-elastic')),
 policy_id uuid NOT NULL REFERENCES public.manifests(id),
 workflow_id uuid NOT NULL REFERENCES public.manifests(id),
 executor_id text NOT NULL,
 issued_wire_sha256 text NOT NULL CHECK(issued_wire_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 16384),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object' AND original_record=convert_from(original_wire,'UTF8')::jsonb),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(issue_kind,issue_id),
 CHECK(original_record ?& ARRAY['schema','issue_kind','issue_id','issuer_actual_source_commit','protocol_authority_source_commit','compatibility_map_sha256','profile','policy_id','workflow_id','executor_id','issued_wire_sha256'] AND (original_record - ARRAY['schema','issue_kind','issue_id','issuer_actual_source_commit','protocol_authority_source_commit','compatibility_map_sha256','profile','policy_id','workflow_id','executor_id','issued_wire_sha256','installed_reconcile_marker_base64'])='{}'::jsonb),
 -- Only this issue has no other immutable table containing its payload.
 -- Retain its exact marker bytes, so intent replacement cannot erase evidence.
 CHECK((CASE WHEN issue_kind='installed_reconcile' THEN
   (original_record ? 'installed_reconcile_marker_base64')
   AND jsonb_typeof(original_record->'installed_reconcile_marker_base64')='string'
   AND octet_length(decode(original_record->>'installed_reconcile_marker_base64','base64'))>0
   AND encode(sha256(decode(original_record->>'installed_reconcile_marker_base64','base64')),'hex')=issued_wire_sha256
 ELSE NOT(original_record ? 'installed_reconcile_marker_base64') END) IS TRUE),
 CHECK((original_record->>'schema'='guest_authority_issue_v1') IS TRUE),
 CHECK((original_record->>'issue_kind'=issue_kind) IS TRUE),
 CHECK((original_record->>'issue_id'=issue_id::text) IS TRUE),
 CHECK((original_record->>'issuer_actual_source_commit'=issuer_actual_source_commit) IS TRUE),
 CHECK((original_record->>'protocol_authority_source_commit'=protocol_authority_source_commit) IS TRUE),
 CHECK((original_record->>'compatibility_map_sha256'=compatibility_map_sha256) IS TRUE),
 CHECK((original_record->>'profile'=profile) IS TRUE),
 CHECK((original_record->>'policy_id'=policy_id::text) IS TRUE),
 CHECK((original_record->>'workflow_id'=workflow_id::text) IS TRUE),
 CHECK((original_record->>'executor_id'=executor_id) IS TRUE),
 CHECK((original_record->>'issued_wire_sha256'=issued_wire_sha256) IS TRUE)
);
-- +goose StatementBegin
CREATE FUNCTION public.guard_guest_authority_issue_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'guest authority issue is immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER guest_authority_issue_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_authority_issues FOR EACH ROW EXECUTE FUNCTION public.guard_guest_authority_issue_immutable();

-- +goose Down
DROP TABLE public.capacity_guest_authority_issues;
DROP FUNCTION public.guard_guest_authority_issue_immutable();
