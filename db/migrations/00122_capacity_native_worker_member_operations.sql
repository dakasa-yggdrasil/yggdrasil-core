-- +goose Up
-- Private member/placement custody only. These rows are not public resource
-- events or mutation grants. Go retains source/auth/proof and live DB-clock
-- validation; historical reads and first late originals do not expire here.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_member_plans (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES public.capacity_native_worker_attempts(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL REFERENCES public.manifests(id) ON DELETE RESTRICT,
    namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 253),
    kind text NOT NULL CHECK (kind IN ('placement','retirement','read_preflight')),
    mode text NOT NULL CHECK (mode IN ('never_admitted','admitted')),
    subject_uid uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('preparing','active','settled','cancelled')),
    revision bigint NOT NULL CHECK (revision >= 1),
    identity jsonb NOT NULL CHECK (jsonb_typeof(identity)='object' AND octet_length(identity::text)<=8388608),
    record jsonb NOT NULL CHECK (jsonb_typeof(record)='object' AND octet_length(record::text)<=8388608),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    -- Compare the opaque identity value, not a re-encoded Go digest. The
    -- record is the snapshot loaded by Go and cannot carry another identity.
    CHECK ((record->'identity'=identity AND record->>'state'=state
        AND record->'revision'=to_jsonb(revision)) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_member_one_live_subject
    ON public.capacity_native_worker_member_plans(attempt_id,kind,subject_uid)
    WHERE state NOT IN ('settled','cancelled');
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_member_one_live_retirement
    ON public.capacity_native_worker_member_plans(attempt_id)
    WHERE kind='retirement' AND state NOT IN ('settled','cancelled');
CREATE INDEX IF NOT EXISTS capacity_native_worker_member_plan_attempt
    ON public.capacity_native_worker_member_plans(attempt_id);

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_member_permits (
    id uuid PRIMARY KEY,
    plan_id uuid NOT NULL REFERENCES public.capacity_native_worker_member_plans(id) ON DELETE RESTRICT,
    attempt_id uuid NOT NULL REFERENCES public.capacity_native_worker_attempts(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL REFERENCES public.manifests(id) ON DELETE RESTRICT,
    namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 253),
    action text NOT NULL CHECK (action IN ('cordon','evict_pod','bind_pod','delete_node','retire_registry','provider_destroy')),
    capability text NOT NULL,
    subject_uid uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('preparing','issued','redeemed','received','unknown','no_effect','observed','member_absent')),
    revision bigint NOT NULL CHECK (revision >= 1),
    context jsonb NOT NULL CHECK (jsonb_typeof(context)='object' AND octet_length(context::text)<=8388608),
    record jsonb NOT NULL CHECK (jsonb_typeof(record)='object' AND octet_length(record::text)<=8388608),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((context->>'schema'='native_worker_member_context_v1'
        AND context->>'permit_id'=id::text
        AND context->>'plan_id'=plan_id::text
        AND context->>'attempt_id'=attempt_id::text
        AND context->>'policy_id'=policy_id::text
        AND context->>'action'=action
        AND context#>>'{actor,capability}'=capability
        AND context->>'core_source_commit' ~ '^[0-9a-f]{40}$'
        AND context->>'realm_uid' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND context->>'realm_uid'<>'00000000-0000-0000-0000-000000000000'
        AND context->>'pool_uid' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND context->>'pool_uid'<>'00000000-0000-0000-0000-000000000000'
        AND context->>'policy_checksum' ~ '^[0-9a-f]{64}$'
        AND context->>'birth_sha256' ~ '^[0-9a-f]{64}$'
        AND context->>'bootstrap_policy_sha256' ~ '^[0-9a-f]{64}$'
        AND context#>>'{actor,source_commit}' ~ '^[0-9a-f]{40}$'
        AND context#>>'{observer,source_commit}' ~ '^[0-9a-f]{40}$'
        AND context#>>'{actor,scope_sha256}' ~ '^[0-9a-f]{64}$'
        AND context#>>'{observer,scope_sha256}' ~ '^[0-9a-f]{64}$'
        AND context->>'registry_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'placement_fence_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'admission_receipt_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'drain_evidence_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'useful_capacity_evidence_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'physical_absence_evidence_sha256' ~ '^([0-9a-f]{64})?$'
        AND context->>'node_absence_evidence_sha256' ~ '^([0-9a-f]{64})?$'
        AND jsonb_typeof(context->'not_after')='string'
        AND (context->>'not_after')::timestamptz IS NOT NULL
        AND record->'context'=context
        AND record->>'state'=state
        AND record->'revision'=to_jsonb(revision)) IS TRUE),
    CHECK ((NOT (record ? 'settlement_token_sha256') OR
        (jsonb_typeof(record->'settlement_token_sha256')='string'
         AND (record->>'settlement_token_sha256'='' OR record->>'settlement_token_sha256' ~ '^[0-9a-f]{64}$'))) IS TRUE),
    CHECK ((NOT (record ? 'original') OR
        (jsonb_typeof(record->'original')='object'
         AND (record->'original')-ARRAY['nonce','ciphertext']='{}'::jsonb
         AND jsonb_typeof(record#>'{original,nonce}')='string'
         AND jsonb_typeof(record#>'{original,ciphertext}')='string'
         AND length(record#>>'{original,nonce}')>0
         AND length(record#>>'{original,ciphertext}')>0)) IS TRUE)
);
-- The same evict_pod key spans both capability aliases and all plans. A seed
-- is not an exposed effect; neither expiry nor wall-clock predicates free one.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_member_one_live_effect
    ON public.capacity_native_worker_member_permits(attempt_id,action,subject_uid)
    WHERE state NOT IN ('preparing','no_effect','observed','member_absent');
-- A Pod cannot escape an exposed Bind by changing Node, pool, epoch or Attempt.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_member_one_realm_bind
    ON public.capacity_native_worker_member_permits((context->>'realm_uid'),subject_uid)
    WHERE action='bind_pod' AND state NOT IN ('preparing','no_effect','observed','member_absent');
CREATE INDEX IF NOT EXISTS capacity_native_worker_member_permit_attempt
    ON public.capacity_native_worker_member_permits(attempt_id);
CREATE INDEX IF NOT EXISTS capacity_native_worker_member_permit_plan_state
    ON public.capacity_native_worker_member_permits(plan_id,state);

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_member_reads (
    id uuid PRIMARY KEY,
    permit_id uuid NOT NULL REFERENCES public.capacity_native_worker_member_permits(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL REFERENCES public.manifests(id) ON DELETE RESTRICT,
    namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 253),
    context_sha256 text NOT NULL CHECK (context_sha256 ~ '^[0-9a-f]{64}$'),
    endpoint_kind text NOT NULL CHECK (endpoint_kind IN ('kubelet_configz','member_inventory')),
    source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
    scope_sha256 text NOT NULL CHECK (scope_sha256 ~ '^[0-9a-f]{64}$'),
    subject_node_uid uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('issued','captured')),
    record jsonb NOT NULL CHECK (jsonb_typeof(record)='object' AND octet_length(record::text)<=8388608),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((record->>'read_id'=id::text
        AND record->>'permit_id'=permit_id::text
        AND record->>'context_sha256'=context_sha256
        AND record->>'subject_node_uid'=subject_node_uid::text
        AND record->>'sdk_source_commit'=source_commit
        AND record->>'scope_sha256'=scope_sha256
        AND record->>'kind'=endpoint_kind
        AND (record->>'created_at')::timestamptz=created_at) IS TRUE),
    CHECK ((NOT (record ? 'private_original') OR
        (jsonb_typeof(record->'private_original')='object'
         AND (record->'private_original')-ARRAY['nonce','ciphertext']='{}'::jsonb
         AND jsonb_typeof(record#>'{private_original,nonce}')='string'
         AND jsonb_typeof(record#>'{private_original,ciphertext}')='string'
         AND length(record#>>'{private_original,nonce}')>0
         AND length(record#>>'{private_original,ciphertext}')>0)) IS TRUE)
);
CREATE INDEX IF NOT EXISTS capacity_native_worker_member_read_permit
    ON public.capacity_native_worker_member_reads(permit_id);

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_member_events (
    id bigserial PRIMARY KEY,
    plan_id uuid NOT NULL REFERENCES public.capacity_native_worker_member_plans(id) ON DELETE RESTRICT,
    permit_id uuid REFERENCES public.capacity_native_worker_member_permits(id) ON DELETE RESTRICT,
    read_id uuid REFERENCES public.capacity_native_worker_member_reads(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL REFERENCES public.manifests(id) ON DELETE RESTRICT,
    namespace text NOT NULL CHECK (octet_length(namespace) BETWEEN 1 AND 253),
    kind text NOT NULL CHECK (octet_length(kind) BETWEEN 1 AND 128 AND btrim(kind)<>''),
    record jsonb NOT NULL CHECK (jsonb_typeof(record)='object' AND octet_length(record::text)<=8388608),
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS capacity_native_worker_member_event_plan
    ON public.capacity_native_worker_member_events(plan_id,id);

-- Scope reads below consult immutable indexed identities. Go acquires the
-- dimension/Attempt/plan/effect locks in that order before changing a record;
-- these guards neither fetch external facts nor create another lock order.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_member_plan_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'native member plan history is retained'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.capacity_native_worker_attempts a
        WHERE a.id=NEW.attempt_id AND a.policy_id=NEW.policy_id AND a.namespace=NEW.namespace)
    THEN RAISE EXCEPTION 'native member plan attempt scope differs'; END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.state NOT IN ('preparing','active')
        THEN RAISE EXCEPTION 'native member plan must start before settlement'; END IF;
        IF NEW.record ?| ARRAY['provider_dispatch_started_at','network_dispatch_started_at','sealed_facts','physical_absence','node_absence']
        THEN RAISE EXCEPTION 'native member plan cannot insert prior dispatch or evidence'; END IF;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
            OR NEW.policy_id IS DISTINCT FROM OLD.policy_id OR NEW.namespace IS DISTINCT FROM OLD.namespace
            OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.mode IS DISTINCT FROM OLD.mode
            OR NEW.subject_uid IS DISTINCT FROM OLD.subject_uid OR NEW.identity IS DISTINCT FROM OLD.identity
            OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.revision<>OLD.revision+1
            OR OLD.state IN ('settled','cancelled')
        THEN RAISE EXCEPTION 'native member plan identity or terminal history changed'; END IF;
        IF (OLD.record ? 'sealed_facts' AND NEW.record->'sealed_facts' IS DISTINCT FROM OLD.record->'sealed_facts')
            OR (OLD.record ? 'physical_absence' AND NEW.record->'physical_absence' IS DISTINCT FROM OLD.record->'physical_absence')
            OR (OLD.record ? 'node_absence' AND NEW.record->'node_absence' IS DISTINCT FROM OLD.record->'node_absence')
            OR (OLD.record ? 'provider_dispatch_started_at' AND
                (NEW.record->'provider_dispatch_started_at' IS DISTINCT FROM OLD.record->'provider_dispatch_started_at'
                 OR NEW.record->'provider_permit_id' IS DISTINCT FROM OLD.record->'provider_permit_id'))
            OR (OLD.record ? 'network_dispatch_started_at' AND
                (NEW.record->'network_dispatch_started_at' IS DISTINCT FROM OLD.record->'network_dispatch_started_at'
                 OR NEW.record->'network_permit_id' IS DISTINCT FROM OLD.record->'network_permit_id'))
        THEN RAISE EXCEPTION 'native member plan evidence or dispatch is immutable'; END IF;
        IF NEW.record ? 'provider_dispatch_started_at' AND NOT (OLD.record ? 'provider_dispatch_started_at') THEN
            IF (NEW.kind='retirement' AND NEW.mode='never_admitted' AND OLD.state='active' AND NEW.state='active'
                AND jsonb_typeof(NEW.record->'provider_dispatch_started_at')='string'
                AND (NEW.record->>'provider_dispatch_started_at')::timestamptz IS NOT NULL
                AND (NEW.record-ARRAY['revision','provider_permit_id','provider_dispatch_started_at'])=
                    (OLD.record-ARRAY['revision','provider_permit_id','provider_dispatch_started_at'])
                AND EXISTS(SELECT 1 FROM public.capacity_native_worker_abort_permits a
                    WHERE a.id::text=NEW.record->>'provider_permit_id' AND a.attempt_id=NEW.attempt_id
                      AND a.policy_id=NEW.policy_id AND a.namespace=NEW.namespace AND a.state='issued')) IS NOT TRUE
            THEN RAISE EXCEPTION 'native member provider dispatch requires its original issued abort permit'; END IF;
        END IF;
        IF NEW.record ? 'network_dispatch_started_at' AND NOT (OLD.record ? 'network_dispatch_started_at') THEN
            IF (NEW.kind='retirement' AND NEW.mode='never_admitted' AND OLD.state='active' AND NEW.state='active'
                AND jsonb_typeof(NEW.record->'network_dispatch_started_at')='string'
                AND (NEW.record->>'network_dispatch_started_at')::timestamptz IS NOT NULL
                AND (NEW.record-ARRAY['revision','network_permit_id','network_dispatch_started_at'])=
                    (OLD.record-ARRAY['revision','network_permit_id','network_dispatch_started_at'])
                AND EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits n
                    WHERE n.id::text=NEW.record->>'network_permit_id' AND n.attempt_id=NEW.attempt_id
                      AND n.policy_id=NEW.policy_id AND n.namespace=NEW.namespace AND n.action='remove' AND n.state='issued')) IS NOT TRUE
            THEN RAISE EXCEPTION 'native member network dispatch requires its original issued remove permit'; END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_member_plan_guard ON public.capacity_native_worker_member_plans;
CREATE TRIGGER capacity_native_worker_member_plan_guard BEFORE INSERT OR UPDATE OR DELETE
    ON public.capacity_native_worker_member_plans FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_member_plan_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_member_permit_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p record;
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'native member permit custody is retained'; END IF;
    SELECT plan.kind,plan.mode,plan.subject_uid INTO p
        FROM public.capacity_native_worker_member_plans plan
        JOIN public.capacity_native_worker_attempts a ON a.id=plan.attempt_id
        WHERE plan.id=NEW.plan_id AND plan.attempt_id=NEW.attempt_id
          AND plan.policy_id=NEW.policy_id AND plan.namespace=NEW.namespace
          AND a.policy_id=NEW.policy_id AND a.namespace=NEW.namespace;
    IF NOT FOUND OR NEW.context->>'mode' IS DISTINCT FROM p.mode
    THEN RAISE EXCEPTION 'native member permit parent scope differs'; END IF;
    IF p.kind='read_preflight' AND (NEW.action<>'cordon' OR NEW.capability<>'ensure_native_worker_pool_member'
        OR NEW.state NOT IN ('preparing','no_effect') OR NEW.record ? 'settlement_token_sha256'
        OR NEW.record ? 'original' OR NEW.record ? 'dispatch_started_at' OR NEW.record ? 'redeemed_at')
    THEN RAISE EXCEPTION 'native read preflight cannot expose a mutation'; END IF;
    IF NOT (
        (p.kind='read_preflight' AND NEW.action='cordon' AND NEW.capability='ensure_native_worker_pool_member') OR
        (p.kind='retirement' AND NEW.action='cordon' AND NEW.capability='ensure_native_worker_pool_member') OR
        (p.kind='placement' AND NEW.action='bind_pod' AND NEW.capability='ensure_native_worker_pod_placement') OR
        (p.kind='retirement' AND NEW.action='evict_pod' AND NEW.capability='destroy_native_worker_pool_member') OR
        (p.kind='placement' AND NEW.action='evict_pod' AND NEW.capability='destroy_native_worker_pod_placement') OR
        (p.kind='retirement' AND NEW.action IN ('delete_node','retire_registry') AND NEW.capability='destroy_native_worker_pool_member') OR
        (p.kind='retirement' AND p.mode='admitted' AND NEW.action='provider_destroy' AND NEW.capability='destroy_native_worker')
    ) THEN RAISE EXCEPTION 'native member action and capability differ'; END IF;
    IF (NEW.action IN ('evict_pod','bind_pod') AND NEW.context#>>'{pod,uid}' IS DISTINCT FROM NEW.subject_uid::text)
        OR (NEW.action NOT IN ('evict_pod','bind_pod') AND NEW.context#>>'{node,uid}' IS DISTINCT FROM NEW.subject_uid::text)
        OR (p.kind='placement' AND NEW.context#>>'{pod,uid}' IS DISTINCT FROM p.subject_uid::text)
        OR (p.kind IN ('retirement','read_preflight') AND NEW.context#>>'{node,uid}' IS DISTINCT FROM p.subject_uid::text)
    THEN RAISE EXCEPTION 'native member subject differs from its plan and context'; END IF;
    IF (NEW.state IN ('preparing','issued') AND
        (COALESCE(NEW.record->>'settlement_token_sha256','')<>'' OR NEW.record ? 'original'))
        OR (NEW.state IN ('redeemed','received','unknown','observed','member_absent')
            AND COALESCE(NEW.record->>'settlement_token_sha256','')='')
        OR (NEW.record ? 'original' AND COALESCE(NEW.record->>'settlement_token_sha256','')='')
    THEN RAISE EXCEPTION 'native member custody and redemption token differ'; END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.state NOT IN ('preparing','issued')
        THEN RAISE EXCEPTION 'native member permit must start unexposed'; END IF;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.plan_id IS DISTINCT FROM OLD.plan_id
            OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
            OR NEW.namespace IS DISTINCT FROM OLD.namespace OR NEW.action IS DISTINCT FROM OLD.action
            OR NEW.capability IS DISTINCT FROM OLD.capability OR NEW.subject_uid IS DISTINCT FROM OLD.subject_uid
            OR NEW.context IS DISTINCT FROM OLD.context OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.revision<>OLD.revision+1
            OR (OLD.record ? 'original' AND NEW.record->'original' IS DISTINCT FROM OLD.record->'original')
            OR (OLD.record ? 'dispatch_started_at' AND NEW.record->'dispatch_started_at' IS DISTINCT FROM OLD.record->'dispatch_started_at')
            OR (COALESCE(OLD.record->>'settlement_token_sha256','')<>''
                AND NEW.record->'settlement_token_sha256' IS DISTINCT FROM OLD.record->'settlement_token_sha256')
        THEN RAISE EXCEPTION 'native member permit identity or original custody changed'; END IF;
        IF COALESCE(OLD.record->>'settlement_token_sha256','')=''
            AND COALESCE(NEW.record->>'settlement_token_sha256','')<>''
            AND NOT (OLD.state='issued' AND NEW.state='redeemed')
        THEN RAISE EXCEPTION 'native member token requires the original redemption'; END IF;
        IF NOT (
            (OLD.state='preparing' AND NEW.state IN ('preparing','no_effect')) OR
            (OLD.state='issued' AND NEW.state IN ('redeemed','no_effect')) OR
            (OLD.state='issued' AND NEW.state='issued'
                AND NOT (OLD.record ? 'dispatch_started_at')
                AND jsonb_typeof(NEW.record->'dispatch_started_at')='string'
                AND (NEW.record->>'dispatch_started_at')::timestamptz IS NOT NULL
                AND (NEW.record-ARRAY['revision','dispatch_started_at'])=(OLD.record-'revision')) OR
            (OLD.state='redeemed' AND NEW.state IN ('received','unknown')) OR
            (OLD.state IN ('received','unknown') AND NEW.state IN ('unknown','no_effect','observed','member_absent')) OR
            (OLD.state IN ('observed','no_effect','member_absent') AND NEW.state=OLD.state)
        ) THEN RAISE EXCEPTION 'native member transition cannot reopen an exposed right'; END IF;
        IF OLD.state IN ('observed','no_effect','member_absent')
            AND (NEW.record-ARRAY['revision','original']) IS DISTINCT FROM (OLD.record-ARRAY['revision','original'])
        THEN RAISE EXCEPTION 'native member terminal record only accepts original custody'; END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_member_permit_guard ON public.capacity_native_worker_member_permits;
CREATE TRIGGER capacity_native_worker_member_permit_guard BEFORE INSERT OR UPDATE OR DELETE
    ON public.capacity_native_worker_member_permits FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_member_permit_guard();

-- The private original is only an encrypted envelope, including on incomplete
-- transport. SQL never decodes it, hashes raw bytes, or interprets it as proof.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_member_read_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'native member read custody is retained'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.capacity_native_worker_member_permits p
        WHERE p.id=NEW.permit_id AND p.policy_id=NEW.policy_id AND p.namespace=NEW.namespace
          AND p.context#>>'{node,uid}'=NEW.subject_node_uid::text
          AND p.context#>>'{observer,source_commit}'=NEW.source_commit
          AND p.context#>>'{observer,scope_sha256}'=NEW.scope_sha256)
    THEN RAISE EXCEPTION 'native member read parent scope differs'; END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'issued' OR NEW.record ? 'private_original'
        THEN RAISE EXCEPTION 'native member read must be issued before capture'; END IF;
    ELSE
        IF OLD.endpoint_kind<>'kubelet_configz' OR OLD.state<>'issued' OR NEW.state<>'captured'
            OR NEW.id IS DISTINCT FROM OLD.id OR NEW.permit_id IS DISTINCT FROM OLD.permit_id
            OR NEW.policy_id IS DISTINCT FROM OLD.policy_id OR NEW.namespace IS DISTINCT FROM OLD.namespace
            OR NEW.context_sha256 IS DISTINCT FROM OLD.context_sha256 OR NEW.endpoint_kind IS DISTINCT FROM OLD.endpoint_kind
            OR NEW.source_commit IS DISTINCT FROM OLD.source_commit OR NEW.scope_sha256 IS DISTINCT FROM OLD.scope_sha256
            OR NEW.subject_node_uid IS DISTINCT FROM OLD.subject_node_uid OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR (NEW.record-'private_original') IS DISTINCT FROM (OLD.record-'private_original')
            OR NOT (NEW.record ? 'private_original')
        THEN RAISE EXCEPTION 'native member read capture or identity changed'; END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_member_read_guard ON public.capacity_native_worker_member_reads;
CREATE TRIGGER capacity_native_worker_member_read_guard BEFORE INSERT OR UPDATE OR DELETE
    ON public.capacity_native_worker_member_reads FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_member_read_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_member_event_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'native member events are append-only'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.capacity_native_worker_member_plans p
        WHERE p.id=NEW.plan_id AND p.policy_id=NEW.policy_id AND p.namespace=NEW.namespace)
        OR (NEW.permit_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM public.capacity_native_worker_member_permits p
            WHERE p.id=NEW.permit_id AND p.plan_id=NEW.plan_id
              AND p.policy_id=NEW.policy_id AND p.namespace=NEW.namespace))
        OR (NEW.read_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM public.capacity_native_worker_member_reads r
            JOIN public.capacity_native_worker_member_permits p ON p.id=r.permit_id
            WHERE r.id=NEW.read_id AND p.plan_id=NEW.plan_id
              AND r.policy_id=NEW.policy_id AND r.namespace=NEW.namespace
              AND (NEW.permit_id IS NULL OR r.permit_id=NEW.permit_id)))
    THEN RAISE EXCEPTION 'native member event parent scope differs'; END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_member_event_guard ON public.capacity_native_worker_member_events;
CREATE TRIGGER capacity_native_worker_member_event_guard BEFORE INSERT OR UPDATE OR DELETE
    ON public.capacity_native_worker_member_events FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_member_event_guard();

-- +goose Down
-- Refuse even settled/no_effect/read-only history, before dropping any guard.
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE public.capacity_native_worker_attempts IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE public.capacity_native_worker_member_plans,
        public.capacity_native_worker_member_permits,
        public.capacity_native_worker_member_reads,
        public.capacity_native_worker_member_events IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM public.capacity_native_worker_member_plans)
        OR EXISTS (SELECT 1 FROM public.capacity_native_worker_member_permits)
        OR EXISTS (SELECT 1 FROM public.capacity_native_worker_member_reads)
        OR EXISTS (SELECT 1 FROM public.capacity_native_worker_member_events)
    THEN RAISE EXCEPTION 'native member plans and private custody cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_member_events;
DROP TABLE IF EXISTS public.capacity_native_worker_member_reads;
DROP TABLE IF EXISTS public.capacity_native_worker_member_permits;
DROP TABLE IF EXISTS public.capacity_native_worker_member_plans;
DROP FUNCTION IF EXISTS public.capacity_native_worker_member_event_guard();
DROP FUNCTION IF EXISTS public.capacity_native_worker_member_read_guard();
DROP FUNCTION IF EXISTS public.capacity_native_worker_member_permit_guard();
DROP FUNCTION IF EXISTS public.capacity_native_worker_member_plan_guard();
