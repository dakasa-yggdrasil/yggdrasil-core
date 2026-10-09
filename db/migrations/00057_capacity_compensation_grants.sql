-- +goose Up
ALTER TABLE public.capacity_mutation_grants
    DROP CONSTRAINT IF EXISTS capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants
    ADD CONSTRAINT capacity_mutation_grants_state_check
    CHECK (state IN ('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated'));

-- The failed parent keeps its reservation while its separately authorized
-- child occupies the existing one-open-send slot index. Never expire the parent.
-- +goose Down
-- A downgrade cannot discard unresolved or confirmed compensation authority.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM public.capacity_mutation_grants WHERE state IN ('compensating','compensated')) THEN
        RAISE EXCEPTION 'capacity compensation history prevents destructive downgrade';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE public.capacity_mutation_grants
    DROP CONSTRAINT IF EXISTS capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants
    ADD CONSTRAINT capacity_mutation_grants_state_check
    CHECK (state IN ('issued','redeemed','settled','confirmed','rejected','expired'));
