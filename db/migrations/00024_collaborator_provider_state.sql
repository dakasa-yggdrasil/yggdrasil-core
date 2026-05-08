-- +goose Up
-- +goose StatementBegin

-- Per (collaborator, provider) record of desired vs observed state.
-- Powers Crossplane-style reconcile loops: every tick computes desired
-- from collaborator+role+team mappings, polls provider for observed,
-- diffs, and overwrites observed when divergence is detected.
--
-- pending_action is set when a step in the lifecycle workflow couldn't
-- complete (provider API down, rate-limited, etc.) and the reconcile
-- loop is the recovery mechanism. error_count + last_error give the
-- operator a debugging surface; alerts fire when error_count exceeds a
-- threshold for the same (collaborator, provider) pair.

CREATE TABLE IF NOT EXISTS public.collaborator_provider_state (
    collaborator_id         UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    provider                TEXT NOT NULL,
    external_id             TEXT NULL,
    desired_state           JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_state          JSONB NULL,
    last_reconciled_at      TIMESTAMPTZ NULL,
    last_drift_detected_at  TIMESTAMPTZ NULL,
    pending_action          TEXT NULL,
    error_count             INT NOT NULL DEFAULT 0,
    last_error              TEXT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collaborator_id, provider),
    CONSTRAINT collaborator_provider_state_pending_action_check
        CHECK (pending_action IS NULL OR pending_action IN ('provision', 'update', 'deprovision'))
);

CREATE INDEX IF NOT EXISTS collaborator_provider_state_pending_idx
    ON public.collaborator_provider_state (provider, pending_action)
    WHERE pending_action IS NOT NULL;

CREATE INDEX IF NOT EXISTS collaborator_provider_state_drift_idx
    ON public.collaborator_provider_state (provider, last_drift_detected_at DESC)
    WHERE last_drift_detected_at IS NOT NULL;

DROP TRIGGER IF EXISTS collaborator_provider_state_touch_updated_at
    ON public.collaborator_provider_state;
CREATE TRIGGER collaborator_provider_state_touch_updated_at
    BEFORE UPDATE ON public.collaborator_provider_state
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS collaborator_provider_state_touch_updated_at
    ON public.collaborator_provider_state;
DROP INDEX IF EXISTS public.collaborator_provider_state_drift_idx;
DROP INDEX IF EXISTS public.collaborator_provider_state_pending_idx;
DROP TABLE IF EXISTS public.collaborator_provider_state;

-- +goose StatementEnd
