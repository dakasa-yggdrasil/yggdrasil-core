-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.integration_event_reactions (
  id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id                      UUID NOT NULL REFERENCES public.event_log(event_id) ON DELETE CASCADE,
  event_type                    TEXT NOT NULL,
  integration_instance_id       UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  integration_type_manifest_id  UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
  capability                    TEXT NOT NULL,
  status                        TEXT NOT NULL,
  attempt                       INT  NOT NULL DEFAULT 0,
  next_attempt_at               TIMESTAMPTZ NULL,
  started_at                    TIMESTAMPTZ NULL,
  finished_at                   TIMESTAMPTZ NULL,
  last_error                    TEXT NULL,
  metadata                      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT iers_status_check CHECK (status IN ('pending','in_progress','succeeded','failed','dead_lettered')),
  CONSTRAINT iers_unique_per_event_instance UNIQUE (event_id, integration_instance_id)
);

CREATE INDEX IF NOT EXISTS iers_pending_idx
  ON public.integration_event_reactions (next_attempt_at, status)
  WHERE status IN ('pending','failed');

CREATE INDEX IF NOT EXISTS iers_event_idx ON public.integration_event_reactions (event_id);

CREATE INDEX IF NOT EXISTS iers_instance_idx
  ON public.integration_event_reactions (integration_instance_id, status, created_at DESC);

DROP TRIGGER IF EXISTS integration_event_reactions_touch_updated_at ON public.integration_event_reactions;
CREATE TRIGGER integration_event_reactions_touch_updated_at
    BEFORE UPDATE ON public.integration_event_reactions
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS integration_event_reactions_touch_updated_at ON public.integration_event_reactions;
DROP TABLE IF EXISTS public.integration_event_reactions;
-- +goose StatementEnd
