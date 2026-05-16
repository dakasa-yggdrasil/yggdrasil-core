-- +goose Up
CREATE TABLE collaborator_external_identities (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  collaborator_id         uuid NOT NULL REFERENCES collaborators(id) ON DELETE CASCADE,
  integration_instance_id uuid NOT NULL,
  external_id             text NOT NULL,
  external_metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
  linked_at               timestamptz NOT NULL DEFAULT now(),
  last_seen_at            timestamptz NOT NULL DEFAULT now(),
  unlinked_at             timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX collaborator_external_identities_active_unique
  ON collaborator_external_identities (integration_instance_id, external_id)
  WHERE unlinked_at IS NULL;

CREATE INDEX collaborator_external_identities_collab_idx
  ON collaborator_external_identities (collaborator_id, integration_instance_id);

CREATE INDEX collaborator_external_identities_unlinked_idx
  ON collaborator_external_identities (unlinked_at)
  WHERE unlinked_at IS NOT NULL;

-- +goose Down
DROP TABLE collaborator_external_identities;
