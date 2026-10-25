package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCapacityMutationRegisteredTypePostgres(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(*model.IntegrationTypeManifestSpec)
	}{
		{"resource_actions_in_transport", func(s *model.IntegrationTypeManifestSpec) {
			s.Capabilities = []string{"ensure_server", "destroy_server"}
		}},
		{"execute_missing", func(s *model.IntegrationTypeManifestSpec) { s.Capabilities = []string{"describe"} }},
		{"catalog_missing", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog = nil }},
		{"catalog_permission", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[0].Category = "permission" }},
		{"resource_default_missing", func(s *model.IntegrationTypeManifestSpec) {
			s.ResourceTypes[0].DefaultActions = []string{"destroy_server"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mutationPostgresFixture(t, true)
			spec := mutationTypeFixture()
			tc.change(&spec)
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			// Corrupt only the stored body while retaining the approved checksum.
			// Active revision checks alone must not admit an invalid action catalog.
			if _, err = f.db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb WHERE id=$1`, f.binding.IntegrationTypeID, string(raw)); err != nil {
				t.Fatal(err)
			}
			if grant, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityConflict) || grant.GrantID != "" {
				t.Fatal("invalid registered type admitted", grant, err)
			}
			var count int
			if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
				t.Fatal("rejected type reserved mutation", count, err)
			}
		})
	}
}
