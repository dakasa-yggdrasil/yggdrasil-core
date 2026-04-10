package message

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestIntegrationTypeSupportsCatalogDiscover(t *testing.T) {
	t.Run("supports action catalog", func(t *testing.T) {
		if !integrationTypeSupportsCatalogDiscover(model.IntegrationTypeManifestSpec{
			Capabilities: []string{"describe", "execute"},
			ActionCatalog: []model.IntegrationActionDefinition{
				{Name: model.CatalogDiscoverOperation},
			},
		}) {
			t.Fatal("expected catalog discover support")
		}
	})

	t.Run("requires execute capability", func(t *testing.T) {
		if integrationTypeSupportsCatalogDiscover(model.IntegrationTypeManifestSpec{
			Capabilities: []string{"describe"},
			ActionCatalog: []model.IntegrationActionDefinition{
				{Name: model.CatalogDiscoverOperation},
			},
		}) {
			t.Fatal("expected missing execute capability to disable support")
		}
	})
}

func TestMatchDiscoveredCandidate(t *testing.T) {
	integrationRef := model.ManifestReference{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Kind:      "integration_type",
		Namespace: "global",
		Name:      "rabbitmq",
		Version:   1,
	}
	surfaceRef := model.ManifestReference{
		ID:        uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Kind:      "surface",
		Namespace: "global",
		Name:      "payments-api",
		Version:   1,
	}
	indexes := discoveredManifestIndexes{
		integrationsByName: map[string]model.ManifestReference{
			"rabbitmq": integrationRef,
		},
		integrationsByCatalogKey: map[string]model.ManifestReference{
			"rabbitmq/operations/api": integrationRef,
		},
		surfacesByKey: map[string]model.ManifestReference{
			"global/payments-api": surfaceRef,
		},
		surfacesByName: map[string]model.ManifestReference{
			"payments-api": surfaceRef,
		},
	}

	if ref := matchDiscoveredCandidate(indexes, model.CatalogDiscoveryCandidate{
		Kind:    model.CatalogDiscoveryKindIntegration,
		Name:    "rabbitmq",
		Domain:  "rabbitmq",
		Section: "operations",
		Entry:   "api",
	}); ref == nil || ref.Name != "rabbitmq" {
		t.Fatalf("integration match = %#v", ref)
	}

	if ref := matchDiscoveredCandidate(indexes, model.CatalogDiscoveryCandidate{
		Kind:      model.CatalogDiscoveryKindSurface,
		Name:      "payments-api",
		Namespace: "global",
	}); ref == nil || ref.Name != "payments-api" {
		t.Fatalf("surface match = %#v", ref)
	}
}

func TestDiscoverCatalogResponseOrderingAndLimit(t *testing.T) {
	items := []model.CatalogDiscoveryItem{
		{
			Kind:    "surface",
			Name:    "payments-api",
			Section: "reference",
			Source: model.CatalogDiscoverySource{
				IntegrationInstance: model.ManifestReference{Name: "github-platform"},
			},
		},
		{
			Kind:    "integration",
			Name:    "rabbitmq",
			Domain:  "rabbitmq",
			Section: "operations",
			Entry:   "api",
			Source: model.CatalogDiscoverySource{
				IntegrationInstance: model.ManifestReference{Name: "github-platform"},
			},
		},
		{
			Kind:    "integration",
			Name:    "grafana",
			Domain:  "grafana",
			Section: "operations",
			Entry:   "api",
			Source: model.CatalogDiscoverySource{
				IntegrationInstance: model.ManifestReference{Name: "github-platform"},
			},
		},
	}

	items = sortAndLimitCatalogDiscoveryItems(items, 2)

	if len(items) != 2 {
		t.Fatalf("unexpected item count: %d", len(items))
	}
	if items[0].Name != "grafana" || items[1].Name != "rabbitmq" {
		t.Fatalf("unexpected ordering after limit: %+v", items)
	}
}
