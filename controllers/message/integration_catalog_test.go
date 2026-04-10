package message

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestDeriveIntegrationCatalogPositionUsesLabels(t *testing.T) {
	manifestRecord := model.Manifest{
		Metadata: model.ManifestMetadata{
			Name: "rabbitmq-on-kubernetes",
			Labels: map[string]string{
				model.IntegrationCatalogLabelDomain:  "rabbitmq",
				model.IntegrationCatalogLabelSection: "installations",
				model.IntegrationCatalogLabelEntry:   "kubernetes",
			},
		},
	}

	position := deriveIntegrationCatalogPosition(manifestRecord, model.IntegrationTypeManifestSpec{Provider: "rabbitmq"})
	if position.Domain != "rabbitmq" || position.Section != "installations" || position.Entry != "kubernetes" {
		t.Fatalf("unexpected catalog position: %+v", position)
	}
}

func TestDeriveIntegrationCatalogPositionFallsBackFromPluginName(t *testing.T) {
	manifestRecord := model.Manifest{
		Metadata: model.ManifestMetadata{
			Name: "rabbitmq-on-kubernetes",
		},
	}

	position := deriveIntegrationCatalogPosition(manifestRecord, model.IntegrationTypeManifestSpec{Provider: "rabbitmq"})
	if position.Domain != "rabbitmq" {
		t.Fatalf("domain = %q, want rabbitmq", position.Domain)
	}
	if position.Section != model.IntegrationCatalogSectionInstallations {
		t.Fatalf("section = %q, want %q", position.Section, model.IntegrationCatalogSectionInstallations)
	}
	if position.Entry != "kubernetes" {
		t.Fatalf("entry = %q, want kubernetes", position.Entry)
	}
}

func TestSummarizeIntegrationCatalogEntryStatus(t *testing.T) {
	tests := []struct {
		name      string
		instances []model.IntegrationCatalogInstance
		want      string
	}{
		{
			name: "healthy instance wins",
			instances: []model.IntegrationCatalogInstance{
				{Status: model.IntegrationRuntimeStatusContractMismatch},
				{Status: model.IntegrationRuntimeStatusHealthy},
			},
			want: model.IntegrationRuntimeStatusHealthy,
		},
		{
			name: "unconfigured without instances or runtime",
			want: model.IntegrationCatalogEntryStatusUnconfigured,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeIntegrationCatalogEntryStatus(tc.instances); got != tc.want {
				t.Fatalf("summarizeIntegrationCatalogEntryStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSummarizeIntegrationCatalogEntryRuntimeState(t *testing.T) {
	healthy := &model.IntegrationRuntimeState{Status: model.IntegrationRuntimeStatusHealthy}
	mismatch := &model.IntegrationRuntimeState{Status: model.IntegrationRuntimeStatusContractMismatch}

	state := summarizeIntegrationCatalogEntryRuntimeState([]model.IntegrationCatalogInstance{
		{Status: model.IntegrationRuntimeStatusContractMismatch, RuntimeState: mismatch},
		{Status: model.IntegrationRuntimeStatusHealthy, RuntimeState: healthy},
	})
	if state != healthy {
		t.Fatalf("expected healthy runtime state to win, got %#v", state)
	}
}

func TestGroupIntegrationCatalogEntries(t *testing.T) {
	entries := []model.IntegrationCatalogEntry{
		{
			Domain:     "rabbitmq",
			Section:    "operations",
			Entry:      "api",
			PluginName: "rabbitmq",
			IntegrationType: model.ManifestReference{
				ID: uuid.New(),
			},
		},
		{
			Domain:     "rabbitmq",
			Section:    "installations",
			Entry:      "kubernetes",
			PluginName: "rabbitmq-on-kubernetes",
			IntegrationType: model.ManifestReference{
				ID: uuid.New(),
			},
		},
		{
			Domain:     "grafana",
			Section:    "installations",
			Entry:      "kubernetes",
			PluginName: "grafana-on-kubernetes",
			IntegrationType: model.ManifestReference{
				ID: uuid.New(),
			},
		},
	}

	domains := groupIntegrationCatalogEntries(entries)
	if len(domains) != 2 {
		t.Fatalf("len(domains) = %d, want 2", len(domains))
	}
	if domains[0].Domain != "grafana" {
		t.Fatalf("domains[0].Domain = %q, want grafana", domains[0].Domain)
	}
	if domains[1].Domain != "rabbitmq" {
		t.Fatalf("domains[1].Domain = %q, want rabbitmq", domains[1].Domain)
	}
	if len(domains[1].Sections) != 2 {
		t.Fatalf("len(rabbitmq sections) = %d, want 2", len(domains[1].Sections))
	}
	if domains[1].Sections[0].Name != "installations" {
		t.Fatalf("rabbitmq first section = %q, want installations", domains[1].Sections[0].Name)
	}
}
