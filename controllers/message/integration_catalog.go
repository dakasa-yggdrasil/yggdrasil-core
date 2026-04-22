package message

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type integrationCatalogPosition struct {
	Domain  string
	Section string
	Entry   string
}

func integrationCatalogList(
	ctx context.Context,
	db *sql.DB,
	req model.ListIntegrationCatalogRequest,
) ([]model.IntegrationCatalogDomain, error) {
	req = normalizeListIntegrationCatalogRequest(req)

	typeManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_type",
		Namespace:  req.Namespace,
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	instanceManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	entries := make([]model.IntegrationCatalogEntry, 0, len(typeManifests))
	for _, typeManifest := range typeManifests {
		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
		if err != nil {
			return nil, fmt.Errorf("parse integration_type %s/%s: %w", typeManifest.Metadata.Namespace, typeManifest.Metadata.Name, err)
		}

		position := deriveIntegrationCatalogPosition(typeManifest, typeSpec)
		if !matchesIntegrationCatalogFilter(position, req) {
			continue
		}

		instances, err := buildIntegrationCatalogInstances(ctx, db, typeManifest, instanceManifests, req.CheckKind)
		if err != nil {
			return nil, err
		}
		runtimeState := summarizeIntegrationCatalogEntryRuntimeState(instances)

		entries = append(entries, model.IntegrationCatalogEntry{
			Domain:          position.Domain,
			Section:         position.Section,
			Entry:           position.Entry,
			PluginName:      typeManifest.Metadata.Name,
			Description:     strings.TrimSpace(typeManifest.Metadata.Description),
			Provider:        strings.ToLower(strings.TrimSpace(typeSpec.Provider)),
			AdapterVersion:  strings.TrimSpace(typeSpec.Adapter.Version),
			Status:          summarizeIntegrationCatalogEntryStatus(instances),
			Labels:          cloneStringMap(typeManifest.Metadata.Labels),
			Capabilities:    cloneStringSlice(typeSpec.Capabilities),
			IntegrationType: manifestReferenceFromRecord(typeManifest),
			RuntimeState:    runtimeState,
			Instances:       instances,
		})
	}

	return groupIntegrationCatalogEntries(entries), nil
}

// ListIntegrationCatalog exposes the explicit catalog view for synchronous callers such as HTTP surfaces.
func ListIntegrationCatalog(
	ctx context.Context,
	db *sql.DB,
	req model.ListIntegrationCatalogRequest,
) ([]model.IntegrationCatalogDomain, error) {
	return integrationCatalogList(ctx, db, req)
}

func getIntegrationCatalogEntry(
	ctx context.Context,
	db *sql.DB,
	req model.GetIntegrationCatalogEntryRequest,
) (model.IntegrationCatalogEntry, error) {
	req = normalizeGetIntegrationCatalogEntryRequest(req)
	if req.Domain == "" || req.Section == "" || req.Entry == "" {
		return model.IntegrationCatalogEntry{}, fmt.Errorf("domain, section, and entry are required")
	}

	domains, err := integrationCatalogList(ctx, db, model.ListIntegrationCatalogRequest(req))
	if err != nil {
		return model.IntegrationCatalogEntry{}, err
	}

	for _, domain := range domains {
		for _, section := range domain.Sections {
			for _, entry := range section.Entries {
				if entry.Domain == req.Domain && entry.Section == req.Section && entry.Entry == req.Entry {
					return entry, nil
				}
			}
		}
	}

	return model.IntegrationCatalogEntry{}, repository.ErrManifestNotFound
}

// GetIntegrationCatalogEntry exposes one explicit catalog entry for synchronous callers such as HTTP surfaces.
func GetIntegrationCatalogEntry(
	ctx context.Context,
	db *sql.DB,
	req model.GetIntegrationCatalogEntryRequest,
) (model.IntegrationCatalogEntry, error) {
	return getIntegrationCatalogEntry(ctx, db, req)
}

func normalizeListIntegrationCatalogRequest(req model.ListIntegrationCatalogRequest) model.ListIntegrationCatalogRequest {
	req.Namespace = strings.ToLower(strings.TrimSpace(req.Namespace))
	req.Domain = normalizeCatalogValue(req.Domain)
	req.Section = normalizeCatalogValue(req.Section)
	req.Entry = normalizeCatalogValue(req.Entry)
	req.CheckKind = normalizeIntegrationInstanceHealthCheckKind(req.CheckKind)
	return req
}

func normalizeGetIntegrationCatalogEntryRequest(req model.GetIntegrationCatalogEntryRequest) model.GetIntegrationCatalogEntryRequest {
	req.Namespace = strings.ToLower(strings.TrimSpace(req.Namespace))
	req.Domain = normalizeCatalogValue(req.Domain)
	req.Section = normalizeCatalogValue(req.Section)
	req.Entry = normalizeCatalogValue(req.Entry)
	req.CheckKind = normalizeIntegrationInstanceHealthCheckKind(req.CheckKind)
	return req
}

func deriveIntegrationCatalogPosition(
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
) integrationCatalogPosition {
	labels := typeManifest.Metadata.Labels

	domain := normalizeCatalogValue(labels[model.IntegrationCatalogLabelDomain])
	if domain == "" {
		domain = normalizeCatalogValue(typeSpec.Provider)
	}
	if domain == "" {
		domain = normalizeCatalogValue(typeManifest.Metadata.Name)
	}

	section := normalizeCatalogValue(labels[model.IntegrationCatalogLabelSection])
	if section == "" {
		section = inferCatalogSection(typeManifest.Metadata.Name, typeSpec.Provider)
	}

	entry := normalizeCatalogValue(labels[model.IntegrationCatalogLabelEntry])
	if entry == "" {
		entry = deriveCatalogEntryFallback(typeManifest.Metadata.Name, section)
	}

	return integrationCatalogPosition{
		Domain:  domain,
		Section: section,
		Entry:   entry,
	}
}

func deriveCatalogEntryFallback(pluginName, section string) string {
	pluginName = normalizeCatalogValue(pluginName)
	if pluginName == "" {
		return "default"
	}

	if section == model.IntegrationCatalogSectionInstallations {
		// Legacy "<provider>-on-<substrate>" form (e.g. rabbitmq-on-kubernetes).
		if _, suffix, ok := strings.Cut(pluginName, "-on-"); ok {
			if suffix = normalizeCatalogValue(suffix); suffix != "" {
				return suffix
			}
		}
		// Current "<provider>-<substrate>" form (e.g. rabbitmq-kubernetes).
		// Take the last "-"-separated token as the substrate when it matches
		// a known one — keeps single-word providers (rabbitmq, grafana) out
		// of the fallback while picking up explicit installation substrates.
		if substrate := knownInstallationSubstrate(pluginName); substrate != "" {
			return substrate
		}
		return "default"
	}

	return "api"
}

// inferCatalogSection guesses a section when the manifest omits the
// yggdrasil.io/catalog-section label. Recognized patterns:
//
//   - "<provider>-on-<substrate>" → installations (legacy naming)
//   - "<provider>-<substrate>" where substrate is a known installation
//     target (kubernetes, helm, ...) → installations (current naming)
//   - everything else → operations (the safe default for runtime adapters)
func inferCatalogSection(pluginName, provider string) string {
	name := strings.ToLower(strings.TrimSpace(pluginName))
	if name == "" {
		return model.IntegrationCatalogSectionOperations
	}
	if strings.Contains(name, "-on-") {
		return model.IntegrationCatalogSectionInstallations
	}
	if knownInstallationSubstrate(name) != "" {
		return model.IntegrationCatalogSectionInstallations
	}
	_ = provider // reserved for future provider-specific overrides
	return model.IntegrationCatalogSectionOperations
}

// knownInstallationSubstrate returns the substrate name (e.g. "kubernetes")
// when pluginName ends with one we recognize as an installation target.
// Empty return means the suffix doesn't denote an installation — the caller
// should fall back to "operations".
func knownInstallationSubstrate(pluginName string) string {
	name := strings.ToLower(strings.TrimSpace(pluginName))
	for _, substrate := range knownInstallationSubstrates {
		if strings.HasSuffix(name, "-"+substrate) {
			return substrate
		}
	}
	return ""
}

// knownInstallationSubstrates enumerates suffixes that mark a provider as an
// installation adapter rather than a runtime operations adapter. Keep this
// list narrow: false positives push runtime providers into the wrong section.
var knownInstallationSubstrates = []string{
	"kubernetes",
	"helm",
	"compose",
}

func normalizeCatalogValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "-")
	return value
}

func matchesIntegrationCatalogFilter(position integrationCatalogPosition, req model.ListIntegrationCatalogRequest) bool {
	if req.Domain != "" && position.Domain != req.Domain {
		return false
	}
	if req.Section != "" && position.Section != req.Section {
		return false
	}
	if req.Entry != "" && position.Entry != req.Entry {
		return false
	}
	return true
}

func buildIntegrationCatalogInstances(
	ctx context.Context,
	db *sql.DB,
	typeManifest model.Manifest,
	instanceManifests []model.Manifest,
	checkKind string,
) ([]model.IntegrationCatalogInstance, error) {
	items := make([]model.IntegrationCatalogInstance, 0)
	for _, instanceManifest := range instanceManifests {
		instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
		if err != nil {
			return nil, fmt.Errorf("parse integration_instance %s/%s: %w", instanceManifest.Metadata.Namespace, instanceManifest.Metadata.Name, err)
		}

		if !integrationInstanceTargetsType(instanceSpec.TypeRef, typeManifest) {
			continue
		}

		health, err := buildIntegrationInstanceHealth(ctx, db, instanceManifest, checkKind)
		if err != nil {
			return nil, err
		}

		items = append(items, model.IntegrationCatalogInstance{
			IntegrationInstance: manifestReferenceFromRecord(instanceManifest),
			Description:         strings.TrimSpace(instanceManifest.Metadata.Description),
			Owners:              cloneStringSlice(instanceSpec.Owners),
			DeclaredStatus:      health.DeclaredStatus,
			Status:              health.Status,
			RuntimeState:        health.RuntimeState,
		})
	}

	slices.SortFunc(items, func(a, b model.IntegrationCatalogInstance) int {
		if cmp := strings.Compare(a.IntegrationInstance.Namespace, b.IntegrationInstance.Namespace); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.IntegrationInstance.Name, b.IntegrationInstance.Name)
	})

	return items, nil
}

func integrationInstanceTargetsType(selector model.ManifestSelector, typeManifest model.Manifest) bool {
	if manifestID := strings.TrimSpace(selector.ManifestID); manifestID != "" {
		return manifestID == typeManifest.ID.String()
	}

	namespace := strings.ToLower(strings.TrimSpace(selector.Namespace))
	if namespace == "" {
		namespace = "global"
	}
	if namespace != typeManifest.Metadata.Namespace {
		return false
	}
	if strings.ToLower(strings.TrimSpace(selector.Name)) != typeManifest.Metadata.Name {
		return false
	}
	if selector.Version != nil && *selector.Version != typeManifest.Version {
		return false
	}
	return true
}

func summarizeIntegrationCatalogEntryStatus(instances []model.IntegrationCatalogInstance) string {
	if len(instances) == 0 {
		return model.IntegrationCatalogEntryStatusUnconfigured
	}

	statuses := make([]string, 0, len(instances))
	for _, instance := range instances {
		statuses = append(statuses, strings.ToLower(strings.TrimSpace(instance.Status)))
	}

	for _, preferred := range []string{
		model.IntegrationRuntimeStatusHealthy,
		model.IntegrationInstanceHealthStatusUnknown,
		model.IntegrationRuntimeStatusContractMismatch,
		model.IntegrationRuntimeStatusInvalidResponse,
		model.IntegrationRuntimeStatusUnreachable,
		"draft",
		"disabled",
	} {
		if slices.Contains(statuses, preferred) {
			return preferred
		}
	}

	return statuses[0]
}

func summarizeIntegrationCatalogEntryRuntimeState(
	instances []model.IntegrationCatalogInstance,
) *model.IntegrationRuntimeState {
	if len(instances) == 0 {
		return nil
	}

	for _, preferred := range []string{
		model.IntegrationRuntimeStatusHealthy,
		model.IntegrationInstanceHealthStatusUnknown,
		model.IntegrationRuntimeStatusContractMismatch,
		model.IntegrationRuntimeStatusInvalidResponse,
		model.IntegrationRuntimeStatusUnreachable,
		"draft",
		"disabled",
	} {
		for _, instance := range instances {
			if instance.RuntimeState == nil {
				continue
			}
			if strings.ToLower(strings.TrimSpace(instance.Status)) == preferred {
				return instance.RuntimeState
			}
		}
	}

	for _, instance := range instances {
		if instance.RuntimeState != nil {
			return instance.RuntimeState
		}
	}

	return nil
}

func groupIntegrationCatalogEntries(entries []model.IntegrationCatalogEntry) []model.IntegrationCatalogDomain {
	slices.SortFunc(entries, func(a, b model.IntegrationCatalogEntry) int {
		if cmp := strings.Compare(a.Domain, b.Domain); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Section, b.Section); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Entry, b.Entry); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.PluginName, b.PluginName)
	})

	domains := make([]model.IntegrationCatalogDomain, 0)
	var currentDomain *model.IntegrationCatalogDomain
	var currentSection *model.IntegrationCatalogSection

	for _, entry := range entries {
		if currentDomain == nil || currentDomain.Domain != entry.Domain {
			domains = append(domains, model.IntegrationCatalogDomain{
				Domain: entry.Domain,
			})
			currentDomain = &domains[len(domains)-1]
			currentSection = nil
		}

		if currentSection == nil || currentSection.Name != entry.Section {
			currentDomain.Sections = append(currentDomain.Sections, model.IntegrationCatalogSection{
				Name: entry.Section,
			})
			currentSection = &currentDomain.Sections[len(currentDomain.Sections)-1]
		}

		currentSection.Entries = append(currentSection.Entries, entry)
	}

	return domains
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}

	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func cloneStringSlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}
