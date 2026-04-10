package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

type discoveredManifestIndexes struct {
	integrationsByName       map[string]model.ManifestReference
	integrationsByCatalogKey map[string]model.ManifestReference
	surfacesByKey            map[string]model.ManifestReference
	surfacesByName           map[string]model.ManifestReference
}

type catalogDiscoveryOutput struct {
	Items []model.CatalogDiscoveryCandidate `json:"items"`
}

func discoverCatalog(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	req model.DiscoverCatalogRequest,
) (model.DiscoverCatalogResponse, error) {
	req = normalizeDiscoverCatalogRequest(req)

	sources, err := resolveCatalogDiscoverySources(ctx, conn, db, req)
	if err != nil {
		return model.DiscoverCatalogResponse{}, err
	}

	indexes, err := buildDiscoveredManifestIndexes(ctx, db, req.Namespace)
	if err != nil {
		return model.DiscoverCatalogResponse{}, err
	}

	items := make([]model.CatalogDiscoveryItem, 0)
	for index, source := range sources {
		response, err := executeCatalogDiscoverySource(ctx, conn, db, source, req)
		if err != nil {
			sources[index].DiscoveryStatus = "failed"
			sources[index].Message = strings.TrimSpace(err.Error())
			if manifestSelectorIsSet(req.Source) {
				return model.DiscoverCatalogResponse{}, err
			}
			continue
		}

		sources[index].DiscoveryStatus = "succeeded"
		for _, candidate := range response.Items {
			if !catalogDiscoveryCandidateMatchesRequest(candidate, req) {
				continue
			}
			items = append(items, buildCatalogDiscoveryItem(sources[index], candidate, indexes))
		}
	}

	items = sortAndLimitCatalogDiscoveryItems(items, req.Limit)

	return model.DiscoverCatalogResponse{
		Sources: sources,
		Items:   items,
	}, nil
}

// DiscoverCatalog exposes catalog discovery for synchronous callers such as HTTP surfaces.
func DiscoverCatalog(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	req model.DiscoverCatalogRequest,
) (model.DiscoverCatalogResponse, error) {
	return discoverCatalog(ctx, conn, db, req)
}

func normalizeDiscoverCatalogRequest(req model.DiscoverCatalogRequest) model.DiscoverCatalogRequest {
	req.Namespace = strings.ToLower(strings.TrimSpace(req.Namespace))
	req.Query = strings.TrimSpace(req.Query)
	req.Kinds = normalizeCatalogDiscoveryKinds(req.Kinds)
	if req.Limit < 0 {
		req.Limit = 0
	}
	return req
}

func normalizeCatalogDiscoveryKinds(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		switch value {
		case model.CatalogDiscoveryKindIntegration, model.CatalogDiscoveryKindSurface:
		default:
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func manifestSelectorIsSet(selector model.ManifestSelector) bool {
	return strings.TrimSpace(selector.ManifestID) != "" ||
		strings.TrimSpace(selector.Namespace) != "" ||
		strings.TrimSpace(selector.Name) != ""
}

func resolveCatalogDiscoverySources(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	req model.DiscoverCatalogRequest,
) ([]model.CatalogDiscoverySource, error) {
	if manifestSelectorIsSet(req.Source) {
		source, err := resolveCatalogDiscoverySource(ctx, conn, db, req.Source)
		if err != nil {
			return nil, err
		}
		return []model.CatalogDiscoverySource{source}, nil
	}

	instanceManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	sources := make([]model.CatalogDiscoverySource, 0, len(instanceManifests))
	for _, instanceManifest := range instanceManifests {
		instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
		if err != nil {
			return nil, fmt.Errorf("parse integration_instance %s/%s: %w", instanceManifest.Metadata.Namespace, instanceManifest.Metadata.Name, err)
		}

		typeManifest, err := resolveManifestForKind(
			ctx,
			db,
			"integration_type",
			instanceSpec.TypeRef.ManifestID,
			instanceSpec.TypeRef.Namespace,
			instanceSpec.TypeRef.Name,
			instanceSpec.TypeRef.Version,
		)
		if err != nil {
			return nil, err
		}

		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
		if err != nil {
			return nil, fmt.Errorf("parse integration_type %s/%s: %w", typeManifest.Metadata.Namespace, typeManifest.Metadata.Name, err)
		}
		if !integrationTypeSupportsCatalogDiscover(typeSpec) {
			continue
		}

		source, err := buildCatalogDiscoverySource(ctx, db, instanceManifest, typeManifest, typeSpec)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	slices.SortFunc(sources, func(left, right model.CatalogDiscoverySource) int {
		if cmp := strings.Compare(left.Domain, right.Domain); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Section, right.Section); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Entry, right.Entry); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.PluginName, right.PluginName)
	})

	return sources, nil
}

func resolveCatalogDiscoverySource(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	selector model.ManifestSelector,
) (model.CatalogDiscoverySource, error) {
	instanceManifest, _, typeManifest, typeSpec, err := resolveIntegrationInstance(ctx, conn, db, selector)
	if err != nil {
		return model.CatalogDiscoverySource{}, err
	}
	if !integrationTypeSupportsCatalogDiscover(typeSpec) {
		return model.CatalogDiscoverySource{}, fmt.Errorf(
			"integration instance %s/%s does not support %s",
			instanceManifest.Metadata.Namespace,
			instanceManifest.Metadata.Name,
			model.CatalogDiscoverOperation,
		)
	}

	return buildCatalogDiscoverySource(ctx, db, instanceManifest, typeManifest, typeSpec)
}

func buildCatalogDiscoverySource(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
) (model.CatalogDiscoverySource, error) {
	position := deriveIntegrationCatalogPosition(typeManifest, typeSpec)
	health, err := buildIntegrationInstanceHealth(ctx, db, instanceManifest, model.IntegrationRuntimeCheckKindOverall)
	if err != nil {
		return model.CatalogDiscoverySource{}, err
	}

	return model.CatalogDiscoverySource{
		IntegrationInstance: manifestReferenceFromRecord(instanceManifest),
		IntegrationType:     manifestReferenceFromRecord(typeManifest),
		Provider:            strings.ToLower(strings.TrimSpace(typeSpec.Provider)),
		PluginName:          strings.TrimSpace(typeManifest.Metadata.Name),
		Domain:              position.Domain,
		Section:             position.Section,
		Entry:               position.Entry,
		HealthStatus:        health.Status,
		DiscoveryStatus:     "pending",
	}, nil
}

func integrationTypeSupportsCatalogDiscover(typeSpec model.IntegrationTypeManifestSpec) bool {
	if !slices.Contains(typeSpec.Capabilities, "execute") {
		return false
	}

	for _, action := range typeSpec.ActionCatalog {
		if strings.EqualFold(strings.TrimSpace(action.Name), model.CatalogDiscoverOperation) {
			return true
		}
	}
	for _, resourceType := range typeSpec.ResourceTypes {
		for _, action := range resourceType.DefaultActions {
			if strings.EqualFold(strings.TrimSpace(action), model.CatalogDiscoverOperation) {
				return true
			}
		}
	}
	return false
}

func executeCatalogDiscoverySource(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	source model.CatalogDiscoverySource,
	req model.DiscoverCatalogRequest,
) (catalogDiscoveryOutput, error) {
	response, err := executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			ManifestID: source.IntegrationInstance.ID.String(),
			Namespace:  source.IntegrationInstance.Namespace,
			Name:       source.IntegrationInstance.Name,
			Version:    &source.IntegrationInstance.Version,
		},
		Operation:  model.CatalogDiscoverOperation,
		Capability: model.CatalogDiscoverOperation,
		Input: map[string]any{
			"kinds": req.Kinds,
			"query": req.Query,
			"limit": req.Limit,
		},
		Metadata: map[string]any{
			"purpose": "catalog_discovery",
		},
	}, 0)
	if err != nil {
		return catalogDiscoveryOutput{}, err
	}

	var output catalogDiscoveryOutput
	raw, err := json.Marshal(response.Output)
	if err != nil {
		return catalogDiscoveryOutput{}, fmt.Errorf("marshal discovery output: %w", err)
	}
	if len(bytesTrimSpace(raw)) == 0 || string(bytesTrimSpace(raw)) == "null" {
		return catalogDiscoveryOutput{}, nil
	}
	if err := json.Unmarshal(raw, &output); err != nil {
		return catalogDiscoveryOutput{}, fmt.Errorf("decode discovery output: %w", err)
	}

	return output, nil
}

func buildDiscoveredManifestIndexes(
	ctx context.Context,
	db *sql.DB,
	namespace string,
) (discoveredManifestIndexes, error) {
	typeManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_type",
		Namespace:  namespace,
		ActiveOnly: true,
	})
	if err != nil {
		return discoveredManifestIndexes{}, err
	}

	surfaceManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "surface",
		Namespace:  namespace,
		ActiveOnly: true,
	})
	if err != nil {
		return discoveredManifestIndexes{}, err
	}

	indexes := discoveredManifestIndexes{
		integrationsByName:       map[string]model.ManifestReference{},
		integrationsByCatalogKey: map[string]model.ManifestReference{},
		surfacesByKey:            map[string]model.ManifestReference{},
		surfacesByName:           map[string]model.ManifestReference{},
	}

	for _, manifestRecord := range typeManifests {
		indexes.integrationsByName[manifestRecord.Metadata.Name] = manifestReferenceFromRecord(manifestRecord)

		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(manifestRecord.Spec)
		if err != nil {
			return discoveredManifestIndexes{}, fmt.Errorf("parse integration_type %s/%s: %w", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name, err)
		}
		position := deriveIntegrationCatalogPosition(manifestRecord, typeSpec)
		indexes.integrationsByCatalogKey[catalogDiscoveryIntegrationKey(position.Domain, position.Section, position.Entry)] = manifestReferenceFromRecord(manifestRecord)
	}

	for _, manifestRecord := range surfaceManifests {
		ref := manifestReferenceFromRecord(manifestRecord)
		indexes.surfacesByKey[catalogDiscoverySurfaceKey(manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name)] = ref
		if _, exists := indexes.surfacesByName[manifestRecord.Metadata.Name]; !exists {
			indexes.surfacesByName[manifestRecord.Metadata.Name] = ref
		}
	}

	return indexes, nil
}

func buildCatalogDiscoveryItem(
	source model.CatalogDiscoverySource,
	candidate model.CatalogDiscoveryCandidate,
	indexes discoveredManifestIndexes,
) model.CatalogDiscoveryItem {
	candidate.Kind = strings.ToLower(strings.TrimSpace(candidate.Kind))
	candidate.Name = strings.ToLower(strings.TrimSpace(candidate.Name))
	candidate.Namespace = strings.ToLower(strings.TrimSpace(candidate.Namespace))
	candidate.Domain = normalizeCatalogValue(candidate.Domain)
	candidate.Section = normalizeCatalogValue(candidate.Section)
	candidate.Entry = normalizeCatalogValue(candidate.Entry)

	item := model.CatalogDiscoveryItem{
		Source:             source,
		Kind:               candidate.Kind,
		Name:               candidate.Name,
		Namespace:          candidate.Namespace,
		DisplayName:        strings.TrimSpace(candidate.DisplayName),
		Description:        strings.TrimSpace(candidate.Description),
		Domain:             candidate.Domain,
		Section:            candidate.Section,
		Entry:              candidate.Entry,
		Repository:         strings.TrimSpace(candidate.Repository),
		Labels:             cloneStringMap(candidate.Labels),
		Metadata:           cloneAuthorizationInput(candidate.Metadata),
		Registration:       candidate.Registration,
		RegistrationStatus: model.CatalogDiscoveryRegistrationMissing,
	}

	if registered := matchDiscoveredCandidate(indexes, candidate); registered != nil {
		item.RegisteredManifest = registered
		item.RegistrationStatus = model.CatalogDiscoveryRegistrationRegistered
	}

	return item
}

func matchDiscoveredCandidate(indexes discoveredManifestIndexes, candidate model.CatalogDiscoveryCandidate) *model.ManifestReference {
	switch strings.ToLower(strings.TrimSpace(candidate.Kind)) {
	case model.CatalogDiscoveryKindIntegration:
		if candidate.Name != "" {
			if ref, exists := indexes.integrationsByName[strings.ToLower(strings.TrimSpace(candidate.Name))]; exists {
				return manifestReferencePointer(ref)
			}
		}
		key := catalogDiscoveryIntegrationKey(candidate.Domain, candidate.Section, candidate.Entry)
		if ref, exists := indexes.integrationsByCatalogKey[key]; exists {
			return manifestReferencePointer(ref)
		}
	case model.CatalogDiscoveryKindSurface:
		if candidate.Name != "" && candidate.Namespace != "" {
			if ref, exists := indexes.surfacesByKey[catalogDiscoverySurfaceKey(candidate.Namespace, candidate.Name)]; exists {
				return manifestReferencePointer(ref)
			}
		}
		if candidate.Name != "" {
			if ref, exists := indexes.surfacesByName[strings.ToLower(strings.TrimSpace(candidate.Name))]; exists {
				return manifestReferencePointer(ref)
			}
		}
	}
	return nil
}

func catalogDiscoveryIntegrationKey(domain, section, entry string) string {
	return normalizeCatalogValue(domain) + "/" + normalizeCatalogValue(section) + "/" + normalizeCatalogValue(entry)
}

func catalogDiscoverySurfaceKey(namespace, name string) string {
	return strings.ToLower(strings.TrimSpace(namespace)) + "/" + strings.ToLower(strings.TrimSpace(name))
}

func catalogDiscoveryCandidateMatchesRequest(candidate model.CatalogDiscoveryCandidate, req model.DiscoverCatalogRequest) bool {
	if len(req.Kinds) > 0 && !slices.Contains(req.Kinds, strings.ToLower(strings.TrimSpace(candidate.Kind))) {
		return false
	}
	if req.Query == "" {
		return true
	}

	query := strings.ToLower(strings.TrimSpace(req.Query))
	for _, value := range []string{
		candidate.Name,
		candidate.DisplayName,
		candidate.Description,
		candidate.Domain,
		candidate.Section,
		candidate.Entry,
		candidate.Repository,
	} {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), query) {
			return true
		}
	}
	return false
}

func sortAndLimitCatalogDiscoveryItems(items []model.CatalogDiscoveryItem, limit int) []model.CatalogDiscoveryItem {
	slices.SortFunc(items, func(left, right model.CatalogDiscoveryItem) int {
		if cmp := strings.Compare(left.Kind, right.Kind); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Domain, right.Domain); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Section, right.Section); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Entry, right.Entry); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Namespace, right.Namespace); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.Name, right.Name); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.Source.IntegrationInstance.Name, right.Source.IntegrationInstance.Name)
	})
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}
