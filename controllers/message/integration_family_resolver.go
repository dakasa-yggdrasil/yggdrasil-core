package message

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// resolveIntegrationByFamily resolves a concrete integration_instance when the
// caller addresses the integration by family + operation instead of by an
// explicit instance_ref.
//
// Resolution order:
//  1. If pinnedProvider is non-nil, load that specific integration_type and
//     verify it belongs to the named family + implements the operation.
//  2. Otherwise, list every active integration_type whose FamilyRef.Name
//     matches familyName and whose ImplementedOperations contains operation.
//     - 0 matches ⇒ error "no active provider implementing {family}.{operation}".
//     - >1 match ⇒ error listing candidates, asking the caller to pin via
//       provider_ref. (Ambiguity is intentionally loud — picking silently
//       would surprise operators who added a second provider.)
//     - 1 match ⇒ proceed.
//  3. Load the single active integration_instance of the resolved provider.
//     Zero or multiple active instances are both errors — operators must keep
//     exactly one active instance per provider per namespace.
//  4. Hydrate, validate, preflight, verify — same tail as
//     resolveIntegrationInstance so callers get uniform error surface.
func resolveIntegrationByFamily(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	familyName, operation string,
	pinnedProvider *model.ManifestSelector,
) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error) {
	family := strings.ToLower(strings.TrimSpace(familyName))
	op := strings.ToLower(strings.TrimSpace(operation))
	if family == "" {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{},
			fmt.Errorf("resolve integration by family: family name is required")
	}
	if op == "" {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{},
			fmt.Errorf("resolve integration by family: operation is required")
	}

	typeManifest, typeSpec, err := resolveProviderForFamily(ctx, db, family, op, pinnedProvider)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	instanceManifest, instanceSpec, err := resolveActiveInstanceForProvider(ctx, db, typeManifest)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	if err := hydrateIntegrationInstanceSecrets(ctx, db, &instanceSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	if err := manifestengine.ValidateHydratedIntegrationInstanceInputs(instanceSpec, typeSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	if err := preflightIntegrationInstanceHealth(
		ctx, db, instanceManifest, instanceSpec, typeManifest,
		model.IntegrationRuntimeCheckKindOverall,
	); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	if err := verifyResolvedIntegrationType(ctx, conn, db, instanceManifest, typeManifest, instanceSpec, typeSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	return instanceManifest, instanceSpec, typeManifest, typeSpec, nil
}

func resolveProviderForFamily(
	ctx context.Context,
	db *sql.DB,
	familyName, operation string,
	pinnedProvider *model.ManifestSelector,
) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	if pinnedProvider != nil {
		typeManifest, err := resolveManifestForKind(
			ctx, db, "integration_type",
			pinnedProvider.ManifestID, pinnedProvider.Namespace, pinnedProvider.Name, pinnedProvider.Version,
		)
		if err != nil {
			return model.Manifest{}, model.IntegrationTypeManifestSpec{},
				fmt.Errorf("resolve pinned provider %q: %w", pinnedProvider.Name, err)
		}
		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
		if err != nil {
			return model.Manifest{}, model.IntegrationTypeManifestSpec{},
				fmt.Errorf("parse pinned provider spec: %w", err)
		}
		if err := assertProviderCoversFamilyOperation(typeManifest, typeSpec, familyName, operation); err != nil {
			return model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
		}
		return typeManifest, typeSpec, nil
	}

	candidates, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_type",
		ActiveOnly: true,
	})
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("list integration_type manifests: %w", err)
	}

	type match struct {
		manifest model.Manifest
		spec     model.IntegrationTypeManifestSpec
	}
	var matches []match
	for _, candidate := range candidates {
		spec, err := manifestengine.ParseIntegrationTypeSpec(candidate.Spec)
		if err != nil {
			continue
		}
		if spec.FamilyRef == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(spec.FamilyRef.Name)) != familyName {
			continue
		}
		if !containsFold(spec.ImplementedOperations, operation) {
			continue
		}
		matches = append(matches, match{manifest: candidate, spec: spec})
	}

	switch len(matches) {
	case 0:
		return model.Manifest{}, model.IntegrationTypeManifestSpec{},
			fmt.Errorf("no active provider implements %s.%s", familyName, operation)
	case 1:
		return matches[0].manifest, matches[0].spec, nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.manifest.Metadata.Name)
		}
		return model.Manifest{}, model.IntegrationTypeManifestSpec{},
			fmt.Errorf("%d active providers implement %s.%s (%s); pin one via provider_ref",
				len(matches), familyName, operation, strings.Join(names, ", "))
	}
}

func resolveActiveInstanceForProvider(
	ctx context.Context,
	db *sql.DB,
	typeManifest model.Manifest,
) (model.Manifest, model.IntegrationInstanceManifestSpec, error) {
	candidates, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{},
			fmt.Errorf("list integration_instance manifests: %w", err)
	}

	var matches []model.Manifest
	var specs []model.IntegrationInstanceManifestSpec
	for _, candidate := range candidates {
		spec, err := manifestengine.ParseIntegrationInstanceSpec(candidate.Spec)
		if err != nil {
			continue
		}
		if !selectorMatchesManifest(spec.TypeRef, typeManifest) {
			continue
		}
		if strings.ToLower(strings.TrimSpace(spec.Status)) == "disabled" {
			continue
		}
		matches = append(matches, candidate)
		specs = append(specs, spec)
	}

	switch len(matches) {
	case 0:
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{},
			fmt.Errorf("no active integration_instance for provider %q", typeManifest.Metadata.Name)
	case 1:
		return matches[0], specs[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Metadata.Name)
		}
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{},
			fmt.Errorf("%d active instances for provider %q (%s); keep exactly one active",
				len(matches), typeManifest.Metadata.Name, strings.Join(names, ", "))
	}
}

func assertProviderCoversFamilyOperation(
	typeManifest model.Manifest,
	typeSpec model.IntegrationTypeManifestSpec,
	familyName, operation string,
) error {
	if typeSpec.FamilyRef == nil {
		return fmt.Errorf("provider %q has no family_ref", typeManifest.Metadata.Name)
	}
	if strings.ToLower(strings.TrimSpace(typeSpec.FamilyRef.Name)) != familyName {
		return fmt.Errorf("provider %q belongs to family %q, not %q",
			typeManifest.Metadata.Name, typeSpec.FamilyRef.Name, familyName)
	}
	if !containsFold(typeSpec.ImplementedOperations, operation) {
		return fmt.Errorf("provider %q does not implement operation %q of family %q",
			typeManifest.Metadata.Name, operation, familyName)
	}
	return nil
}

func selectorMatchesManifest(sel model.ManifestSelector, manifest model.Manifest) bool {
	if strings.TrimSpace(sel.ManifestID) != "" {
		return strings.EqualFold(sel.ManifestID, manifest.ID.String())
	}
	if strings.TrimSpace(sel.Name) == "" {
		return false
	}
	if !strings.EqualFold(sel.Name, manifest.Metadata.Name) {
		return false
	}
	if strings.TrimSpace(sel.Namespace) != "" && !strings.EqualFold(sel.Namespace, manifest.Metadata.Namespace) {
		return false
	}
	if sel.Version != nil && *sel.Version != manifest.Version {
		return false
	}
	return true
}

func containsFold(haystack []string, needle string) bool {
	target := strings.ToLower(strings.TrimSpace(needle))
	for _, candidate := range haystack {
		if strings.EqualFold(strings.TrimSpace(candidate), target) {
			return true
		}
	}
	return slices.Contains(haystack, needle)
}
