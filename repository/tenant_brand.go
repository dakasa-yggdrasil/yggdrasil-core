package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var integrationDomainSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func GetTenantBrand(ctx context.Context, db *sql.DB) (model.TenantBrand, error) {
	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				name,
				short_name,
				product_label,
				locale,
				accent_override,
				logo_url,
				support_email,
				COALESCE(integration_domain_catalog, '[]'::jsonb),
				updated_by,
				created_at,
				updated_at
			FROM public.tenant_brand_settings
			WHERE singleton = TRUE
		`,
	)

	brand, err := scanTenantBrand(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DefaultTenantBrand(), nil
	}
	if isUndefinedTable(err) {
		return model.DefaultTenantBrand(), nil
	}
	if err != nil {
		return model.TenantBrand{}, fmt.Errorf("get tenant brand: %w", err)
	}
	return brand, nil
}

func UpdateTenantBrand(
	ctx context.Context,
	db *sql.DB,
	req model.UpdateTenantBrandRequest,
	updatedBy uuid.UUID,
) (model.TenantBrand, error) {
	brand, err := normalizeTenantBrandRequest(req)
	if err != nil {
		return model.TenantBrand{}, err
	}

	catalogJSON, err := json.Marshal(brand.IntegrationDomainCatalog)
	if err != nil {
		return model.TenantBrand{}, fmt.Errorf("marshal integration_domain_catalog: %w", err)
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.tenant_brand_settings (
				singleton,
				name,
				short_name,
				product_label,
				locale,
				accent_override,
				logo_url,
				support_email,
				integration_domain_catalog,
				updated_by
			) VALUES (
				TRUE,
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7,
				$8,
				$9
			)
			ON CONFLICT (singleton)
			DO UPDATE SET
				name = EXCLUDED.name,
				short_name = EXCLUDED.short_name,
				product_label = EXCLUDED.product_label,
				locale = EXCLUDED.locale,
				accent_override = EXCLUDED.accent_override,
				logo_url = EXCLUDED.logo_url,
				support_email = EXCLUDED.support_email,
				integration_domain_catalog = EXCLUDED.integration_domain_catalog,
				updated_by = EXCLUDED.updated_by,
				updated_at = NOW()
			RETURNING
				name,
				short_name,
				product_label,
				locale,
				accent_override,
				logo_url,
				support_email,
				COALESCE(integration_domain_catalog, '[]'::jsonb),
				updated_by,
				created_at,
				updated_at
		`,
		brand.Name,
		brand.ShortName,
		brand.ProductLabel,
		brand.Locale,
		nullString(brand.AccentOverride),
		nullString(brand.LogoURL),
		nullString(brand.SupportEmail),
		catalogJSON,
		updatedBy,
	)

	updated, err := scanTenantBrand(row)
	if err != nil {
		return model.TenantBrand{}, fmt.Errorf("update tenant brand: %w", err)
	}
	return updated, nil
}

func normalizeTenantBrandRequest(req model.UpdateTenantBrandRequest) (model.TenantBrand, error) {
	catalog, err := normalizeIntegrationDomainCatalog(req.IntegrationDomainCatalog)
	if err != nil {
		return model.TenantBrand{}, err
	}
	brand := model.TenantBrand{
		Name:                     strings.TrimSpace(req.Name),
		ShortName:                strings.ToUpper(strings.TrimSpace(req.ShortName)),
		ProductLabel:             strings.TrimSpace(req.ProductLabel),
		Locale:                   strings.TrimSpace(req.Locale),
		AccentOverride:           strings.TrimSpace(req.AccentOverride),
		LogoURL:                  strings.TrimSpace(req.LogoURL),
		SupportEmail:             strings.TrimSpace(req.SupportEmail),
		IntegrationDomainCatalog: catalog,
	}
	if brand.Name == "" {
		return model.TenantBrand{}, fmt.Errorf("name is required")
	}
	if brand.ShortName == "" {
		return model.TenantBrand{}, fmt.Errorf("short_name is required")
	}
	if len(brand.ShortName) > 12 {
		return model.TenantBrand{}, fmt.Errorf("short_name must have at most 12 characters")
	}
	if brand.ProductLabel == "" {
		return model.TenantBrand{}, fmt.Errorf("product_label is required")
	}
	if brand.Locale == "" {
		brand.Locale = "pt-BR"
	}
	if brand.Locale != "pt-BR" && brand.Locale != "en-US" {
		return model.TenantBrand{}, fmt.Errorf("locale is unsupported")
	}
	if brand.AccentOverride != "" && !isHexColor(brand.AccentOverride) {
		return model.TenantBrand{}, fmt.Errorf("accent_override must be a hex color")
	}
	return brand, nil
}

func scanTenantBrand(row interface {
	Scan(dest ...any) error
}) (model.TenantBrand, error) {
	var brand model.TenantBrand
	var accent, logo, support sql.NullString
	var catalogJSON []byte
	var updatedBy sql.NullString
	err := row.Scan(
		&brand.Name,
		&brand.ShortName,
		&brand.ProductLabel,
		&brand.Locale,
		&accent,
		&logo,
		&support,
		&catalogJSON,
		&updatedBy,
		&brand.CreatedAt,
		&brand.UpdatedAt,
	)
	if err != nil {
		return model.TenantBrand{}, err
	}
	brand.AccentOverride = accent.String
	brand.LogoURL = logo.String
	brand.SupportEmail = support.String
	if len(catalogJSON) > 0 {
		if err := json.Unmarshal(catalogJSON, &brand.IntegrationDomainCatalog); err != nil {
			return model.TenantBrand{}, fmt.Errorf("unmarshal integration_domain_catalog: %w", err)
		}
	}
	if updatedBy.Valid {
		if id, err := uuid.Parse(updatedBy.String); err == nil {
			brand.UpdatedBy = &id
		}
	}
	return brand, nil
}

// normalizeIntegrationDomainCatalog validates and trims each entry.
// Slug must match the same pattern as integration_type.spec.domain
// (lowercase slug). Title is required so the section has something to
// render; everything else is presentation polish.
func normalizeIntegrationDomainCatalog(
	entries []model.IntegrationDomainCatalogEntry,
) ([]model.IntegrationDomainCatalogEntry, error) {
	out := make([]model.IntegrationDomainCatalogEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		slug := strings.TrimSpace(strings.ToLower(entry.Slug))
		if slug == "" {
			return nil, fmt.Errorf("integration_domain_catalog[%d].slug is required", i)
		}
		if !integrationDomainSlugPattern.MatchString(slug) {
			return nil, fmt.Errorf(
				"integration_domain_catalog[%d].slug %q must match %s",
				i, entry.Slug, integrationDomainSlugPattern,
			)
		}
		if _, dup := seen[slug]; dup {
			return nil, fmt.Errorf(
				"integration_domain_catalog has duplicate slug %q",
				slug,
			)
		}
		seen[slug] = struct{}{}
		title := strings.TrimSpace(entry.Title)
		if title == "" {
			return nil, fmt.Errorf(
				"integration_domain_catalog[%d].title is required for slug %q",
				i, slug,
			)
		}
		out = append(out, model.IntegrationDomainCatalogEntry{
			Slug:     slug,
			Overline: strings.TrimSpace(entry.Overline),
			Title:    title,
			Subtitle: strings.TrimSpace(entry.Subtitle),
			Order:    entry.Order,
		})
	}
	return out, nil
}

func nullString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func isHexColor(value string) bool {
	if len(value) != 7 || value[0] != '#' {
		return false
	}
	for _, r := range value[1:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func isUndefinedTable(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42P01"
}
