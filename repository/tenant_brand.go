package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

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
				$8
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
		updatedBy,
	)

	updated, err := scanTenantBrand(row)
	if err != nil {
		return model.TenantBrand{}, fmt.Errorf("update tenant brand: %w", err)
	}
	return updated, nil
}

func normalizeTenantBrandRequest(req model.UpdateTenantBrandRequest) (model.TenantBrand, error) {
	brand := model.TenantBrand{
		Name:           strings.TrimSpace(req.Name),
		ShortName:      strings.ToUpper(strings.TrimSpace(req.ShortName)),
		ProductLabel:   strings.TrimSpace(req.ProductLabel),
		Locale:         strings.TrimSpace(req.Locale),
		AccentOverride: strings.TrimSpace(req.AccentOverride),
		LogoURL:        strings.TrimSpace(req.LogoURL),
		SupportEmail:   strings.TrimSpace(req.SupportEmail),
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
	var updatedBy sql.NullString
	err := row.Scan(
		&brand.Name,
		&brand.ShortName,
		&brand.ProductLabel,
		&brand.Locale,
		&accent,
		&logo,
		&support,
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
	if updatedBy.Valid {
		if id, err := uuid.Parse(updatedBy.String); err == nil {
			brand.UpdatedBy = &id
		}
	}
	return brand, nil
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
