package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrSAMLServiceProviderNotFound = errors.New("saml service provider not found")

func RegisterSAMLServiceProvider(ctx context.Context, db *sql.DB, req model.RegisterSAMLServiceProviderRequest) (model.SAMLServiceProvider, error) {
	if req.Slug == "" {
		return model.SAMLServiceProvider{}, fmt.Errorf("saml sp slug required")
	}
	if req.SPEntityID == "" {
		return model.SAMLServiceProvider{}, fmt.Errorf("sp_entity_id required")
	}
	if req.ACSURL == "" {
		return model.SAMLServiceProvider{}, fmt.Errorf("acs_url required")
	}
	nameID := req.NameIDFormat
	if nameID == "" {
		nameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	mapping, err := json.Marshal(req.AttributeMapping)
	if err != nil {
		return model.SAMLServiceProvider{}, fmt.Errorf("marshal attribute_mapping: %w", err)
	}
	if string(mapping) == "null" {
		mapping = []byte("{}")
	}
	signing := true
	if req.SigningRequired != nil {
		signing = *req.SigningRequired
	}
	encryption := false
	if req.EncryptionRequired != nil {
		encryption = *req.EncryptionRequired
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO public.saml_service_providers (
			slug, sp_entity_id, acs_url, slo_url, name_id_format,
			attribute_mapping, signing_required, encryption_required,
			sp_x509_cert
		) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9)
		ON CONFLICT (slug) DO UPDATE SET
			sp_entity_id = EXCLUDED.sp_entity_id,
			acs_url = EXCLUDED.acs_url,
			slo_url = EXCLUDED.slo_url,
			name_id_format = EXCLUDED.name_id_format,
			attribute_mapping = EXCLUDED.attribute_mapping,
			signing_required = EXCLUDED.signing_required,
			encryption_required = EXCLUDED.encryption_required,
			sp_x509_cert = EXCLUDED.sp_x509_cert,
			updated_at = NOW()
		RETURNING id, slug, sp_entity_id, acs_url, COALESCE(slo_url,''),
			name_id_format, attribute_mapping, signing_required,
			encryption_required, sp_x509_cert, status, metadata,
			created_at, updated_at
	`, req.Slug, req.SPEntityID, req.ACSURL, req.SLOURL, nameID,
		mapping, signing, encryption, req.SPX509Cert)
	return scanSAMLServiceProvider(row)
}

func GetSAMLServiceProviderBySlug(ctx context.Context, db *sql.DB, slug string) (model.SAMLServiceProvider, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, slug, sp_entity_id, acs_url, COALESCE(slo_url,''),
			name_id_format, attribute_mapping, signing_required,
			encryption_required, sp_x509_cert, status, metadata,
			created_at, updated_at
		FROM public.saml_service_providers WHERE slug = $1
	`, slug)
	sp, err := scanSAMLServiceProvider(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SAMLServiceProvider{}, ErrSAMLServiceProviderNotFound
	}
	return sp, err
}

func GetSAMLServiceProviderByEntityID(ctx context.Context, db *sql.DB, entityID string) (model.SAMLServiceProvider, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, slug, sp_entity_id, acs_url, COALESCE(slo_url,''),
			name_id_format, attribute_mapping, signing_required,
			encryption_required, sp_x509_cert, status, metadata,
			created_at, updated_at
		FROM public.saml_service_providers WHERE sp_entity_id = $1
	`, entityID)
	sp, err := scanSAMLServiceProvider(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SAMLServiceProvider{}, ErrSAMLServiceProviderNotFound
	}
	return sp, err
}

func ListSAMLServiceProviders(ctx context.Context, db *sql.DB) ([]model.SAMLServiceProvider, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, slug, sp_entity_id, acs_url, COALESCE(slo_url,''),
			name_id_format, attribute_mapping, signing_required,
			encryption_required, sp_x509_cert, status, metadata,
			created_at, updated_at
		FROM public.saml_service_providers
		ORDER BY slug ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list saml sps: %w", err)
	}
	defer rows.Close()
	var out []model.SAMLServiceProvider
	for rows.Next() {
		sp, err := scanSAMLServiceProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func DeactivateSAMLServiceProvider(ctx context.Context, db *sql.DB, slug string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.saml_service_providers SET status = 'inactive' WHERE slug = $1
	`, slug)
	if err != nil {
		return fmt.Errorf("deactivate saml sp: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSAMLServiceProviderNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSAMLServiceProvider(r rowScanner) (model.SAMLServiceProvider, error) {
	var sp model.SAMLServiceProvider
	var attrJSON, metaJSON []byte
	if err := r.Scan(
		&sp.ID, &sp.Slug, &sp.SPEntityID, &sp.ACSURL, &sp.SLOURL,
		&sp.NameIDFormat, &attrJSON, &sp.SigningRequired,
		&sp.EncryptionRequired, &sp.SPX509Cert, &sp.Status, &metaJSON,
		&sp.CreatedAt, &sp.UpdatedAt,
	); err != nil {
		return model.SAMLServiceProvider{}, err
	}
	if len(attrJSON) > 0 {
		if err := json.Unmarshal(attrJSON, &sp.AttributeMapping); err != nil {
			return model.SAMLServiceProvider{}, fmt.Errorf("unmarshal attribute_mapping: %w", err)
		}
	}
	if sp.AttributeMapping == nil {
		sp.AttributeMapping = map[string]string{}
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &sp.Metadata); err != nil {
			return model.SAMLServiceProvider{}, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	if sp.Metadata == nil {
		sp.Metadata = map[string]interface{}{}
	}
	return sp, nil
}

// silence linter for unused import; uuid is used in the model
var _ = uuid.Nil
