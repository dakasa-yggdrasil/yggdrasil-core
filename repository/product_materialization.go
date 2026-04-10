package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// HasProductMaterialization returns whether a stored materialization exists for the given manifest version.
func HasProductMaterialization(ctx context.Context, db *sql.DB, product model.Manifest) (bool, error) {
	var exists bool
	err := db.QueryRowContext(
		ctx,
		`
			SELECT EXISTS (
				SELECT 1
				FROM public.product_materializations
				WHERE product_manifest_id = $1
				  AND product_version = $2
			)
		`,
		product.ID,
		product.Version,
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// CreateProductMaterialization stores one immutable, audit-friendly snapshot of a materialized product.
func CreateProductMaterialization(
	ctx context.Context,
	db *sql.DB,
	product model.Manifest,
	materializedSpec model.ProductManifestSpec,
	components []model.ProductMaterializationComponent,
) (model.ProductMaterialization, error) {
	spec, err := json.Marshal(materializedSpec)
	if err != nil {
		return model.ProductMaterialization{}, err
	}

	componentsJSON, err := json.Marshal(components)
	if err != nil {
		return model.ProductMaterialization{}, err
	}

	checksum := sha256.Sum256(spec)
	materializedChecksum := hex.EncodeToString(checksum[:])

	q := `
		INSERT INTO public.product_materializations (
			product_manifest_id,
			product_version,
			product_checksum,
			materialized_spec,
			materialized_checksum,
			components
		) VALUES (
			$1,
			$2,
			$3,
			$4::jsonb,
			$5,
			$6::jsonb
		)
		RETURNING
			id,
			product_manifest_id,
			product_version,
			product_checksum,
			materialized_spec,
			materialized_checksum,
			components,
			created_at
	`

	return scanProductMaterialization(
		product,
		db.QueryRowContext(
			ctx,
			q,
			product.ID,
			product.Version,
			product.Checksum,
			spec,
			materializedChecksum,
			componentsJSON,
		),
	)
}

type productMaterializationScanner interface {
	Scan(dest ...any) error
}

func scanProductMaterialization(product model.Manifest, row productMaterializationScanner) (model.ProductMaterialization, error) {
	var (
		record            model.ProductMaterialization
		productManifestID uuid.UUID
		productVersion    int
		spec              []byte
		components        []byte
	)

	if err := row.Scan(
		&record.ID,
		&productManifestID,
		&productVersion,
		&record.ProductChecksum,
		&spec,
		&record.MaterializedChecksum,
		&components,
		&record.CreatedAt,
	); err != nil {
		return model.ProductMaterialization{}, err
	}

	record.Product = model.ManifestReference{
		ID:        productManifestID,
		Kind:      product.Kind,
		Namespace: product.Metadata.Namespace,
		Name:      product.Metadata.Name,
		Version:   productVersion,
	}
	record.MaterializedSpec = json.RawMessage(spec)

	if len(components) > 0 {
		if err := json.Unmarshal(components, &record.Components); err != nil {
			return model.ProductMaterialization{}, err
		}
	}

	return record, nil
}
