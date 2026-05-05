package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

func GetOIDCProviderSettings(ctx context.Context, db *sql.DB) (model.OIDCProviderSettings, error) {
	var s model.OIDCProviderSettings
	err := db.QueryRowContext(ctx, `
		SELECT allowed_email_domains, default_team_slug, auto_provision
		FROM oidc_provider_settings
		WHERE singleton = TRUE
	`).Scan(pq.Array(&s.AllowedEmailDomains), &s.DefaultTeamSlug, &s.AutoProvision)
	if err != nil {
		return model.OIDCProviderSettings{}, fmt.Errorf("get provider settings: %w", err)
	}
	return s, nil
}

func UpdateOIDCProviderSettings(ctx context.Context, db *sql.DB, s model.OIDCProviderSettings) error {
	_, err := db.ExecContext(ctx, `
		UPDATE oidc_provider_settings
		SET allowed_email_domains = $1, default_team_slug = $2, auto_provision = $3
		WHERE singleton = TRUE
	`, pq.Array(s.AllowedEmailDomains), s.DefaultTeamSlug, s.AutoProvision)
	if err != nil {
		return fmt.Errorf("update provider settings: %w", err)
	}
	return nil
}
