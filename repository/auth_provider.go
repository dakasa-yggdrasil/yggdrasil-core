package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var ErrThirdPartyAuthProviderNotFound = errors.New("third-party auth provider not found")

// UpsertThirdPartyAuthProvider creates or updates one OAuth/OIDC provider config.
func UpsertThirdPartyAuthProvider(
	ctx context.Context,
	db *sql.DB,
	req model.UpsertThirdPartyAuthProviderRequest,
) (model.ThirdPartyAuthProvider, error) {
	provider, err := normalizeThirdPartyAuthProvider(model.ThirdPartyAuthProvider{
		Name:             req.Name,
		Type:             req.Type,
		Status:           req.Status,
		DisplayName:      req.DisplayName,
		IssuerURL:        req.IssuerURL,
		AuthorizeURL:     req.AuthorizeURL,
		TokenURL:         req.TokenURL,
		UserInfoURL:      req.UserInfoURL,
		ClientID:         req.ClientID,
		ClientSecretRef:  req.ClientSecretRef,
		Scopes:           req.Scopes,
		AutoLinkByEmail:  req.AutoLinkByEmail,
		SubjectField:     req.SubjectField,
		LoginField:       req.LoginField,
		EmailField:       req.EmailField,
		DisplayNameField: req.DisplayNameField,
		AvatarURLField:   req.AvatarURLField,
		ProfileURLField:  req.ProfileURLField,
		Metadata:         req.Metadata,
	})
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}

	scopesRaw, err := marshalJSONArray(provider.Scopes)
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	metadataRaw, err := marshalJSONObject(provider.Metadata)
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.auth_third_party_providers (
				name,
				type,
				status,
				display_name,
				issuer_url,
				authorize_url,
				token_url,
				userinfo_url,
				client_id,
				client_secret_ref,
				scopes,
				auto_link_by_email,
				subject_field,
				login_field,
				email_field,
				display_name_field,
				avatar_url_field,
				profile_url_field,
				metadata
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,$19::jsonb
			)
			ON CONFLICT (name)
			DO UPDATE SET
				type = EXCLUDED.type,
				status = EXCLUDED.status,
				display_name = EXCLUDED.display_name,
				issuer_url = EXCLUDED.issuer_url,
				authorize_url = EXCLUDED.authorize_url,
				token_url = EXCLUDED.token_url,
				userinfo_url = EXCLUDED.userinfo_url,
				client_id = EXCLUDED.client_id,
				client_secret_ref = EXCLUDED.client_secret_ref,
				scopes = EXCLUDED.scopes,
				auto_link_by_email = EXCLUDED.auto_link_by_email,
				subject_field = EXCLUDED.subject_field,
				login_field = EXCLUDED.login_field,
				email_field = EXCLUDED.email_field,
				display_name_field = EXCLUDED.display_name_field,
				avatar_url_field = EXCLUDED.avatar_url_field,
				profile_url_field = EXCLUDED.profile_url_field,
				metadata = EXCLUDED.metadata,
				updated_at = NOW()
			RETURNING
				id,
				name,
				type,
				status,
				display_name,
				issuer_url,
				authorize_url,
				token_url,
				userinfo_url,
				client_id,
				client_secret_ref,
				scopes,
				auto_link_by_email,
				subject_field,
				login_field,
				email_field,
				display_name_field,
				avatar_url_field,
				profile_url_field,
				metadata,
				created_at,
				updated_at
		`,
		provider.Name,
		provider.Type,
		provider.Status,
		provider.DisplayName,
		provider.IssuerURL,
		provider.AuthorizeURL,
		provider.TokenURL,
		provider.UserInfoURL,
		provider.ClientID,
		provider.ClientSecretRef,
		scopesRaw,
		provider.AutoLinkByEmail,
		provider.SubjectField,
		provider.LoginField,
		provider.EmailField,
		provider.DisplayNameField,
		provider.AvatarURLField,
		provider.ProfileURLField,
		metadataRaw,
	)
	return scanThirdPartyAuthProvider(row)
}

// GetThirdPartyAuthProvider resolves one provider by name.
func GetThirdPartyAuthProvider(
	ctx context.Context,
	db *sql.DB,
	req model.GetThirdPartyAuthProviderRequest,
) (model.ThirdPartyAuthProvider, error) {
	name := normalizeThirdPartyAuthProviderName(req.Name)
	if name == "" {
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider name is required")
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				name,
				type,
				status,
				display_name,
				issuer_url,
				authorize_url,
				token_url,
				userinfo_url,
				client_id,
				client_secret_ref,
				scopes,
				auto_link_by_email,
				subject_field,
				login_field,
				email_field,
				display_name_field,
				avatar_url_field,
				profile_url_field,
				metadata,
				created_at,
				updated_at
			FROM public.auth_third_party_providers
			WHERE name = $1
		`,
		name,
	)
	provider, err := scanThirdPartyAuthProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ThirdPartyAuthProvider{}, ErrThirdPartyAuthProviderNotFound
		}
		return model.ThirdPartyAuthProvider{}, err
	}
	return provider, nil
}

// ListThirdPartyAuthProviders returns providers matching the requested filters.
func ListThirdPartyAuthProviders(
	ctx context.Context,
	db *sql.DB,
	req model.ListThirdPartyAuthProvidersRequest,
) ([]model.ThirdPartyAuthProvider, error) {
	query := `
		SELECT
			id,
			name,
			type,
			status,
			display_name,
			issuer_url,
			authorize_url,
			token_url,
			userinfo_url,
			client_id,
			client_secret_ref,
			scopes,
			auto_link_by_email,
			subject_field,
			login_field,
			email_field,
			display_name_field,
			avatar_url_field,
			profile_url_field,
			metadata,
			created_at,
			updated_at
		FROM public.auth_third_party_providers
	`
	var (
		args    []any
		clauses []string
	)
	if value := normalizeThirdPartyAuthProviderType(req.Type); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("type = $%d", len(args)))
	}
	if value := normalizeThirdPartyAuthProviderStatus(req.Status); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY name"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]model.ThirdPartyAuthProvider, 0)
	for rows.Next() {
		item, err := scanThirdPartyAuthProvider(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// DeleteThirdPartyAuthProvider removes one provider by name.
func DeleteThirdPartyAuthProvider(
	ctx context.Context,
	db *sql.DB,
	req model.DeleteThirdPartyAuthProviderRequest,
) (model.ThirdPartyAuthProvider, error) {
	provider, err := GetThirdPartyAuthProvider(ctx, db, model.GetThirdPartyAuthProviderRequest(req))
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public.auth_third_party_providers WHERE id = $1`, provider.ID); err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	return provider, nil
}

func scanThirdPartyAuthProvider(row scanner) (model.ThirdPartyAuthProvider, error) {
	var (
		provider    model.ThirdPartyAuthProvider
		scopesRaw   []byte
		metadataRaw []byte
	)
	if err := row.Scan(
		&provider.ID,
		&provider.Name,
		&provider.Type,
		&provider.Status,
		&provider.DisplayName,
		&provider.IssuerURL,
		&provider.AuthorizeURL,
		&provider.TokenURL,
		&provider.UserInfoURL,
		&provider.ClientID,
		&provider.ClientSecretRef,
		&scopesRaw,
		&provider.AutoLinkByEmail,
		&provider.SubjectField,
		&provider.LoginField,
		&provider.EmailField,
		&provider.DisplayNameField,
		&provider.AvatarURLField,
		&provider.ProfileURLField,
		&metadataRaw,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	); err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	scopes, err := unmarshalStringArray(scopesRaw)
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	metadata, err := unmarshalJSONObject(metadataRaw)
	if err != nil {
		return model.ThirdPartyAuthProvider{}, err
	}
	provider.Scopes = scopes
	provider.Metadata = metadata
	return provider, nil
}

func normalizeThirdPartyAuthProvider(provider model.ThirdPartyAuthProvider) (model.ThirdPartyAuthProvider, error) {
	provider.Name = normalizeThirdPartyAuthProviderName(provider.Name)
	if provider.Name == "" {
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider name is required")
	}
	provider.Type = normalizeThirdPartyAuthProviderType(provider.Type)
	if provider.Type == "" {
		provider.Type = "oidc"
	}
	switch provider.Type {
	case "oidc", "github":
	default:
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider type %q is unsupported", provider.Type)
	}
	provider.Status = normalizeThirdPartyAuthProviderStatus(provider.Status)
	if provider.Status == "" {
		provider.Status = "active"
	}
	switch provider.Status {
	case "active", "disabled":
	default:
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider status %q is unsupported", provider.Status)
	}

	provider.DisplayName = strings.TrimSpace(provider.DisplayName)
	provider.IssuerURL = strings.TrimSpace(provider.IssuerURL)
	provider.AuthorizeURL = strings.TrimSpace(provider.AuthorizeURL)
	provider.TokenURL = strings.TrimSpace(provider.TokenURL)
	provider.UserInfoURL = strings.TrimSpace(provider.UserInfoURL)
	provider.ClientID = strings.TrimSpace(provider.ClientID)
	provider.ClientSecretRef = strings.TrimSpace(provider.ClientSecretRef)
	provider.SubjectField = strings.TrimSpace(provider.SubjectField)
	provider.LoginField = strings.TrimSpace(provider.LoginField)
	provider.EmailField = strings.TrimSpace(provider.EmailField)
	provider.DisplayNameField = strings.TrimSpace(provider.DisplayNameField)
	provider.AvatarURLField = strings.TrimSpace(provider.AvatarURLField)
	provider.ProfileURLField = strings.TrimSpace(provider.ProfileURLField)
	provider.Metadata = cloneJSONObject(provider.Metadata)

	switch provider.Type {
	case "github":
		if provider.DisplayName == "" {
			provider.DisplayName = "GitHub"
		}
		if provider.AuthorizeURL == "" {
			provider.AuthorizeURL = "https://github.com/login/oauth/authorize"
		}
		if provider.TokenURL == "" {
			provider.TokenURL = "https://github.com/login/oauth/access_token"
		}
		if provider.UserInfoURL == "" {
			provider.UserInfoURL = "https://api.github.com/user"
		}
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"read:user", "user:email"}
		}
		if provider.SubjectField == "" {
			provider.SubjectField = "id"
		}
		if provider.LoginField == "" {
			provider.LoginField = "login"
		}
		if provider.EmailField == "" {
			provider.EmailField = "email"
		}
		if provider.DisplayNameField == "" {
			provider.DisplayNameField = "name"
		}
		if provider.AvatarURLField == "" {
			provider.AvatarURLField = "avatar_url"
		}
		if provider.ProfileURLField == "" {
			provider.ProfileURLField = "html_url"
		}
	case "oidc":
		if provider.DisplayName == "" {
			provider.DisplayName = "OIDC"
		}
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"openid", "profile", "email"}
		}
		if provider.SubjectField == "" {
			provider.SubjectField = "sub"
		}
		if provider.LoginField == "" {
			provider.LoginField = "preferred_username"
		}
		if provider.EmailField == "" {
			provider.EmailField = "email"
		}
		if provider.DisplayNameField == "" {
			provider.DisplayNameField = "name"
		}
		if provider.AvatarURLField == "" {
			provider.AvatarURLField = "picture"
		}
		if provider.ProfileURLField == "" {
			provider.ProfileURLField = "profile"
		}
	}

	if provider.ClientID == "" {
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider client_id is required")
	}
	if provider.ClientSecretRef == "" {
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("third-party auth provider client_secret_ref is required")
	}
	if provider.Type == "oidc" {
		if provider.IssuerURL == "" && (provider.AuthorizeURL == "" || provider.TokenURL == "" || provider.UserInfoURL == "") {
			return model.ThirdPartyAuthProvider{}, fmt.Errorf("oidc provider requires issuer_url or explicit authorize_url, token_url, and userinfo_url")
		}
	}
	if provider.Type == "github" && (provider.AuthorizeURL == "" || provider.TokenURL == "" || provider.UserInfoURL == "") {
		return model.ThirdPartyAuthProvider{}, fmt.Errorf("github provider requires authorize_url, token_url, and userinfo_url")
	}
	return provider, nil
}

func normalizeThirdPartyAuthProviderName(value string) string {
	return normalizeSlug(value)
}

func normalizeThirdPartyAuthProviderType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeThirdPartyAuthProviderStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
