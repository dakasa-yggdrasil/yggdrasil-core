package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const maxConfiguredPublicClients = 32

var publicClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type configuredPublicClient struct {
	ClientID                   string   `json:"client_id"`
	RedirectURIs               []string `json:"redirect_uris"`
	PostLogoutRedirectURIs     []string `json:"post_logout_redirect_uris,omitempty"`
	Scopes                     []string `json:"scopes"`
	GrantTypes                 []string `json:"grant_types"`
	PKCERequired               bool     `json:"pkce_required"`
	AccessTokenLifetimeSeconds *int     `json:"access_token_lifetime_seconds,omitempty"`
}

// EnsureConfiguredPublicClients validates and applies the complete declarative
// public-client set from YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON. It is deliberately
// limited to PKCE-only clients with exact HTTPS or loopback redirect URIs.
func EnsureConfiguredPublicClients(ctx context.Context, db *sql.DB, raw string) error {
	clients, err := parseConfiguredPublicClients(raw)
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin public oidc client configuration: %w", err)
	}
	defer tx.Rollback()
	for _, client := range clients {
		if err := repository.UpsertOIDCPublicClient(ctx, tx, client); err != nil {
			return fmt.Errorf("configure public oidc client %q: %w", client.ClientID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit public oidc client configuration: %w", err)
	}
	return nil
}

func parseConfiguredPublicClients(raw string) ([]model.OIDCClient, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var configured []configuredPublicClient
	if err := decoder.Decode(&configured); err != nil {
		return nil, fmt.Errorf("decode YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, fmt.Errorf("decode YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON: %w", err)
	}
	if len(configured) > maxConfiguredPublicClients {
		return nil, fmt.Errorf("YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON contains %d clients; maximum is %d", len(configured), maxConfiguredPublicClients)
	}

	seen := map[string]struct{}{}
	clients := make([]model.OIDCClient, 0, len(configured))
	for index, input := range configured {
		client, err := validateConfiguredPublicClient(input)
		if err != nil {
			return nil, fmt.Errorf("public oidc client at index %d: %w", index, err)
		}
		if _, duplicate := seen[client.ClientID]; duplicate {
			return nil, fmt.Errorf("duplicate public oidc client id %q", client.ClientID)
		}
		seen[client.ClientID] = struct{}{}
		clients = append(clients, client)
	}
	return clients, nil
}

func validateConfiguredPublicClient(input configuredPublicClient) (model.OIDCClient, error) {
	clientID := strings.TrimSpace(input.ClientID)
	if !publicClientIDPattern.MatchString(clientID) {
		return model.OIDCClient{}, fmt.Errorf("client_id %q is invalid", clientID)
	}
	redirects, err := validateRedirectURIs("redirect_uris", input.RedirectURIs, true)
	if err != nil {
		return model.OIDCClient{}, err
	}
	postLogout, err := validateRedirectURIs("post_logout_redirect_uris", input.PostLogoutRedirectURIs, false)
	if err != nil {
		return model.OIDCClient{}, err
	}
	if !input.PKCERequired {
		return model.OIDCClient{}, fmt.Errorf("pkce_required must be true for a public client")
	}
	scopes, err := validateAllowlist("scopes", input.Scopes, []string{"openid", "email", "profile", "roles"}, "openid")
	if err != nil {
		return model.OIDCClient{}, err
	}
	grants, err := validateAllowlist("grant_types", input.GrantTypes, []string{"authorization_code", "refresh_token"}, "authorization_code")
	if err != nil {
		return model.OIDCClient{}, err
	}
	if ttl := input.AccessTokenLifetimeSeconds; ttl != nil && (*ttl < 60 || *ttl > 86400) {
		return model.OIDCClient{}, fmt.Errorf("access_token_lifetime_seconds must be between 60 and 86400")
	}
	return model.OIDCClient{
		ClientID:                   clientID,
		RedirectURIs:               redirects,
		PostLogoutRedirectURIs:     postLogout,
		Scopes:                     scopes,
		GrantTypes:                 grants,
		PKCERequired:               true,
		AccessTokenLifetimeSeconds: input.AccessTokenLifetimeSeconds,
	}, nil
}

func validateRedirectURIs(field string, values []string, required bool) ([]string, error) {
	values = uniqueSorted(values)
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	if len(values) > 16 {
		return nil, fmt.Errorf("%s contains too many values", field)
	}
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("%s contains invalid URI %q", field, value)
		}
		if parsed.Scheme == "https" {
			continue
		}
		host := parsed.Hostname()
		if parsed.Scheme != "http" || !isLoopbackHost(host) {
			return nil, fmt.Errorf("%s URI %q must use HTTPS or an HTTP loopback host", field, value)
		}
	}
	return values, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateAllowlist(field string, values, allowed []string, required string) ([]string, error) {
	values = uniqueSorted(values)
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedSet[value] = struct{}{}
	}
	foundRequired := false
	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return nil, fmt.Errorf("%s contains unsupported value %q", field, value)
		}
		foundRequired = foundRequired || value == required
	}
	if !foundRequired {
		return nil, fmt.Errorf("%s must contain %q", field, required)
	}
	return values, nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return err
}
