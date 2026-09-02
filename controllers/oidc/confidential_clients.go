package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"golang.org/x/crypto/bcrypt"
)

const (
	configuredConfidentialClientsFileVersion  = 1
	maxConfiguredConfidentialClients          = 32
	maxConfiguredConfidentialClientsFileBytes = 256 * 1024
	minimumConfiguredClientBcryptCost         = 12
)

// ConfiguredConfidentialClientsResult is deliberately safe to expose in a
// workflow result. It contains only public client identifiers; the bcrypt hash
// is never returned, logged, emitted, or copied into a workflow input.
type ConfiguredConfidentialClientsResult struct {
	ClientIDs []string
}

type configuredConfidentialClientsFile struct {
	Version int                            `json:"version"`
	Clients []configuredConfidentialClient `json:"clients"`
}

type configuredConfidentialClient struct {
	ClientID                   string   `json:"client_id"`
	ClientType                 string   `json:"client_type"`
	ClientSecretHash           string   `json:"client_secret_hash"`
	TokenEndpointAuthMethod    string   `json:"token_endpoint_auth_method"`
	RedirectURIs               []string `json:"redirect_uris"`
	PostLogoutRedirectURIs     []string `json:"post_logout_redirect_uris"`
	Scopes                     []string `json:"scopes"`
	GrantTypes                 []string `json:"grant_types"`
	PKCERequired               bool     `json:"pkce_required"`
	PKCECodeChallengeMethod    string   `json:"pkce_code_challenge_method"`
	BackchannelLogoutURI       string   `json:"backchannel_logout_uri,omitempty"`
	AccessTokenLifetimeSeconds *int     `json:"access_token_lifetime_seconds,omitempty"`
}

// EnsureConfiguredConfidentialClientsFromFile atomically reconciles the exact
// confidential OIDC client set held in a read-only mounted Secret file.
//
// The file carries bcrypt hashes, never plaintext client secrets. Callers must
// pass the mounted file path from process configuration; there is deliberately
// no environment-value or workflow-input fallback. Every row is read back in
// the same transaction and compared to the validated document before commit.
func EnsureConfiguredConfidentialClientsFromFile(
	ctx context.Context,
	db *sql.DB,
	path string,
) (ConfiguredConfidentialClientsResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("confidential oidc client file path is required")
	}
	clients, err := readConfiguredConfidentialClientsFile(path)
	if err != nil {
		return ConfiguredConfidentialClientsResult{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("begin confidential oidc client reconciliation: %w", err)
	}
	defer tx.Rollback()

	clientIDs := make([]string, 0, len(clients))
	for _, client := range clients {
		if err := repository.UpsertOIDCClient(ctx, tx, client); err != nil {
			// Database errors can carry driver-specific row details. Never let a
			// reusable bcrypt verifier cross the startup/workflow error boundary.
			return ConfiguredConfidentialClientsResult{}, fmt.Errorf("reconcile confidential oidc client %q: database write failed", client.ClientID)
		}
		observed, err := repository.GetOIDCClientByID(ctx, tx, client.ClientID)
		if err != nil {
			return ConfiguredConfidentialClientsResult{}, fmt.Errorf("verify confidential oidc client %q: database read failed", client.ClientID)
		}
		if !sameConfiguredOIDCClient(client, observed) {
			return ConfiguredConfidentialClientsResult{}, fmt.Errorf("verify confidential oidc client %q: stored contract differs from mounted configuration", client.ClientID)
		}
		clientIDs = append(clientIDs, client.ClientID)
	}
	if err := tx.Commit(); err != nil {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("commit confidential oidc client reconciliation: %w", err)
	}
	sort.Strings(clientIDs)
	return ConfiguredConfidentialClientsResult{ClientIDs: clientIDs}, nil
}

// VerifyConfiguredConfidentialClientsFromFile is the read-only counterpart to
// startup reconciliation. It proves that every mounted client exactly matches
// the persisted contract in one repeatable-read transaction.
func VerifyConfiguredConfidentialClientsFromFile(
	ctx context.Context,
	db *sql.DB,
	path string,
) (ConfiguredConfidentialClientsResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("confidential oidc client file path is required")
	}
	clients, err := readConfiguredConfidentialClientsFile(path)
	if err != nil {
		return ConfiguredConfidentialClientsResult{}, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("begin confidential oidc client verification: %w", err)
	}
	defer tx.Rollback()
	clientIDs := make([]string, 0, len(clients))
	for _, client := range clients {
		observed, err := repository.GetOIDCClientByID(ctx, tx, client.ClientID)
		if err != nil {
			return ConfiguredConfidentialClientsResult{}, fmt.Errorf("verify confidential oidc client %q: database read failed", client.ClientID)
		}
		if !sameConfiguredOIDCClient(client, observed) {
			return ConfiguredConfidentialClientsResult{}, fmt.Errorf("verify confidential oidc client %q: stored contract differs from mounted configuration", client.ClientID)
		}
		clientIDs = append(clientIDs, client.ClientID)
	}
	if err := tx.Commit(); err != nil {
		return ConfiguredConfidentialClientsResult{}, fmt.Errorf("commit confidential oidc client verification: %w", err)
	}
	sort.Strings(clientIDs)
	return ConfiguredConfidentialClientsResult{ClientIDs: clientIDs}, nil
}

func readConfiguredConfidentialClientsFile(path string) ([]model.OIDCClient, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open confidential oidc client file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect confidential oidc client file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("confidential oidc client file must be a regular file")
	}
	if info.Mode().Perm()&0o222 != 0 {
		return nil, fmt.Errorf("confidential oidc client file must be mounted read-only")
	}
	limited := io.LimitReader(file, maxConfiguredConfidentialClientsFileBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read confidential oidc client file: %w", err)
	}
	if len(payload) > maxConfiguredConfidentialClientsFileBytes {
		return nil, fmt.Errorf("confidential oidc client file exceeds %d bytes", maxConfiguredConfidentialClientsFileBytes)
	}
	return parseConfiguredConfidentialClients(payload)
}

func parseConfiguredConfidentialClients(payload []byte) ([]model.OIDCClient, error) {
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var document configuredConfidentialClientsFile
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode confidential oidc client file: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, fmt.Errorf("decode confidential oidc client file: %w", err)
	}
	if document.Version != configuredConfidentialClientsFileVersion {
		return nil, fmt.Errorf("confidential oidc client file version must be %d", configuredConfidentialClientsFileVersion)
	}
	if len(document.Clients) == 0 {
		return nil, fmt.Errorf("confidential oidc client file must contain at least one client")
	}
	if len(document.Clients) > maxConfiguredConfidentialClients {
		return nil, fmt.Errorf("confidential oidc client file contains %d clients; maximum is %d", len(document.Clients), maxConfiguredConfidentialClients)
	}

	seen := make(map[string]struct{}, len(document.Clients))
	clients := make([]model.OIDCClient, 0, len(document.Clients))
	for index, input := range document.Clients {
		client, err := validateConfiguredConfidentialClient(input)
		if err != nil {
			return nil, fmt.Errorf("confidential oidc client at index %d: %w", index, err)
		}
		if _, duplicate := seen[client.ClientID]; duplicate {
			return nil, fmt.Errorf("duplicate confidential oidc client id %q", client.ClientID)
		}
		seen[client.ClientID] = struct{}{}
		clients = append(clients, client)
	}
	return clients, nil
}

func validateConfiguredConfidentialClient(input configuredConfidentialClient) (model.OIDCClient, error) {
	clientID := strings.TrimSpace(input.ClientID)
	if !publicClientIDPattern.MatchString(clientID) {
		return model.OIDCClient{}, fmt.Errorf("client_id %q is invalid", clientID)
	}
	if strings.TrimSpace(input.ClientType) != "confidential" {
		return model.OIDCClient{}, fmt.Errorf("client_type must be %q", "confidential")
	}
	if strings.TrimSpace(input.TokenEndpointAuthMethod) != "client_secret_basic" {
		return model.OIDCClient{}, fmt.Errorf("token_endpoint_auth_method must be %q", "client_secret_basic")
	}
	hash := strings.TrimSpace(input.ClientSecretHash)
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < minimumConfiguredClientBcryptCost {
		return model.OIDCClient{}, fmt.Errorf("client_secret_hash must be a valid bcrypt hash with cost of at least %d", minimumConfiguredClientBcryptCost)
	}
	redirects, err := validateHTTPSURIs("redirect_uris", input.RedirectURIs, true)
	if err != nil {
		return model.OIDCClient{}, err
	}
	postLogout, err := validateHTTPSURIs("post_logout_redirect_uris", input.PostLogoutRedirectURIs, true)
	if err != nil {
		return model.OIDCClient{}, err
	}
	scopes, err := validateAllowlist("scopes", input.Scopes, []string{"openid", "email", "profile", "roles"}, "openid")
	if err != nil {
		return model.OIDCClient{}, err
	}
	grants, err := validateAllowlist("grant_types", input.GrantTypes, []string{"authorization_code", "refresh_token"}, "authorization_code")
	if err != nil {
		return model.OIDCClient{}, err
	}
	if !input.PKCERequired {
		return model.OIDCClient{}, fmt.Errorf("pkce_required must be true")
	}
	if strings.TrimSpace(input.PKCECodeChallengeMethod) != "S256" {
		return model.OIDCClient{}, fmt.Errorf("pkce_code_challenge_method must be %q", "S256")
	}
	backchannel := strings.TrimSpace(input.BackchannelLogoutURI)
	if backchannel != "" {
		validated, err := validateHTTPSURIs("backchannel_logout_uri", []string{backchannel}, true)
		if err != nil {
			return model.OIDCClient{}, err
		}
		backchannel = validated[0]
	}
	if ttl := input.AccessTokenLifetimeSeconds; ttl != nil && (*ttl < 60 || *ttl > 86400) {
		return model.OIDCClient{}, fmt.Errorf("access_token_lifetime_seconds must be between 60 and 86400")
	}
	return model.OIDCClient{
		ClientID:                   clientID,
		ClientSecretHash:           hash,
		RedirectURIs:               redirects,
		PostLogoutRedirectURIs:     postLogout,
		Scopes:                     scopes,
		GrantTypes:                 grants,
		PKCERequired:               true,
		BackchannelLogoutURI:       backchannel,
		AccessTokenLifetimeSeconds: input.AccessTokenLifetimeSeconds,
	}, nil
}

func validateHTTPSURIs(field string, values []string, required bool) ([]string, error) {
	values = uniqueSorted(values)
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	if len(values) > 16 {
		return nil, fmt.Errorf("%s contains too many values", field)
	}
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("%s contains invalid HTTPS URI %q", field, value)
		}
	}
	return values, nil
}

func sameConfiguredOIDCClient(want, got model.OIDCClient) bool {
	return want.ClientID == got.ClientID &&
		want.ClientSecretHash == got.ClientSecretHash &&
		slices.Equal(want.RedirectURIs, got.RedirectURIs) &&
		slices.Equal(want.PostLogoutRedirectURIs, got.PostLogoutRedirectURIs) &&
		slices.Equal(want.Scopes, got.Scopes) &&
		slices.Equal(want.GrantTypes, got.GrantTypes) &&
		want.PKCERequired == got.PKCERequired &&
		want.BackchannelLogoutURI == got.BackchannelLogoutURI &&
		equalOptionalInt(want.AccessTokenLifetimeSeconds, got.AccessTokenLifetimeSeconds)
}

func equalOptionalInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
