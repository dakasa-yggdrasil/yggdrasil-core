package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"golang.org/x/crypto/bcrypt"
)

const (
	testConfidentialClientID = "tartaro"
	testRedirectURI          = "https://tartaro.example.test/tartaro/auth/oidc/callback"
	testPostLogoutURI        = "https://tartaro.example.test/login"
	testBackchannelURI       = "https://tartaro.example.test/tartaro/oidc/back-channel-logout"
)

func validConfidentialClientDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("test-only-confidential-client-secret"), 12)
	if err != nil {
		t.Fatalf("generate bcrypt hash: %v", err)
	}
	document := configuredConfidentialClientsFile{
		Version: configuredConfidentialClientsFileVersion,
		Clients: []configuredConfidentialClient{{
			ClientID:                testConfidentialClientID,
			ClientType:              "confidential",
			ClientSecretHash:        string(hash),
			TokenEndpointAuthMethod: "client_secret_basic",
			RedirectURIs:            []string{testRedirectURI},
			PostLogoutRedirectURIs:  []string{testPostLogoutURI},
			Scopes:                  []string{"roles", "openid", "email", "profile"},
			GrantTypes:              []string{"refresh_token", "authorization_code"},
			PKCERequired:            true,
			PKCECodeChallengeMethod: "S256",
			BackchannelLogoutURI:    testBackchannelURI,
		}},
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return payload, string(hash)
}

func writeReadOnlyConfidentialClientFile(t *testing.T, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, payload, 0o400); err != nil {
		t.Fatalf("write client file: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod client file: %v", err)
	}
	return path
}

func TestParseConfiguredConfidentialClientsAcceptsStrictContract(t *testing.T) {
	payload, hash := validConfidentialClientDocument(t)
	clients, err := parseConfiguredConfidentialClients(payload)
	if err != nil {
		t.Fatalf("parse configured confidential clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("client count = %d, want 1", len(clients))
	}
	client := clients[0]
	if client.ClientID != testConfidentialClientID || client.ClientSecretHash != hash || !client.PKCERequired {
		t.Fatalf("unexpected client: %#v", client)
	}
	if got := client.Scopes; len(got) != 4 || got[0] != "email" || got[3] != "roles" {
		t.Fatalf("scopes were not canonicalized: %#v", got)
	}
	if got := client.GrantTypes; len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
		t.Fatalf("grants were not canonicalized: %#v", got)
	}
}

func TestParseConfiguredConfidentialClientsFailsClosed(t *testing.T) {
	payload, _ := validConfidentialClientDocument(t)
	var base map[string]any
	if err := json.Unmarshal(payload, &base); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "plaintext secret field",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["client_secret"] = "must-never-be-accepted"
			},
			want: "unknown field",
		},
		{
			name: "weak bcrypt cost",
			mutate: func(document map[string]any) {
				client := document["clients"].([]any)[0].(map[string]any)
				weak, err := bcrypt.GenerateFromPassword([]byte("test-secret"), 10)
				if err != nil {
					t.Fatal(err)
				}
				client["client_secret_hash"] = string(weak)
			},
			want: "cost of at least 12",
		},
		{
			name: "non bcrypt hash",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["client_secret_hash"] = "sha256:not-bcrypt"
			},
			want: "valid bcrypt hash",
		},
		{
			name: "non https redirect",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["redirect_uris"] = []any{"http://127.0.0.1/callback"}
			},
			want: "invalid HTTPS URI",
		},
		{
			name: "wrong auth method",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["token_endpoint_auth_method"] = "client_secret_post"
			},
			want: "client_secret_basic",
		},
		{
			name: "pkce disabled",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["pkce_required"] = false
			},
			want: "pkce_required must be true",
		},
		{
			name: "plain pkce",
			mutate: func(document map[string]any) {
				document["clients"].([]any)[0].(map[string]any)["pkce_code_challenge_method"] = "plain"
			},
			want: "must be \"S256\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var document map[string]any
			encoded, _ := json.Marshal(base)
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			tc.mutate(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseConfiguredConfidentialClients(mutated)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "must-never-be-accepted") {
				t.Fatal("validation error exposed plaintext secret material")
			}
		})
	}
}

func TestReadConfiguredConfidentialClientsRequiresReadOnlyFile(t *testing.T) {
	payload, _ := validConfidentialClientDocument(t)
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfiguredConfidentialClientsFile(path); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only file error, got %v", err)
	}
}

func TestEnsureConfiguredConfidentialClientsReconcilesIdempotentlyAndVerifiesAtomically(t *testing.T) {
	payload, hash := validConfidentialClientDocument(t)
	path := writeReadOnlyConfidentialClientFile(t, payload)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for attempt := 0; attempt < 2; attempt++ {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO oidc_clients").
			WithArgs(
				testConfidentialClientID,
				hash,
				sqlmock.AnyArg(),
				sqlmock.AnyArg(),
				sqlmock.AnyArg(),
				sqlmock.AnyArg(),
				true,
				testBackchannelURI,
				nil,
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT client_id, client_secret_hash").
			WithArgs(testConfidentialClientID).
			WillReturnRows(sqlmock.NewRows([]string{
				"client_id", "client_secret_hash", "redirect_uris", "post_logout_redirect_uris",
				"scopes", "grant_types", "pkce_required", "backchannel_logout_uri",
				"access_token_lifetime_seconds", "created_at",
			}).AddRow(
				testConfidentialClientID,
				hash,
				"{"+testRedirectURI+"}",
				"{"+testPostLogoutURI+"}",
				"{email,openid,profile,roles}",
				"{authorization_code,refresh_token}",
				true,
				testBackchannelURI,
				nil,
				time.Now().UTC(),
			))
		mock.ExpectCommit()
	}

	var result ConfiguredConfidentialClientsResult
	for attempt := 0; attempt < 2; attempt++ {
		result, err = EnsureConfiguredConfidentialClientsFromFile(context.Background(), db, path)
		if err != nil {
			t.Fatalf("ensure configured confidential clients attempt %d: %v", attempt+1, err)
		}
	}
	if len(result.ClientIDs) != 1 || result.ClientIDs[0] != testConfidentialClientID {
		t.Fatalf("unexpected safe result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureConfiguredConfidentialClientsRollsBackOnReadbackDrift(t *testing.T) {
	payload, hash := validConfidentialClientDocument(t)
	path := writeReadOnlyConfidentialClientFile(t, payload)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO oidc_clients").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT client_id, client_secret_hash").
		WithArgs(testConfidentialClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id", "client_secret_hash", "redirect_uris", "post_logout_redirect_uris",
			"scopes", "grant_types", "pkce_required", "backchannel_logout_uri",
			"access_token_lifetime_seconds", "created_at",
		}).AddRow(
			testConfidentialClientID,
			hash,
			"{https://wrong.example.test/callback}",
			"{"+testPostLogoutURI+"}",
			"{email,openid,profile,roles}",
			"{authorization_code,refresh_token}",
			true,
			testBackchannelURI,
			nil,
			time.Now().UTC(),
		))
	mock.ExpectRollback()

	_, err = EnsureConfiguredConfidentialClientsFromFile(context.Background(), db, path)
	if err == nil || !strings.Contains(err.Error(), "stored contract differs") {
		t.Fatalf("expected readback drift error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureConfiguredConfidentialClientsRedactsDatabaseErrors(t *testing.T) {
	payload, hash := validConfidentialClientDocument(t)
	path := writeReadOnlyConfidentialClientFile(t, payload)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO oidc_clients").WillReturnError(errors.New("rejected row containing " + hash))
	mock.ExpectRollback()

	_, err = EnsureConfiguredConfidentialClientsFromFile(context.Background(), db, path)
	if err == nil || !strings.Contains(err.Error(), "database write failed") {
		t.Fatalf("expected redacted database error, got %v", err)
	}
	if strings.Contains(err.Error(), hash) {
		t.Fatal("database error exposed the bcrypt verifier")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyConfiguredConfidentialClientsIsReadOnlyAndExact(t *testing.T) {
	payload, hash := validConfidentialClientDocument(t)
	path := writeReadOnlyConfidentialClientFile(t, payload)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT client_id, client_secret_hash").
		WithArgs(testConfidentialClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id", "client_secret_hash", "redirect_uris", "post_logout_redirect_uris",
			"scopes", "grant_types", "pkce_required", "backchannel_logout_uri",
			"access_token_lifetime_seconds", "created_at",
		}).AddRow(
			testConfidentialClientID,
			hash,
			"{"+testRedirectURI+"}",
			"{"+testPostLogoutURI+"}",
			"{email,openid,profile,roles}",
			"{authorization_code,refresh_token}",
			true,
			testBackchannelURI,
			nil,
			time.Now().UTC(),
		))
	mock.ExpectCommit()

	result, err := VerifyConfiguredConfidentialClientsFromFile(context.Background(), db, path)
	if err != nil {
		t.Fatalf("verify configured confidential clients: %v", err)
	}
	if len(result.ClientIDs) != 1 || result.ClientIDs[0] != testConfidentialClientID {
		t.Fatalf("unexpected safe verification result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
