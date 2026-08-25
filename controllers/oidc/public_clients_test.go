package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestParseConfiguredPublicClientsAcceptsPKCELoopbackClient(t *testing.T) {
	raw := `[{
		"client_id":"dakasa-cli",
		"redirect_uris":["http://127.0.0.1:47819/callback"],
		"scopes":["roles","openid","email","profile"],
		"grant_types":["refresh_token","authorization_code"],
		"pkce_required":true,
		"access_token_lifetime_seconds":900
	}]`
	clients, err := parseConfiguredPublicClients(raw)
	if err != nil {
		t.Fatalf("parse configured clients: %v", err)
	}
	if len(clients) != 1 || clients[0].ClientID != "dakasa-cli" || clients[0].ClientSecretHash != "" || !clients[0].PKCERequired {
		t.Fatalf("unexpected public client: %#v", clients)
	}
	if got := clients[0].Scopes; len(got) != 4 || got[0] != "email" || got[3] != "roles" {
		t.Fatalf("expected canonical scope ordering, got %#v", got)
	}
}

func TestParseConfiguredPublicClientsFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "unknown field",
			raw:  `[{"client_id":"cli","redirect_uris":["http://127.0.0.1/cb"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true,"secret":"bad"}]`,
			want: "unknown field",
		},
		{
			name: "public client without pkce",
			raw:  `[{"client_id":"cli","redirect_uris":["http://127.0.0.1/cb"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":false}]`,
			want: "pkce_required must be true",
		},
		{
			name: "non loopback http redirect",
			raw:  `[{"client_id":"cli","redirect_uris":["http://example.com/cb"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true}]`,
			want: "HTTPS or an HTTP loopback host",
		},
		{
			name: "missing openid scope",
			raw:  `[{"client_id":"cli","redirect_uris":["https://example.com/cb"],"scopes":["email"],"grant_types":["authorization_code"],"pkce_required":true}]`,
			want: `must contain "openid"`,
		},
		{
			name: "duplicate id",
			raw:  `[{"client_id":"cli","redirect_uris":["https://example.com/a"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true},{"client_id":"cli","redirect_uris":["https://example.com/b"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true}]`,
			want: "duplicate public oidc client id",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfiguredPublicClients(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestParseConfiguredPublicClientsBlankIsNoop(t *testing.T) {
	clients, err := parseConfiguredPublicClients("  ")
	if err != nil || len(clients) != 0 {
		t.Fatalf("blank config should be a no-op, got clients=%#v err=%v", clients, err)
	}
}

func TestEnsureConfiguredPublicClientsAppliesAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw := `[{"client_id":"dakasa-cli","redirect_uris":["http://127.0.0.1:47819/callback"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true}]`
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO oidc_clients").
		WithArgs("dakasa-cli", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, nil).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := EnsureConfiguredPublicClients(context.Background(), db, raw); err != nil {
		t.Fatalf("ensure configured public clients: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureConfiguredPublicClientsRollsBackOnConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw := `[
		{"client_id":"first-cli","redirect_uris":["http://127.0.0.1:47819/callback"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true},
		{"client_id":"second-cli","redirect_uris":["http://127.0.0.1:47820/callback"],"scopes":["openid"],"grant_types":["authorization_code"],"pkce_required":true}
	]`
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO oidc_clients").
		WithArgs("first-cli", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, nil).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO oidc_clients").
		WithArgs("second-cli", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, nil).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = EnsureConfiguredPublicClients(context.Background(), db, raw)
	if err == nil || !strings.Contains(err.Error(), "confidential client") {
		t.Fatalf("expected fail-closed client conflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
