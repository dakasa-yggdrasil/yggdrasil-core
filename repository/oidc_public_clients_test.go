package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestUpsertOIDCPublicClientUpdatesOnlyPublicRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("INSERT INTO oidc_clients").
		WithArgs("dakasa-cli", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), true, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpsertOIDCPublicClient(context.Background(), db, model.OIDCClient{
		ClientID:         "dakasa-cli",
		RedirectURIs:     []string{"http://127.0.0.1:47819/callback"},
		Scopes:           []string{"openid"},
		GrantTypes:       []string{"authorization_code"},
		PKCERequired:     true,
		ClientSecretHash: "",
	})
	if err != nil {
		t.Fatalf("upsert public client: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertOIDCPublicClientRefusesConfidentialConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("INSERT INTO oidc_clients").WillReturnResult(sqlmock.NewResult(0, 0))

	err = UpsertOIDCPublicClient(context.Background(), db, model.OIDCClient{ClientID: "existing", PKCERequired: true})
	if !errors.Is(err, ErrOIDCClientTypeConflict) {
		t.Fatalf("expected confidential client conflict, got %v", err)
	}
}

func TestUpsertOIDCPublicClientRejectsSecret(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = UpsertOIDCPublicClient(context.Background(), db, model.OIDCClient{ClientID: "bad", ClientSecretHash: "secret"})
	if err == nil {
		t.Fatal("expected public client secret rejection")
	}
}
