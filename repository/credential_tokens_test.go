package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestCredentialTokenLifecycle exercises the full single-use token lifecycle:
// issue, consume, double-consume guard, and InvalidatePrior.
func TestCredentialTokenLifecycle(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()
	cleanCredentialsFixtures(t, db)
	defer cleanCredentialsFixtures(t, db)

	// 1. Seed collaborator.
	collaboratorID := seedCredentialsCollaborator(t, db, "bob")

	// 2. Generate a raw token and hash.
	gen, err := password.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// 3. Issue token (purpose=setup, expires +48h, CreatedBy=nil).
	issued, err := IssueCredentialToken(ctx, db, IssueCredentialTokenInput{
		CollaboratorID: collaboratorID,
		Purpose:        model.CredentialTokenPurposeSetup,
		TokenHash:      gen.Hash,
		ExpiresAt:      time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("IssueCredentialToken: %v", err)
	}
	if issued.ConsumedAt != nil {
		t.Error("expected ConsumedAt to be nil on freshly issued token")
	}
	if issued.CollaboratorID != collaboratorID.String() {
		t.Errorf("collaborator_id mismatch: want %s, got %s", collaboratorID, issued.CollaboratorID)
	}
	if issued.Purpose != model.CredentialTokenPurposeSetup {
		t.Errorf("purpose mismatch: want %s, got %s", model.CredentialTokenPurposeSetup, issued.Purpose)
	}

	// 4. Consume the token — assert collaborator_id matches.
	consumed, err := ConsumeCredentialToken(ctx, db, ConsumeCredentialTokenInput{
		TokenHash: gen.Hash,
		Purpose:   model.CredentialTokenPurposeSetup,
	})
	if err != nil {
		t.Fatalf("ConsumeCredentialToken (first): %v", err)
	}
	if consumed.CollaboratorID != collaboratorID.String() {
		t.Errorf("consumed collaborator_id mismatch: want %s, got %s", collaboratorID, consumed.CollaboratorID)
	}
	if consumed.ConsumedAt == nil {
		t.Error("expected ConsumedAt to be set after consume")
	}

	// 5. Second consume must return ErrCredentialTokenInvalid.
	_, err = ConsumeCredentialToken(ctx, db, ConsumeCredentialTokenInput{
		TokenHash: gen.Hash,
		Purpose:   model.CredentialTokenPurposeSetup,
	})
	if err == nil {
		t.Fatal("second consume: expected ErrCredentialTokenInvalid, got nil")
	}
	if err != ErrCredentialTokenInvalid {
		t.Errorf("second consume: expected ErrCredentialTokenInvalid, got %v", err)
	}

	// 6. Issue another token without InvalidatePrior, then another with
	//    InvalidatePrior=true. Only one active token should remain.
	gen2, err := password.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken gen2: %v", err)
	}
	if _, err := IssueCredentialToken(ctx, db, IssueCredentialTokenInput{
		CollaboratorID: collaboratorID,
		Purpose:        model.CredentialTokenPurposeSetup,
		TokenHash:      gen2.Hash,
		ExpiresAt:      time.Now().Add(48 * time.Hour),
	}); err != nil {
		t.Fatalf("IssueCredentialToken gen2: %v", err)
	}

	gen3, err := password.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken gen3: %v", err)
	}
	if _, err := IssueCredentialToken(ctx, db, IssueCredentialTokenInput{
		CollaboratorID:  collaboratorID,
		Purpose:         model.CredentialTokenPurposeSetup,
		TokenHash:       gen3.Hash,
		ExpiresAt:       time.Now().Add(48 * time.Hour),
		InvalidatePrior: true,
	}); err != nil {
		t.Fatalf("IssueCredentialToken gen3 (InvalidatePrior): %v", err)
	}

	// Exactly one active token should remain.
	var activeCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_credential_tokens
		WHERE collaborator_id = $1 AND purpose = $2 AND consumed_at IS NULL
	`, collaboratorID, model.CredentialTokenPurposeSetup).Scan(&activeCount); err != nil {
		t.Fatalf("count active tokens: %v", err)
	}
	if activeCount != 1 {
		t.Errorf("expected exactly 1 active token after InvalidatePrior, got %d", activeCount)
	}
}

// ctx is a package-level background context for convenience in tests.
var ctx = context.Background()
