package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func contactProofSessionFixture(t *testing.T, db *sql.DB, channel string) (model.Collaborator, model.AuthSession, string) {
	t.Helper()
	c, _ := contactOTPFixture(t, db)
	plain := "recent-contact-session-fixture-password"
	hash, err := coreauth.HashPassword(plain)
	if err != nil {
		t.Fatal("recent proof password fixture generation failed")
	}
	if _, err := db.Exec(`UPDATE public.auth_identities SET password_hash=$2,password_scheme='pbkdf2_sha256',mfa_enrolled_at=NULL WHERE collaborator_id=$1`, c.ID, hash); err != nil {
		t.Fatal("recent proof password fixture failed")
	}
	if channel == "sms" {
		contactOTPSetPhone(t, db, c.ID, "+12025550134")
	}
	binding := contactOTPBinding(t, db, c.ID, channel)
	authority := contactOTPLoginBinding(t, db, c.ID)
	token, code := contactOTPIssue(t, db, c.ID, channel, "login", authority, binding, true)
	req := model.LoginWithPasswordRequest{Identifier: c.PrimaryEmail, Password: plain}
	session, _, err := VerifyContactOTPAndCreateSession(context.Background(), db, c.ID, channel, authority, binding, token, code, req, time.Hour)
	if err != nil || session.ID == uuid.Nil {
		t.Fatal("recent proof authenticated session fixture failed")
	}
	return c, session, plain
}

func TestRecentContactSessionProofPostgres(t *testing.T) {
	db := contactOTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("AUTH_EMAIL_INTEGRATION", "mfa-tests/mail")
	t.Setenv("AUTH_SMS_INTEGRATION", "mfa-tests/text")
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	ctx := context.Background()

	t.Run("metadata_cannot_forge_proof", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		session, _, err := CreateAuthSession(ctx, db, c.ID, map[string]any{"recent_contact_mfa_verified": true, "contact_mfa_verified_at": time.Now().UTC().Format(time.RFC3339Nano)}, time.Hour)
		if err != nil {
			t.Fatal("forged metadata session fixture failed")
		}
		available, err := HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
		if err != nil || available {
			t.Fatal("user metadata forged recent contact MFA authority")
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("forged proof consumption fixture failed")
		}
		defer func() { _ = tx.Rollback() }()
		contactOTPRequireInvalid(t, ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, "fixture-password"))
	})

	t.Run("proof_is_atomic_and_password_mismatch_preserves_it", func(t *testing.T) {
		c, session, plain := contactProofSessionFixture(t, db, "email")
		available, err := HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
		if err != nil || !available {
			t.Fatal("contact OTP session did not atomically create a usable recent proof")
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("incorrect current password proof fixture failed")
		}
		if !errors.Is(ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, "incorrect-password"), ErrAuthInvalidCredentials) {
			_ = tx.Rollback()
			t.Fatal("recent proof omitted current-password verification under locks")
		}
		_ = tx.Rollback()
		available, err = HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
		if err != nil || !available {
			t.Fatal("incorrect password consumed the valid recent contact proof")
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil || ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, plain) != nil {
			if tx != nil {
				_ = tx.Rollback()
			}
			t.Fatal("valid recent proof could not authorize its password transaction")
		}
		_ = tx.Rollback()
		available, err = HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
		if err != nil || !available {
			t.Fatal("rolling back password mutation lost the recent contact proof")
		}
	})

	t.Run("context_and_lifetime_fail_closed", func(t *testing.T) {
		for _, scenario := range []string{"expired", "email_changed", "email_round_trip", "sms_changed", "password_changed", "revoked", "session_expired", "owner_suspended", "foreign_session"} {
			t.Run(scenario, func(t *testing.T) {
				channel := "email"
				if scenario == "sms_changed" {
					channel = "sms"
				}
				c, session, plain := contactProofSessionFixture(t, db, channel)
				var err error
				switch scenario {
				case "expired":
					_, err = db.Exec(`UPDATE public.auth_contact_session_proofs SET verified_at=clock_timestamp()-INTERVAL '6 minutes' WHERE session_id=$1`, session.ID)
				case "email_changed":
					_, err = db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, uuid.NewString()+"@example.test")
				case "email_round_trip":
					_, err = db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, uuid.NewString()+"@example.test")
					if err == nil {
						_, err = db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, c.PrimaryEmail)
					}
				case "sms_changed":
					contactOTPSetPhone(t, db, c.ID, "+12025550135")
				case "password_changed":
					_, err = db.Exec(`UPDATE public.auth_identities SET password_hash='replacement-password-fixture' WHERE collaborator_id=$1`, c.ID)
				case "revoked":
					_, err = db.Exec(`UPDATE public.auth_sessions SET status='revoked',revoked_at=clock_timestamp() WHERE id=$1`, session.ID)
				case "session_expired":
					_, err = db.Exec(`UPDATE public.auth_sessions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1`, session.ID)
				case "owner_suspended":
					_, err = db.Exec(`UPDATE public.collaborators SET status='suspended' WHERE id=$1`, c.ID)
				case "foreign_session":
					other, _ := contactOTPFixture(t, db)
					c.ID = other.ID
				}
				if err != nil {
					t.Fatal("recent proof invalidation fixture failed")
				}
				available, err := HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
				if err != nil || available {
					t.Fatal("stale or foreign proof remained available for password changes")
				}
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal("stale proof consumption fixture failed")
				}
				defer func() { _ = tx.Rollback() }()
				contactOTPRequireInvalid(t, ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, plain))
			})
		}
	})

	t.Run("password_change_and_revocation_commit_with_proof", func(t *testing.T) {
		c, session, plain := contactProofSessionFixture(t, db, "sms")
		hash, err := coreauth.HashPassword("changed-after-recent-proof-password")
		if err != nil {
			t.Fatal("password change credential fixture failed")
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("password change proof transaction fixture failed")
		}
		defer func() { _ = tx.Rollback() }()
		if ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, plain) != nil || SetPasswordHash(ctx, tx, c.ID, hash, "pbkdf2_sha256", time.Now().Add(24*time.Hour)) != nil {
			t.Fatal("proof and password replacement could not share a transaction")
		}
		if _, err := RevokeAllAuthSessions(ctx, tx, c.ID); err != nil || tx.Commit() != nil {
			t.Fatal("password replacement and session revocation did not commit with the proof")
		}
		var consumed bool
		if db.QueryRow(`SELECT consumed_at IS NOT NULL FROM public.auth_contact_session_proofs WHERE session_id=$1`, session.ID).Scan(&consumed) != nil || !consumed {
			t.Fatal("successful password change failed to consume recent contact proof")
		}
		available, err := HasRecentContactSessionProof(ctx, db, c.ID, session.ID)
		if err != nil || available {
			t.Fatal("password replacement left recent proof usable after revocation")
		}
	})

	t.Run("concurrent_proof_consumption_is_single_use", func(t *testing.T) {
		c, session, plain := contactProofSessionFixture(t, db, "email")
		results := make(chan error, 8)
		for range 8 {
			go func() {
				tx, err := db.BeginTx(ctx, nil)
				if err == nil {
					err = ConsumeRecentContactSessionProofTx(ctx, tx, c.ID, session.ID, plain)
					if err == nil {
						err = tx.Commit()
					} else {
						_ = tx.Rollback()
					}
				}
				results <- err
			}()
		}
		successes := 0
		for range 8 {
			err := <-results
			if err == nil {
				successes++
			} else {
				contactOTPRequireInvalid(t, err)
			}
		}
		if successes != 1 {
			t.Fatal("concurrent password changes consumed one recent proof more than once")
		}
	})
}
