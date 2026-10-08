package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func contactOTPPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_MFA_CONTACT_POSTGRES") == "true" {
			t.Fatal("mandatory contact MFA PostgreSQL gate lacks DB_URL")
		}
		t.Skip("contact MFA PostgreSQL verification runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("contact MFA PostgreSQL connection unavailable")
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal("contact MFA PostgreSQL connection unavailable")
	}
	return db
}

func contactOTPFixture(t *testing.T, db *sql.DB) (model.Collaborator, string) {
	t.Helper()
	id := uuid.NewString()
	c, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{Slug: "mfa-contact-ci-" + id, DisplayName: "MFA contact CI", PrimaryEmail: id + "@example.test"})
	if err != nil {
		t.Fatal("contact MFA fixture creation failed")
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.collaborators WHERE id=$1`, c.ID) })
	if _, err := db.Exec(`UPDATE public.auth_identities SET password_hash='fixture-password-hash',password_scheme='argon2id',password_updated_at=NULL WHERE collaborator_id=$1`, c.ID); err != nil {
		t.Fatal("contact MFA credential fixture failed")
	}
	session := uuid.New()
	if _, err := db.Exec(`INSERT INTO public.auth_sessions (id,collaborator_id,token_hash,expires_at) VALUES ($1,$2,$3,NOW()+INTERVAL '1 hour')`, session, c.ID, mfa.HashContactOTPToken(session.String())); err != nil {
		t.Fatal("contact MFA session fixture failed")
	}
	return c, "session:" + session.String()
}

func contactOTPBinding(t *testing.T, db *sql.DB, id uuid.UUID, channel string) string {
	t.Helper()
	binding, err := ReadContactBinding(context.Background(), db, id, channel)
	if err != nil || binding == "" {
		t.Fatal("canonical contact binding unavailable")
	}
	return binding
}

func contactOTPLoginBinding(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	binding, err := ReadContactLoginBinding(context.Background(), db, id)
	if err != nil || !strings.HasPrefix(binding, "login-password:") {
		t.Fatal("password authentication binding unavailable")
	}
	return binding
}

func contactOTPSeedFactor(t *testing.T, db *sql.DB, id uuid.UUID, channel string) string {
	t.Helper()
	binding := contactOTPBinding(t, db, id, channel)
	if _, err := db.Exec(`INSERT INTO public.auth_mfa_contact_factors (collaborator_id,channel,contact_binding) VALUES ($1,$2,$3)`, id, channel, binding); err != nil {
		t.Fatal("enrolled contact fixture failed")
	}
	if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, id); err != nil {
		t.Fatal("enrolled contact posture fixture failed")
	}
	return binding
}

func contactOTPIssue(t *testing.T, db *sql.DB, id uuid.UUID, channel, purpose, authority, binding string, activate bool) (string, string) {
	t.Helper()
	token, code, err := mfa.GenerateContactOTP()
	if err != nil {
		t.Fatal("challenge generation failed")
	}
	challenge, err := IssueContactOTP(context.Background(), db, id, channel, purpose, authority, binding, token, code)
	if err != nil || challenge.TokenHash != mfa.HashContactOTPToken(token) || challenge.CodeHash != mfa.HashContactOTPCode(token, code) {
		t.Fatal("contact OTP issuance or private vault contract failed")
	}
	if activate && ActivateContactOTP(context.Background(), db, challenge.TokenHash) != nil {
		t.Fatal("sent challenge activation failed")
	}
	return token, code
}

func contactOTPRecoveryHashes(t *testing.T) []string {
	t.Helper()
	_, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		t.Fatal("recovery vault generation failed")
	}
	return hashes
}

func contactOTPSetPhone(t *testing.T, db *sql.DB, id uuid.UUID, phone string) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("phone fixture transaction failed")
	}
	defer func() { _ = tx.Rollback() }()
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	if _, err := SetPhoneContactTx(context.Background(), tx, envelope, id, phone, "ci:mfa-contact", "self_profile"); err != nil || tx.Commit() != nil {
		t.Fatal("typed phone fixture failed")
	}
}

func contactOTPRequireInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrContactOTPInvalid) {
		t.Fatal("unusable contact OTP was not rejected")
	}
}

func TestMFAContactOTPPostgres(t *testing.T) {
	db := contactOTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("AUTH_EMAIL_INTEGRATION", "mfa-tests/mail")
	t.Setenv("AUTH_SMS_INTEGRATION", "mfa-tests/text")
	ctx := context.Background()

	t.Run("delivered_enrollment_replay", func(t *testing.T) {
		c, authority := contactOTPFixture(t, db)
		binding := contactOTPBinding(t, db, c.ID, "email")
		token, code := contactOTPIssue(t, db, c.ID, "email", "enroll", authority, binding, false)
		hashes := contactOTPRecoveryHashes(t)
		contactOTPRequireInvalid(t, VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", authority, binding, token, code, hashes))
		if ActivateContactOTP(ctx, db, mfa.HashContactOTPToken(token)) != nil {
			t.Fatal("confirmed delivery was not activated")
		}
		if VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", authority, binding, token, code, hashes) != nil {
			t.Fatal("delivered code did not enroll the factor")
		}
		factors, err := ListContactMFAFactors(ctx, db, c.ID)
		if err != nil || len(factors) != 1 || factors[0].Channel != "email" {
			t.Fatal("verified factor was not discoverable")
		}
		var vaultSize, attempts int
		var enrolled bool
		if db.QueryRow(`SELECT array_length(recovery_codes_hashes,1),mfa_enrolled_at IS NOT NULL FROM public.auth_identities WHERE collaborator_id=$1`, c.ID).Scan(&vaultSize, &enrolled) != nil || vaultSize != 10 || !enrolled {
			t.Fatal("enrollment did not atomically preserve MFA posture and recovery vault")
		}
		if db.QueryRow(`SELECT attempts FROM public.auth_mfa_contact_challenges WHERE token_hash=$1`, mfa.HashContactOTPToken(token)).Scan(&attempts) != nil || attempts != 1 {
			t.Fatal("undelivered challenge spent a verification attempt")
		}
		contactOTPRequireInvalid(t, VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", authority, binding, token, code, hashes))
	})

	t.Run("wrong_attempt_budget", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		for range ContactOTPMaxAttempts {
			contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, "invalid-format"))
		}
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code))
		var attempts int
		if db.QueryRow(`SELECT attempts FROM public.auth_mfa_contact_challenges WHERE token_hash=$1`, mfa.HashContactOTPToken(token)).Scan(&attempts) != nil || attempts != ContactOTPMaxAttempts {
			t.Fatal("failed guesses rolled back or exceeded the five-attempt budget")
		}
	})

	t.Run("cross_owner_channel_purpose_context", func(t *testing.T) {
		c, sessionAuthority := contactOTPFixture(t, db)
		other, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		otherBinding := contactOTPSeedFactor(t, db, other.ID, "email")
		contactOTPSetPhone(t, db, c.ID, "+12025550123")
		smsBinding := contactOTPSeedFactor(t, db, c.ID, "sms")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, other.ID, "email", "login", contactOTPLoginBinding(t, db, other.ID), otherBinding, token, code))
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "sms", "login", authority, smsBinding, token, code))
		contactOTPRequireInvalid(t, VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", sessionAuthority, binding, token, code, contactOTPRecoveryHashes(t)))
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority+"changed", binding, token, code))
		if VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code) != nil {
			t.Fatal("scope failures consumed the legitimate challenge")
		}
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code))
	})

	t.Run("contact_change_invalidates_factor_and_challenge", func(t *testing.T) {
		for _, channel := range []string{"email", "sms"} {
			t.Run(channel, func(t *testing.T) {
				c, _ := contactOTPFixture(t, db)
				if channel == "sms" {
					contactOTPSetPhone(t, db, c.ID, "+12025550124")
				}
				binding := contactOTPSeedFactor(t, db, c.ID, channel)
				authority := contactOTPLoginBinding(t, db, c.ID)
				token, code := contactOTPIssue(t, db, c.ID, channel, "login", authority, binding, true)
				if channel == "sms" {
					// Declaring even the same phone creates a new unverified version.
					contactOTPSetPhone(t, db, c.ID, "+12025550124")
				} else if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, uuid.NewString()+"@example.test"); err != nil {
					t.Fatal("contact replacement fixture failed")
				}
				contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, channel, "login", authority, binding, token, code))
				current := contactOTPBinding(t, db, c.ID, channel)
				contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, channel, "login", authority, current, token, code))
				factors, err := ListContactMFAFactors(ctx, db, c.ID)
				if err != nil || len(factors) != 0 {
					t.Fatal("old contact proof transferred to the changed recipient")
				}
			})
		}
	})

	t.Run("enrollment_link_authority_and_replay", func(t *testing.T) {
		c, sessionAuthority := contactOTPFixture(t, db)
		binding := contactOTPBinding(t, db, c.ID, "email")
		first := mfa.HashContactOTPToken(uuid.NewString())
		second := mfa.HashContactOTPToken(uuid.NewString())
		for _, hash := range []string{first, second} {
			if _, err := IssueMFAEnrollToken(ctx, db, c.ID, hash, time.Now().Add(time.Hour)); err != nil {
				t.Fatal("enrollment link fixture failed")
			}
		}
		authority := "enroll-token:" + first
		token, code := contactOTPIssue(t, db, c.ID, "email", "enroll", authority, binding, true)
		if VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", authority, binding, token, code, contactOTPRecoveryHashes(t)) != nil {
			t.Fatal("valid enrollment link proof failed")
		}
		var outstanding int
		if db.QueryRow(`SELECT count(*) FROM public.mfa_enroll_tokens WHERE collaborator_id=$1 AND consumed_at IS NULL`, c.ID).Scan(&outstanding) != nil || outstanding != 0 {
			t.Fatal("first enrollment left replayable enrollment links")
		}
		contactOTPRequireInvalid(t, VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", "enroll", authority, binding, token, code, contactOTPRecoveryHashes(t)))
		// Even newly issued operator links cannot add factors once MFA exists.
		third := mfa.HashContactOTPToken(uuid.NewString())
		if _, err := IssueMFAEnrollToken(ctx, db, c.ID, third, time.Now().Add(time.Hour)); err != nil {
			t.Fatal("additional enrollment link fixture failed")
		}
		nextToken, nextCode, _ := mfa.GenerateContactOTP()
		_, err := IssueContactOTP(ctx, db, c.ID, "email", "enroll", "enroll-token:"+third, binding, nextToken, nextCode)
		contactOTPRequireInvalid(t, err)
		// Authenticated-session additions are still allowed after first enrollment.
		contactOTPSetPhone(t, db, c.ID, "+12025550125")
		sms := contactOTPBinding(t, db, c.ID, "sms")
		nextToken, nextCode = contactOTPIssue(t, db, c.ID, "sms", "enroll", sessionAuthority, sms, true)
		if VerifyAndEnrollContactOTP(ctx, db, c.ID, "sms", "enroll", sessionAuthority, sms, nextToken, nextCode, contactOTPRecoveryHashes(t)) != nil {
			t.Fatal("live-session contact factor addition failed")
		}
	})

	t.Run("email_round_trip_does_not_revive_proof", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, uuid.NewString()+"@example.test"); err != nil {
			t.Fatal("email replacement fixture failed")
		}
		if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, c.ID, c.PrimaryEmail); err != nil {
			t.Fatal("email reversion fixture failed")
		}
		factors, err := ListContactMFAFactors(ctx, db, c.ID)
		if err != nil || len(factors) != 0 {
			t.Fatal("email reversion resurrected an old verified factor")
		}
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code))
	})

	t.Run("send_limits_failed_sends_and_purposes", func(t *testing.T) {
		c, sessionAuthority := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, false)
		token, code, _ := mfa.GenerateContactOTP()
		_, err := IssueContactOTP(ctx, db, c.ID, "email", "enroll", sessionAuthority, binding, token, code)
		if !errors.Is(err, ErrContactOTPRateLimited) {
			t.Fatal("resend cooldown was bypassed through another purpose or failed delivery")
		}
		for i := 1; i < ContactOTPMaxSends; i++ {
			if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=created_at-INTERVAL '61 seconds' WHERE collaborator_id=$1`, c.ID); err != nil {
				t.Fatal("send-budget clock fixture failed")
			}
			contactOTPIssue(t, db, c.ID, "email", "enroll", sessionAuthority, binding, false)
		}
		if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=created_at-INTERVAL '61 seconds' WHERE collaborator_id=$1`, c.ID); err != nil {
			t.Fatal("send-budget clock fixture failed")
		}
		token, code, _ = mfa.GenerateContactOTP()
		_, err = IssueContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code)
		if !errors.Is(err, ErrContactOTPRateLimited) {
			t.Fatal("sixth hourly send bypassed the shared sending budget")
		}
	})

	t.Run("concurrent_single_consume", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		results := make(chan error, 8)
		var group sync.WaitGroup
		for range 8 {
			group.Add(1)
			go func() {
				defer group.Done()
				results <- VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code)
			}()
		}
		group.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else {
				contactOTPRequireInvalid(t, err)
			}
		}
		if successes != 1 {
			t.Fatal("concurrent login proofs did not consume exactly once")
		}
	})

	t.Run("concurrent_single_send", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		results := make(chan error, 2)
		for range 2 {
			go func() {
				token, code, err := mfa.GenerateContactOTP()
				if err == nil {
					_, err = IssueContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code)
				}
				results <- err
			}()
		}
		successes := 0
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrContactOTPRateLimited) {
				t.Fatal("concurrent send reservation failed unexpectedly")
			}
		}
		if successes != 1 {
			t.Fatal("concurrent sends bypassed the serialized cooldown")
		}
	})

	t.Run("expired_revoked_suspended_password_changed", func(t *testing.T) {
		for _, change := range []string{"expired", "suspended", "password", "session_revoked"} {
			t.Run(change, func(t *testing.T) {
				c, authority := contactOTPFixture(t, db)
				binding := contactOTPBinding(t, db, c.ID, "email")
				purpose := "enroll"
				if change == "password" {
					binding = contactOTPSeedFactor(t, db, c.ID, "email")
					authority = contactOTPLoginBinding(t, db, c.ID)
					purpose = "login"
				}
				token, code := contactOTPIssue(t, db, c.ID, "email", purpose, authority, binding, true)
				var err error
				switch change {
				case "expired":
					_, err = db.Exec(`UPDATE public.auth_mfa_contact_challenges SET expires_at=NOW()-INTERVAL '1 second' WHERE collaborator_id=$1`, c.ID)
				case "suspended":
					_, err = db.Exec(`UPDATE public.collaborators SET status='suspended' WHERE id=$1`, c.ID)
				case "password":
					_, err = db.Exec(`UPDATE public.auth_identities SET password_hash='changed-password-hash' WHERE collaborator_id=$1`, c.ID)
				case "session_revoked":
					_, err = db.Exec(`UPDATE public.auth_sessions SET revoked_at=NOW(),status='revoked' WHERE collaborator_id=$1`, c.ID)
				}
				if err != nil {
					t.Fatal("credential/contact lifetime fixture failed")
				}
				if purpose == "login" {
					contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", purpose, authority, binding, token, code))
				} else {
					contactOTPRequireInvalid(t, VerifyAndEnrollContactOTP(ctx, db, c.ID, "email", purpose, authority, binding, token, code, contactOTPRecoveryHashes(t)))
				}
			})
		}
	})

	t.Run("last_primary_factor_and_reset", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		if _, err := db.Exec(`UPDATE public.auth_identities SET recovery_codes_hashes=$2 WHERE collaborator_id=$1`, c.ID, pgTextArray(contactOTPRecoveryHashes(t))); err != nil {
			t.Fatal("recovery-only guard fixture failed")
		}
		if !errors.Is(DisableContactMFAFactor(ctx, db, c.ID, "email"), ErrLastMFAFactor) {
			t.Fatal("recovery codes were counted as a primary factor")
		}
		contactOTPSetPhone(t, db, c.ID, "+12025550126")
		contactOTPSeedFactor(t, db, c.ID, "sms")
		if DisableContactMFAFactor(ctx, db, c.ID, "sms") != nil {
			t.Fatal("second primary contact factor could not be removed")
		}
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("reset fixture transaction failed")
		}
		defer func() { _ = tx.Rollback() }()
		if ResetMFAFactors(ctx, tx, c.ID) != nil || tx.Commit() != nil {
			t.Fatal("full MFA reset failed")
		}
		var factors, outstanding int
		if db.QueryRow(`SELECT count(*) FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1`, c.ID).Scan(&factors) != nil || factors != 0 {
			t.Fatal("full reset retained a verified contact factor")
		}
		if db.QueryRow(`SELECT count(*) FROM public.auth_mfa_contact_challenges WHERE collaborator_id=$1 AND consumed_at IS NULL`, c.ID).Scan(&outstanding) != nil || outstanding != 0 {
			t.Fatal("full reset retained an outstanding contact challenge")
		}
		contactOTPRequireInvalid(t, VerifyContactOTP(ctx, db, c.ID, "email", "login", authority, binding, token, code))
	})

	t.Run("atomic_session_and_replay", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		hash, err := coreauth.HashPassword("mfa-contact-session-fixture-password")
		if err != nil {
			t.Fatal("session password fixture generation failed")
		}
		if _, err := db.Exec(`UPDATE public.auth_identities SET password_hash=$2,password_scheme='pbkdf2_sha256',password_must_change=TRUE WHERE collaborator_id=$1`, c.ID, hash); err != nil {
			t.Fatal("session password fixture failed")
		}
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		req := model.LoginWithPasswordRequest{Identifier: c.PrimaryEmail, Password: "mfa-contact-session-fixture-password"}
		wrong := req
		wrong.Password = "incorrect-fixture-password"
		if _, _, err := VerifyContactOTPAndCreateSession(ctx, db, c.ID, "email", authority, binding, token, code, wrong, time.Hour); !errors.Is(err, ErrAuthInvalidCredentials) {
			t.Fatal("session issuance did not independently reprove the locked password")
		}
		badMetadata := req
		badMetadata.Metadata = map[string]any{"ip_address": "invalid-inet-fixture"}
		if _, _, err := VerifyContactOTPAndCreateSession(ctx, db, c.ID, "email", authority, binding, token, code, badMetadata, time.Hour); err == nil {
			t.Fatal("invalid session metadata unexpectedly committed")
		}
		var attempts int
		var consumed bool
		if db.QueryRow(`SELECT attempts,consumed_at IS NOT NULL FROM public.auth_mfa_contact_challenges WHERE token_hash=$1`, mfa.HashContactOTPToken(token)).Scan(&attempts, &consumed) != nil || attempts != 0 || consumed {
			t.Fatal("failed session issuance committed a partial OTP proof")
		}
		session, rawSession, err := VerifyContactOTPAndCreateSession(ctx, db, c.ID, "email", authority, binding, token, code, req, time.Hour)
		if err != nil || session.ID == uuid.Nil || session.CollaboratorID != c.ID || rawSession == "" {
			t.Fatal("correct proof did not atomically issue a password-change session")
		}
		_, _, err = VerifyContactOTPAndCreateSession(ctx, db, c.ID, "email", authority, binding, token, code, req, time.Hour)
		contactOTPRequireInvalid(t, err)
		var count int
		if db.QueryRow(`SELECT count(*) FROM public.auth_sessions WHERE collaborator_id=$1`, c.ID).Scan(&count) != nil || count != 2 {
			t.Fatal("replayed or failed proofs issued additional sessions")
		}
	})

	t.Run("reset_serializes_before_session_issuance", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		hash, err := coreauth.HashPassword("mfa-contact-reset-fixture-password")
		if err != nil {
			t.Fatal("reset password fixture generation failed")
		}
		if _, err := db.Exec(`UPDATE public.auth_identities SET password_hash=$2,password_scheme='pbkdf2_sha256' WHERE collaborator_id=$1`, c.ID, hash); err != nil {
			t.Fatal("reset password fixture failed")
		}
		binding := contactOTPSeedFactor(t, db, c.ID, "email")
		authority := contactOTPLoginBinding(t, db, c.ID)
		token, code := contactOTPIssue(t, db, c.ID, "email", "login", authority, binding, true)
		reset, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("serialized reset transaction failed")
		}
		defer func() { _ = reset.Rollback() }()
		if ResetMFAFactors(ctx, reset, c.ID) != nil {
			t.Fatal("serialized reset mutation failed")
		}
		if _, err := RevokeAllAuthSessions(ctx, reset, c.ID); err != nil {
			t.Fatal("serialized reset revocation failed")
		}
		results := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			req := model.LoginWithPasswordRequest{Identifier: c.PrimaryEmail, Password: "mfa-contact-reset-fixture-password"}
			_, _, err := VerifyContactOTPAndCreateSession(ctx, db, c.ID, "email", authority, binding, token, code, req, time.Hour)
			results <- err
		}()
		<-started
		if reset.Commit() != nil {
			t.Fatal("serialized reset did not commit")
		}
		contactOTPRequireInvalid(t, <-results)
		var count int
		if db.QueryRow(`SELECT count(*) FROM public.auth_sessions WHERE collaborator_id=$1 AND status='active' AND revoked_at IS NULL`, c.ID).Scan(&count) != nil || count != 0 {
			t.Fatal("a proof crossing reset issued a live session after revocation")
		}
	})

	t.Run("concurrent_last_primary_guard", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		contactOTPSeedFactor(t, db, c.ID, "email")
		contactOTPSetPhone(t, db, c.ID, "+12025550127")
		contactOTPSeedFactor(t, db, c.ID, "sms")
		results := make(chan error, 2)
		for _, channel := range []string{"email", "sms"} {
			go func() { results <- DisableContactMFAFactor(ctx, db, c.ID, channel) }()
		}
		successes := 0
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrLastMFAFactor) {
				t.Fatal("concurrent primary-factor removal failed unexpectedly")
			}
		}
		factors, err := ListContactMFAFactors(ctx, db, c.ID)
		if successes != 1 || err != nil || len(factors) != 1 {
			t.Fatal("concurrent removals stranded the identity without a primary factor")
		}
	})

	t.Run("unconfigured_contact_does_not_count_as_alternate", func(t *testing.T) {
		c, _ := contactOTPFixture(t, db)
		contactOTPSeedFactor(t, db, c.ID, "email")
		contactOTPSetPhone(t, db, c.ID, "+12025550128")
		contactOTPSeedFactor(t, db, c.ID, "sms")
		t.Setenv("AUTH_SMS_INTEGRATION", "")
		all, err := ListContactMFAFactors(ctx, db, c.ID)
		if err != nil || len(all) != 2 {
			t.Fatal("unavailable enrolled factor disappeared from the enrollment list")
		}
		configured, err := ConfiguredContactMFAFactors(ctx, db, c.ID)
		if err != nil || len(configured) != 1 || configured[0].Channel != "email" {
			t.Fatal("unconfigured SMS factor counted as a usable primary factor")
		}
		if !errors.Is(DisableContactMFAFactor(ctx, db, c.ID, "email"), ErrLastMFAFactor) {
			t.Fatal("unconfigured SMS permitted removal of the last usable contact factor")
		}
		if _, err := db.Exec(`UPDATE public.auth_identities SET webauthn_credentials='[{"id":"fixture-last-passkey"}]'::jsonb WHERE collaborator_id=$1`, c.ID); err != nil {
			t.Fatal("passkey guard fixture failed")
		}
		t.Setenv("AUTH_EMAIL_INTEGRATION", "missing-selector-slash")
		if !errors.Is(RemoveWebAuthnCredential(ctx, db, c.ID, "fixture-last-passkey"), ErrLastMFAFactor) {
			t.Fatal("unconfigured contacts permitted removal of the last usable passkey")
		}
	})
}
