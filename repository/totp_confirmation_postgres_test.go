package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/pquerna/otp/totp"
)

func TestTOTPConfirmationPostgres(t *testing.T) {
	db := contactOTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	ctx := context.Background()
	envelope := cryptoenvelope.NewWithStaticKEK([]byte(strings.Repeat("k", 32)))
	for _, scenario := range []string{"pending_after_global_mfa", "stale_replacement_code", "enroll_link_single_use", "reset_clears_confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			c, _ := contactOTPFixture(t, db)
			if MarkMFAEnrolled(ctx, db, c.ID, time.Now()) != nil {
				t.Fatal("global contact MFA fixture failed")
			}
			seed := "JBSWY3DPEHPK3PXP"
			if SetTOTPSecret(ctx, db, envelope, c.ID, []byte(seed)) != nil {
				t.Fatal("pending TOTP fixture failed")
			}
			identity, err := GetAuthIdentityByCollaboratorID(ctx, db, c.ID)
			if err != nil || identity.HasTOTP || identity.MFAEnrolledAt == nil {
				t.Fatal("global MFA posture incorrectly confirmed a pending TOTP seed")
			}
			if _, err := GetConfirmedTOTPSecret(ctx, db, envelope, c.ID); !errors.Is(err, mfa.ErrInvalidTOTP) {
				t.Fatal("pending TOTP seed was available to authentication")
			}
			code, err := totp.GenerateCode(seed, time.Now())
			if err != nil {
				t.Fatal("current TOTP proof fixture failed")
			}
			hashes := contactOTPRecoveryHashes(t)
			if !errors.Is(ConfirmTOTPEnrollment(ctx, db, envelope, c.ID, "invalid", hashes, ""), mfa.ErrInvalidTOTP) {
				t.Fatal("invalid code confirmed TOTP")
			}
			token := ""
			if scenario == "enroll_link_single_use" {
				token = strings.Repeat("a", 64)
				if _, err := IssueMFAEnrollToken(ctx, db, c.ID, token, time.Now().Add(time.Hour)); err != nil {
					t.Fatal("TOTP enrollment link fixture failed")
				}
			}
			if ConfirmTOTPEnrollment(ctx, db, envelope, c.ID, code, hashes, token) != nil {
				t.Fatal("current TOTP proof was not atomically confirmed")
			}
			if got, err := GetConfirmedTOTPSecret(ctx, db, envelope, c.ID); err != nil || string(got) != seed {
				t.Fatal("confirmed seed was not preserved for authentication")
			}
			switch scenario {
			case "stale_replacement_code":
				var replacement mfa.TOTPSecret
				var replacementCode string
				for {
					replacement, err = mfa.GenerateTOTPSecret(c.PrimaryEmail)
					if err != nil {
						t.Fatal("replacement TOTP fixture failed")
					}
					replacementCode, err = totp.GenerateCode(replacement.Base32, time.Now())
					if err == nil && mfa.ValidateTOTP(replacement.Base32, code) != nil {
						break
					}
				}
				if SetTOTPSecret(ctx, db, envelope, c.ID, []byte(replacement.Base32)) != nil {
					t.Fatal("replacement TOTP write failed")
				}
				identity, err := GetAuthIdentityByCollaboratorID(ctx, db, c.ID)
				if err != nil || identity.HasTOTP {
					t.Fatal("replacement inherited an old seed's confirmation")
				}
				if !errors.Is(ConfirmTOTPEnrollment(ctx, db, envelope, c.ID, code, hashes, ""), mfa.ErrInvalidTOTP) {
					t.Fatal("stale seed proof confirmed a replaced seed")
				}
				if ConfirmTOTPEnrollment(ctx, db, envelope, c.ID, replacementCode, hashes, "") != nil {
					t.Fatal("current replacement seed could not be confirmed")
				}
			case "enroll_link_single_use":
				if !errors.Is(ConfirmTOTPEnrollment(ctx, db, envelope, c.ID, code, hashes, token), ErrMFAEnrollTokenAlreadyConsumed) {
					t.Fatal("TOTP enrollment link was replayed")
				}
			case "reset_clears_confirmation":
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal("TOTP reset fixture failed")
				}
				defer func() { _ = tx.Rollback() }()
				if ResetMFAFactors(ctx, tx, c.ID) != nil || tx.Commit() != nil {
					t.Fatal("TOTP reset failed")
				}
				var confirmed bool
				if db.QueryRow(`SELECT totp_confirmed_at IS NOT NULL FROM public.auth_identities WHERE collaborator_id=$1`, c.ID).Scan(&confirmed) != nil || confirmed {
					t.Fatal("MFA reset retained TOTP confirmation authority")
				}
			}
		})
	}
}
