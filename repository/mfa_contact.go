package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var (
	ErrContactOTPInvalid     = errors.New("contact OTP is invalid or unavailable")
	ErrContactOTPRateLimited = errors.New("contact OTP sending limit reached")
	ErrContactUnavailable    = errors.New("MFA contact is unavailable")
	ErrLastMFAFactor         = errors.New("cannot remove the last primary MFA factor")
)

const (
	ContactOTPTTL         = 5 * time.Minute
	ContactOTPResendDelay = time.Minute
	ContactOTPMaxAttempts = 5
	ContactOTPMaxSends    = 5
)

func validContactChannel(channel string) bool { return channel == "email" || channel == "sms" }

func privateContactDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// ReadContactBinding identifies the canonical recipient without disclosing
// it. SMS uses the typed contact's version and declaration timestamp so even
// deleting and recreating version one cannot resurrect an old enrolled factor.
// Mutating callers take the collaborator lock before calling this helper.
func ReadContactBinding(ctx context.Context, db DBQuerier, id uuid.UUID, channel string) (string, error) {
	if id == uuid.Nil || !validContactChannel(channel) {
		return "", ErrContactUnavailable
	}
	var status, email string
	err := db.QueryRowContext(ctx, `SELECT status,primary_email FROM public.collaborators WHERE id=$1`, id).Scan(&status, &email)
	if errors.Is(err, sql.ErrNoRows) || err == nil && status != "active" {
		return "", ErrContactUnavailable
	}
	if err != nil {
		return "", fmt.Errorf("read MFA contact owner: %w", err)
	}
	if channel == "email" {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			return "", ErrContactUnavailable
		}
		return privateContactDigest(id.String() + "\x00email\x00" + email), nil
	}
	var version int64
	var declaredAt time.Time
	err = db.QueryRowContext(ctx, `SELECT version,declared_at FROM public.collaborator_phone_contacts WHERE collaborator_id=$1`, id).Scan(&version, &declaredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrContactUnavailable
	}
	if err != nil {
		return "", fmt.Errorf("read MFA phone declaration: %w", err)
	}
	return privateContactDigest(fmt.Sprintf("%s\x00sms\x00%d\x00%s", id, version, declaredAt.UTC().Format(time.RFC3339Nano))), nil
}

// ContactLoginBindingForVersion binds the owner and its random credential
// epoch, without deriving anything from password material. An invalid epoch
// fails closed; the migration generates one for every identity.
func ContactLoginBindingForVersion(id uuid.UUID, version string) string {
	epoch, err := uuid.Parse(version)
	if err != nil || epoch == uuid.Nil || id == uuid.Nil {
		return ""
	}
	return "login-password:" + id.String() + ":" + epoch.String()
}

// ReadContactLoginBinding reads the random epoch of a password-bearing active
// identity. Legacy credentials without password_updated_at remain protected.
func ReadContactLoginBinding(ctx context.Context, db DBQuerier, id uuid.UUID) (string, error) {
	var version string
	var hasPassword bool
	err := db.QueryRowContext(ctx, `SELECT a.mfa_password_version::text,COALESCE(a.password_hash,'')<>'' FROM public.auth_identities a JOIN public.collaborators c ON c.id=a.collaborator_id WHERE a.collaborator_id=$1 AND c.status='active'`, id).Scan(&version, &hasPassword)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !hasPassword {
		return "", ErrContactOTPInvalid
	}
	if err != nil {
		return "", fmt.Errorf("read MFA password binding: %w", err)
	}
	binding := ContactLoginBindingForVersion(id, version)
	if binding == "" {
		return "", ErrContactOTPInvalid
	}
	return binding, nil
}

// lockContactOwnerTx establishes the shared collaborator -> auth identity lock
// order used by contact mutations, issuance, verification and factor removal.
func lockContactOwnerTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM public.collaborators WHERE id=$1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || err == nil && status != "active" {
		return ErrContactOTPInvalid
	}
	if err != nil {
		return fmt.Errorf("lock MFA contact owner: %w", err)
	}
	var identity uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT collaborator_id FROM public.auth_identities WHERE collaborator_id=$1 FOR UPDATE`, id).Scan(&identity)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrContactOTPInvalid
	}
	if err != nil {
		return fmt.Errorf("lock MFA contact identity: %w", err)
	}
	return nil
}

func validateContactContextTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, purpose, binding string) error {
	if purpose == "login" {
		current, err := ReadContactLoginBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		if binding != current {
			return ErrContactOTPInvalid
		}
		var locked bool
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(locked_until>clock_timestamp(),FALSE) FROM public.auth_identities WHERE collaborator_id=$1`, id).Scan(&locked); err != nil {
			return fmt.Errorf("read MFA credential posture: %w", err)
		}
		if locked {
			return ErrContactOTPInvalid
		}
		return nil
	}
	if purpose != "enroll" {
		return ErrContactOTPInvalid
	}
	var exists bool
	switch {
	case strings.HasPrefix(binding, "enroll-token:"):
		hash := strings.TrimPrefix(binding, "enroll-token:")
		if len(hash) != 64 {
			return ErrContactOTPInvalid
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.mfa_enroll_tokens t JOIN public.auth_identities a ON a.collaborator_id=t.collaborator_id WHERE t.collaborator_id=$1 AND t.token_hash=$2 AND t.consumed_at IS NULL AND t.expires_at>clock_timestamp() AND a.mfa_enrolled_at IS NULL)`, id, hash).Scan(&exists); err != nil {
			return fmt.Errorf("read MFA enrollment authority: %w", err)
		}
	case strings.HasPrefix(binding, "session:"):
		sessionID, err := uuid.Parse(strings.TrimPrefix(binding, "session:"))
		if err != nil {
			return ErrContactOTPInvalid
		}
		// The row lock prevents revocation between proof and factor persistence.
		var found uuid.UUID
		err = tx.QueryRowContext(ctx, `SELECT id FROM public.auth_sessions WHERE id=$1 AND collaborator_id=$2 AND status='active' AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`, sessionID, id).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrContactOTPInvalid
		}
		if err != nil {
			return fmt.Errorf("read MFA enrollment session: %w", err)
		}
		exists = true
	default:
		return ErrContactOTPInvalid
	}
	if !exists {
		return ErrContactOTPInvalid
	}
	return nil
}

func enabledContactFactorTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, channel, binding string) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1 AND channel=$2 AND contact_binding=$3)`, id, channel, binding).Scan(&exists); err != nil {
		return fmt.Errorf("read enabled MFA contact factor: %w", err)
	}
	if !exists {
		return ErrContactOTPInvalid
	}
	return nil
}

// IssueContactOTP reserves a send before invoking a provider. All purposes
// share the same owner/channel quota; unsuccessful sends still count. A new
// challenge supersedes older challenges for that purpose and channel.
func IssueContactOTP(ctx context.Context, db *sql.DB, id uuid.UUID, channel, purpose, contextBinding, expectedContactBinding, rawToken, code string) (model.MFAContactChallenge, error) {
	if !validContactChannel(channel) || expectedContactBinding == "" || !mfa.ValidContactOTPToken(rawToken) || !mfa.ValidContactOTPCode(code) {
		return model.MFAContactChallenge{}, ErrContactOTPInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("begin contact OTP issuance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return model.MFAContactChallenge{}, err
	}
	current, err := ReadContactBinding(ctx, tx, id, channel)
	if err != nil {
		return model.MFAContactChallenge{}, err
	}
	if current != expectedContactBinding {
		return model.MFAContactChallenge{}, ErrContactOTPInvalid
	}
	if err := validateContactContextTx(ctx, tx, id, purpose, contextBinding); err != nil {
		return model.MFAContactChallenge{}, err
	}
	if purpose == "login" {
		if err := enabledContactFactorTx(ctx, tx, id, channel, current); err != nil {
			return model.MFAContactChallenge{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM public.auth_mfa_contact_challenges WHERE collaborator_id=$1 AND created_at<NOW()-INTERVAL '24 hours'`, id); err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("prune contact OTP challenges: %w", err)
	}
	var count int
	var tooSoon bool
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MAX(created_at)>NOW()-INTERVAL '60 seconds',FALSE) FROM public.auth_mfa_contact_challenges WHERE collaborator_id=$1 AND channel=$2 AND created_at>NOW()-INTERVAL '1 hour'`, id, channel).Scan(&count, &tooSoon); err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("read contact OTP sending budget: %w", err)
	}
	if count >= ContactOTPMaxSends || tooSoon {
		return model.MFAContactChallenge{}, ErrContactOTPRateLimited
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.auth_mfa_contact_challenges SET consumed_at=NOW() WHERE collaborator_id=$1 AND channel=$2 AND purpose=$3 AND consumed_at IS NULL`, id, channel, purpose); err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("supersede contact OTP challenges: %w", err)
	}
	out := model.MFAContactChallenge{TokenHash: mfa.HashContactOTPToken(rawToken), CodeHash: mfa.HashContactOTPCode(rawToken, code), CollaboratorID: id, Channel: channel, Purpose: purpose, ContextBinding: contextBinding, ContactBinding: current}
	err = tx.QueryRowContext(ctx, `INSERT INTO public.auth_mfa_contact_challenges (token_hash,code_hash,collaborator_id,channel,purpose,context_binding,contact_binding,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()+INTERVAL '5 minutes') RETURNING created_at,expires_at`, out.TokenHash, out.CodeHash, id, channel, purpose, contextBinding, current).Scan(&out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("store contact OTP challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.MFAContactChallenge{}, fmt.Errorf("commit contact OTP issuance: %w", err)
	}
	return out, nil
}

// ActivateContactOTP is called only after the adapter explicitly confirms
// status=sent. Pending/unknown/failed deliveries cannot create usable codes.
func ActivateContactOTP(ctx context.Context, db *sql.DB, tokenHash string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin contact OTP activation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var id uuid.UUID
	var channel, binding string
	err = tx.QueryRowContext(ctx, `SELECT collaborator_id,channel,contact_binding FROM public.auth_mfa_contact_challenges WHERE token_hash=$1`, tokenHash).Scan(&id, &channel, &binding)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrContactOTPInvalid
	}
	if err != nil {
		return fmt.Errorf("read contact OTP activation: %w", err)
	}
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return err
	}
	current, err := ReadContactBinding(ctx, tx, id, channel)
	if err != nil {
		return err
	}
	if current != binding {
		return ErrContactOTPInvalid
	}
	res, err := tx.ExecContext(ctx, `UPDATE public.auth_mfa_contact_challenges SET delivered_at=NOW() WHERE token_hash=$1 AND delivered_at IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp()`, tokenHash)
	if err != nil {
		return fmt.Errorf("activate contact OTP: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return ErrContactOTPInvalid
	}
	return tx.Commit()
}

// reserveAndVerifyContactOTPTx spends an attempt before comparison. Its caller
// must commit ErrContactOTPInvalid when spent=true so incorrect guesses cannot
// roll back the budget; all other outcomes may safely roll back.
func reserveAndVerifyContactOTPTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, channel, purpose, contextBinding, expectedContactBinding, rawToken, code string) (spent bool, err error) {
	if !validContactChannel(channel) || expectedContactBinding == "" || !mfa.ValidContactOTPToken(rawToken) {
		return false, ErrContactOTPInvalid
	}
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return false, err
	}
	current, err := ReadContactBinding(ctx, tx, id, channel)
	if err != nil {
		return false, err
	}
	if current != expectedContactBinding {
		return false, ErrContactOTPInvalid
	}
	if err := validateContactContextTx(ctx, tx, id, purpose, contextBinding); err != nil {
		return false, err
	}
	if purpose == "login" {
		if err := enabledContactFactorTx(ctx, tx, id, channel, current); err != nil {
			return false, err
		}
	}
	var codeHash string
	err = tx.QueryRowContext(ctx, `UPDATE public.auth_mfa_contact_challenges SET attempts=attempts+1 WHERE token_hash=$1 AND collaborator_id=$2 AND channel=$3 AND purpose=$4 AND context_binding=$5 AND contact_binding=$6 AND delivered_at IS NOT NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() AND attempts<5 RETURNING code_hash`, mfa.HashContactOTPToken(rawToken), id, channel, purpose, contextBinding, current).Scan(&codeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrContactOTPInvalid
	}
	if err != nil {
		return false, fmt.Errorf("reserve contact OTP attempt: %w", err)
	}
	if !mfa.VerifyContactOTPCode(rawToken, code, codeHash) {
		return true, ErrContactOTPInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.auth_mfa_contact_challenges SET consumed_at=NOW() WHERE token_hash=$1`, mfa.HashContactOTPToken(rawToken)); err != nil {
		return false, fmt.Errorf("consume contact OTP challenge: %w", err)
	}
	return true, nil
}

func finishContactOTPAttempt(tx *sql.Tx, spent bool, err error) error {
	if err != nil && (!spent || !errors.Is(err, ErrContactOTPInvalid)) {
		return err
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit contact OTP verification: %w", commitErr)
	}
	return err
}

func VerifyContactOTP(ctx context.Context, db *sql.DB, id uuid.UUID, channel, purpose, contextBinding, currentContactBinding, rawToken, code string) error {
	if purpose != "login" {
		return ErrContactOTPInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin contact OTP verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	spent, err := reserveAndVerifyContactOTPTx(ctx, tx, id, channel, purpose, contextBinding, currentContactBinding, rawToken, code)
	return finishContactOTPAttempt(tx, spent, err)
}

// VerifyContactOTPAndCreateSession keeps the password proof, one-use OTP and
// resulting session inside the reset/factor mutation lock boundary. A reset
// either precedes this transaction and rejects the proof, or follows it and
// revokes the committed session. It cannot finish between proof and issuance.
func VerifyContactOTPAndCreateSession(ctx context.Context, db *sql.DB, id uuid.UUID, channel, contextBinding, contactBinding, rawToken, code string, req model.LoginWithPasswordRequest, ttl time.Duration) (model.AuthSession, string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.AuthSession{}, "", fmt.Errorf("begin contact OTP session: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return model.AuthSession{}, "", err
	}
	var hash, scheme, version string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(password_hash,''),COALESCE(NULLIF(password_scheme,''),'pbkdf2_sha256'),mfa_password_version::text FROM public.auth_identities WHERE collaborator_id=$1`, id).Scan(&hash, &scheme, &version); err != nil {
		return model.AuthSession{}, "", fmt.Errorf("read locked contact OTP password: %w", err)
	}
	if hash == "" || contextBinding == "" || contextBinding != ContactLoginBindingForVersion(id, version) {
		return model.AuthSession{}, "", ErrContactOTPInvalid
	}
	if strings.TrimSpace(req.Password) == "" || verifyPasswordBridge(scheme, hash, req.Password) != nil {
		return model.AuthSession{}, "", ErrAuthInvalidCredentials
	}
	spent, err := reserveAndVerifyContactOTPTx(ctx, tx, id, channel, "login", contextBinding, contactBinding, rawToken, code)
	if err != nil {
		return model.AuthSession{}, "", finishContactOTPAttempt(tx, spent, err)
	}
	session, token, err := createAuthSession(ctx, tx, id, req.Metadata, ttl)
	if err != nil {
		return model.AuthSession{}, "", fmt.Errorf("issue proved contact OTP session: %w", err)
	}
	if err := finishContactOTPAttempt(tx, true, nil); err != nil {
		return model.AuthSession{}, "", err
	}
	return session, token, nil
}

// VerifyAndEnrollContactOTP commits proof, one-use enrollment authority,
// factor binding, MFA posture and recovery vault together. No partial
// enrollment can survive an expired/replayed link or a changed recipient.
func VerifyAndEnrollContactOTP(ctx context.Context, db *sql.DB, id uuid.UUID, channel, purpose, contextBinding, currentContactBinding, rawToken, code string, recoveryHashes []string) error {
	if purpose != "enroll" || len(recoveryHashes) != mfa.RecoveryCodeCount {
		return ErrContactOTPInvalid
	}
	for _, hash := range recoveryHashes {
		if len(hash) != 64 {
			return ErrContactOTPInvalid
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin contact MFA enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	spent, err := reserveAndVerifyContactOTPTx(ctx, tx, id, channel, purpose, contextBinding, currentContactBinding, rawToken, code)
	if err != nil {
		return finishContactOTPAttempt(tx, spent, err)
	}
	if strings.HasPrefix(contextBinding, "enroll-token:") {
		res, err := tx.ExecContext(ctx, `UPDATE public.mfa_enroll_tokens SET consumed_at=NOW() WHERE token_hash=$1 AND collaborator_id=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()`, strings.TrimPrefix(contextBinding, "enroll-token:"), id)
		if err != nil {
			return fmt.Errorf("consume contact MFA enrollment authority: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return ErrContactOTPInvalid
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.mfa_enroll_tokens SET consumed_at=NOW() WHERE collaborator_id=$1 AND consumed_at IS NULL`, id); err != nil {
			return fmt.Errorf("invalidate superseded MFA enrollment links: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.auth_mfa_contact_factors (collaborator_id,channel,contact_binding) VALUES ($1,$2,$3) ON CONFLICT (collaborator_id,channel) DO UPDATE SET contact_binding=EXCLUDED.contact_binding,enrolled_at=NOW()`, id, channel, currentContactBinding); err != nil {
		return fmt.Errorf("enroll contact MFA factor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.auth_identities SET mfa_enrolled_at=COALESCE(mfa_enrolled_at,NOW()),recovery_codes_hashes=$2 WHERE collaborator_id=$1`, id, pgTextArray(recoveryHashes)); err != nil {
		return fmt.Errorf("persist contact MFA enrollment: %w", err)
	}
	return finishContactOTPAttempt(tx, true, nil)
}

// ListContactMFAFactors silently excludes stale recipient bindings. Declaring
// a new email/phone never transfers a verified factor to the new recipient.
func ListContactMFAFactors(ctx context.Context, db dbtx, id uuid.UUID) ([]model.MFAContactFactor, error) {
	rows, err := db.QueryContext(ctx, `SELECT channel,contact_binding,enrolled_at FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1 ORDER BY channel`, id)
	if err != nil {
		return nil, fmt.Errorf("list contact MFA factors: %w", err)
	}
	var stored []model.MFAContactFactor
	for rows.Next() {
		factor := model.MFAContactFactor{CollaboratorID: id}
		if err := rows.Scan(&factor.Channel, &factor.ContactBinding, &factor.EnrolledAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan contact MFA factor: %w", err)
		}
		stored = append(stored, factor)
	}
	readErr := rows.Err()
	_ = rows.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read contact MFA factors: %w", readErr)
	}
	out := make([]model.MFAContactFactor, 0, len(stored))
	for _, factor := range stored {
		current, err := ReadContactBinding(ctx, db, id, factor.Channel)
		if errors.Is(err, ErrContactUnavailable) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if current == factor.ContactBinding {
			out = append(out, factor)
		}
	}
	return out, nil
}

func CountContactMFAFactorsTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) (int, error) {
	factors, err := ListContactMFAFactors(ctx, tx, id)
	return len(factors), err
}

// ConfiguredContactMFAFactors counts only current contact proofs that the
// operator has configured to deliver OTPs. Listing all enrolled factors stays
// separate so surfaces can show an enrolled but unavailable method.
func ConfiguredContactMFAFactors(ctx context.Context, db dbtx, id uuid.UUID) ([]model.MFAContactFactor, error) {
	factors, err := ListContactMFAFactors(ctx, db, id)
	if err != nil {
		return nil, err
	}
	out := make([]model.MFAContactFactor, 0, len(factors))
	for _, factor := range factors {
		if contactMFADeliveryReady(ctx, db, id, factor.Channel) {
			out = append(out, factor)
		}
	}
	return out, nil
}

// Configuration alone cannot make an encrypted SMS contact usable. This
// matches the HTTP availability check without contacting a message provider.
func contactMFADeliveryReady(ctx context.Context, db dbtx, id uuid.UUID, channel string) bool {
	if _, _, configured := mfa.ContactDeliverySelector(channel); !configured {
		return false
	}
	if channel == "sms" {
		envelope, err := contactphone.EnvelopeFromEnv()
		if err != nil {
			return false
		}
		phone, err := GetPhoneContact(ctx, db, envelope, id)
		return err == nil && phone != nil
	}
	return true
}

func CountConfiguredContactMFAFactorsTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) (int, error) {
	factors, err := ConfiguredContactMFAFactors(ctx, tx, id)
	return len(factors), err
}

func DisableContactMFAFactor(ctx context.Context, db *sql.DB, id uuid.UUID, channel string) error {
	if !validContactChannel(channel) {
		return ErrContactOTPInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin contact MFA removal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return err
	}
	var traditional int
	if err := tx.QueryRowContext(ctx, `SELECT (CASE WHEN totp_secret_ciphertext IS NOT NULL THEN 1 ELSE 0 END)+jsonb_array_length(webauthn_credentials) FROM public.auth_identities WHERE collaborator_id=$1`, id).Scan(&traditional); err != nil {
		return fmt.Errorf("count primary MFA factors: %w", err)
	}
	factors, err := ListContactMFAFactors(ctx, tx, id)
	if err != nil {
		return err
	}
	removesEnrolled := false
	remainingConfigured := 0
	for _, factor := range factors {
		if factor.Channel == channel {
			removesEnrolled = true
			continue
		}
		if contactMFADeliveryReady(ctx, tx, id, factor.Channel) {
			remainingConfigured++
		}
	}
	if removesEnrolled && traditional+remainingConfigured == 0 {
		return ErrLastMFAFactor
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1 AND channel=$2`, id, channel); err != nil {
		return fmt.Errorf("remove contact MFA factor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.auth_mfa_contact_challenges SET consumed_at=NOW() WHERE collaborator_id=$1 AND channel=$2 AND consumed_at IS NULL`, id, channel); err != nil {
		return fmt.Errorf("invalidate removed MFA contact challenges: %w", err)
	}
	return tx.Commit()
}
