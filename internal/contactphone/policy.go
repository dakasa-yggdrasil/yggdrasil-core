package contactphone

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
)

const EnrollmentPolicyEnv = "YGGDRASIL_REQUIRE_NEW_COLLABORATOR_PHONE"

// EnrollmentRequired controls new enrollment only. A persisted pending profile
// remains restricted independently of a later policy rollback.
func EnrollmentRequired() (bool, error) {
	switch strings.TrimSpace(os.Getenv(EnrollmentPolicyEnv)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New("YGGDRASIL_REQUIRE_NEW_COLLABORATOR_PHONE must be true or false")
	}
}

// EnvelopeFromEnv reuses the existing auth-at-rest key, with no fallback or
// plaintext persistence. Diagnostics never include key or contact material.
func EnvelopeFromEnv() (*cryptoenvelope.Envelope, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_KEK_BASE64")))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("phone contact encryption is not configured")
	}
	return cryptoenvelope.NewWithStaticKEK(raw), nil
}
