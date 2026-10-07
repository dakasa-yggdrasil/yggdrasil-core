package contactphone

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEnrollmentPolicyFailsClosedOnMalformedConfiguration(t *testing.T) {
	for _, raw := range []string{"", "false", "true", "enabled"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(EnrollmentPolicyEnv, raw)
			required, err := EnrollmentRequired()
			if raw == "enabled" {
				if err == nil {
					t.Fatal("invalid policy accepted")
				}
				return
			}
			if err != nil || required != (raw == "true") {
				t.Fatal("policy default changed")
			}
		})
	}
}

func TestPhoneEnvelopeRequiresConfiguredStrongKey(t *testing.T) {
	for _, raw := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", raw)
		if _, err := EnvelopeFromEnv(); err == nil {
			t.Fatal("contact envelope silently used a missing or invalid key")
		}
	}
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	if _, err := EnvelopeFromEnv(); err != nil {
		t.Fatal("valid envelope rejected")
	}
}
