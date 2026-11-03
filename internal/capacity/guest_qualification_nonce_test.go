package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
)

func TestQualificationNonceImmutableSignedBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	enrollment := model.CapacityGuestRetirementEnrollment{}
	enrollment.Statement.ObservationPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	c := QualificationProbeChallenge{Schema: qualificationProbeSchema, ChallengeID: "fixture", EnrollmentSHA256: strings.Repeat("a", 64), NonceSHA256: strings.Repeat("b", 64), IssuedAt: time.Unix(100, 0), OriginalDeadline: time.Unix(105, 0)}
	n := QualificationProbeNonce{Schema: "original_qualification_guest_nonce_v1", ChallengeID: c.ChallengeID, EnrollmentSHA256: c.EnrollmentSHA256, NonceSHA256: strings.Repeat("c", 64), PreflightSHA256: GuestRetirementSHA(c), IssuedMonotonicNS: 10, ExpiresMonotonicNS: 5000000010}
	n.Signature, _ = GuestLifecycleSignature(key, n)
	c.GuestNonce = n
	if err := ValidateQualificationProbeNonce(c, enrollment); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*QualificationProbeChallenge){
		"mixed_version":       func(c *QualificationProbeChallenge) { c.Schema = "original_qualification_serving_probe_v1" },
		"different_preflight": func(c *QualificationProbeChallenge) { c.NonceSHA256 = strings.Repeat("d", 64) },
		"changed_identity":    func(c *QualificationProbeChallenge) { c.Actor.PID = 42 },
		"missing_nonce":       func(c *QualificationProbeChallenge) { c.GuestNonce = QualificationProbeNonce{} },
		"signature":           func(c *QualificationProbeChallenge) { c.GuestNonce.Signature = "invalid" },
		"expiry_extended":     func(c *QualificationProbeChallenge) { c.GuestNonce.ExpiresMonotonicNS++ },
		"expiry_shortened":    func(c *QualificationProbeChallenge) { c.GuestNonce.ExpiresMonotonicNS-- },
		"zero_origin":         func(c *QualificationProbeChallenge) { c.GuestNonce.IssuedMonotonicNS = 0 },
		"overflow_interval": func(c *QualificationProbeChallenge) {
			c.GuestNonce.IssuedMonotonicNS = -1
			c.GuestNonce.ExpiresMonotonicNS = 1<<63 - 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			altered := c
			mutate(&altered)
			if ValidateQualificationProbeNonce(altered, enrollment) == nil {
				t.Fatal("accepted changed proof")
			}
		})
	}
}
