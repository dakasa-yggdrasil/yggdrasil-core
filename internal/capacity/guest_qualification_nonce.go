package capacity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidateQualificationProbeNonce authenticates the Guest's opaque, immutable
// local budget. It does not compare different machines' clock readings.
func ValidateQualificationProbeNonce(c QualificationProbeChallenge, enrollment model.CapacityGuestRetirementEnrollment) error {
	n := c.GuestNonce
	preflight := c
	preflight.GuestNonce = QualificationProbeNonce{}
	duration := c.OriginalDeadline.Sub(c.IssuedAt)
	signature := n.Signature
	n.Signature = ""
	if c.Schema != qualificationProbeSchema || duration <= 0 || duration > 5*time.Second || n.Schema != "original_qualification_guest_nonce_v1" || n.ChallengeID != c.ChallengeID || n.EnrollmentSHA256 != c.EnrollmentSHA256 || n.Actor != c.Actor || n.Runtime != c.Runtime || n.Writer != c.Writer || !ValidDigest(n.NonceSHA256) || n.PreflightSHA256 != GuestRetirementSHA(preflight) || n.IssuedMonotonicNS <= 0 || n.ExpiresMonotonicNS <= n.IssuedMonotonicNS || n.ExpiresMonotonicNS-n.IssuedMonotonicNS != int64(duration) || !GuestQualificationSignature(enrollment.Statement.ObservationPublicKey, signature, n) {
		return fmt.Errorf("authentic immutable guest nonce required")
	}
	return nil
}

// AcquireQualificationProbeNonce performs exactly one authenticated preflight.
// original is the same caller-owned five-second context used for final delivery
// and acceptance; this function never creates or renews a deadline.
func AcquireQualificationProbeNonce(original context.Context, client *GuestOriginalHTTPClient, key ed25519.PrivateKey, c QualificationProbeChallenge, enrollment model.CapacityGuestRetirementEnrollment) (QualificationProbeChallenge, error) {
	if original.Err() != nil || c.GuestNonce != (QualificationProbeNonce{}) || !GuestLifecycleKeyMatches(key, enrollment.Statement.CoreIntentPublicKey) {
		return c, fmt.Errorf("original preflight context required")
	}
	deadline, ok := original.Deadline()
	if !ok || c.OriginalDeadline.After(deadline) {
		return c, fmt.Errorf("original preflight deadline required")
	}
	signature, err := GuestLifecycleSignature(key, c)
	if err != nil {
		return c, err
	}
	wire, err := json.Marshal(QualificationProbeRequest{Challenge: c, Signature: signature})
	if err != nil {
		return c, err
	}
	returned, err := client.Original(original, http.MethodGet, "/v1/qualification-serving-probe-nonce", wire)
	if err != nil {
		return c, err
	}
	var nonce QualificationProbeNonce
	if GuestOriginalHTTPDecode(returned, &nonce) != nil || original.Err() != nil {
		return c, fmt.Errorf("original guest nonce response required")
	}
	c.GuestNonce = nonce
	if err := ValidateQualificationProbeNonce(c, enrollment); err != nil {
		return c, err
	}
	return c, nil
}
