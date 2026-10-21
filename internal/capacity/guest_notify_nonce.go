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

const GuestNotifyCanaryNoncePath = "/v1/guest/provisioning/notify-creation-canary-nonce"

func GuestNotifyPreflightSHA(c model.CapacityGuestNotifyCanaryChallenge) string {
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
	c.Signature = ""
	return GuestRetirementSHA(c)
}
func ValidateGuestNotifyCanaryPreflight(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, now time.Time) error {
	if c.GuestNonce != (model.CapacityGuestNotifyCanaryNonce{}) {
		return fmt.Errorf("empty original Guest nonce required at preflight")
	}
	return validateGuestNotifyCanaryChallengeBase(c, e, now)
}
func ValidateGuestNotifyCanaryNonce(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment) error {
	n := c.GuestNonce
	signature := n.Signature
	n.Signature = ""
	phase := "read"
	if GuestNotifyCanaryPublication(c) {
		phase = "publish"
	}
	duration := c.OriginalDeadline.Sub(c.IssuedAt)
	if n.Schema != "original_notify_canary_guest_nonce_v1" || n.ChallengeID != c.ChallengeID || n.Phase != phase || n.PreflightSHA256 != GuestNotifyPreflightSHA(c) || n.EnrollmentSHA256 != c.EnrollmentSHA256 || n.Actor != e.Statement.Actor || n.Runtime != e.Statement.Runtime || len(e.Statement.Writers) != 1 || n.Writer != e.Statement.Writers[0] || !ValidDigest(n.NonceSHA256) || duration <= 0 || duration > 5*time.Second || n.IssuedMonotonicNS <= 0 || n.ExpiresMonotonicNS <= n.IssuedMonotonicNS || n.ExpiresMonotonicNS-n.IssuedMonotonicNS != int64(duration) || !guestRetirementVerify(e.Statement.ObservationPublicKey, signature, n) {
		return fmt.Errorf("authentic immutable local Guest kernel nonce required")
	}
	return nil
}
func ValidateGuestNotifyCanaryChallenge(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, now time.Time) error {
	if err := validateGuestNotifyCanaryChallengeBase(c, e, now); err != nil {
		return err
	}
	return ValidateGuestNotifyCanaryNonce(c, e)
}

// The caller creates its original five-second context BEFORE any nonce I/O.
// This performs one GET, retains its real original HTTP return, and signs the
// exact scope plus opaque local Guest nonce without renewing either owner.
func AcquireGuestNotifyCanaryNonce(original context.Context, client *GuestOriginalHTTPClient, key ed25519.PrivateKey, c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment) (model.CapacityGuestNotifyCanaryChallenge, GuestOriginalHTTPReturn, error) {
	var returned GuestOriginalHTTPReturn
	if original == nil || original.Err() != nil || ValidateGuestNotifyCanaryPreflight(c, e, time.Now().UTC()) != nil || !GuestLifecycleKeyMatches(key, e.Statement.CoreIntentPublicKey) {
		return c, returned, ErrGuestOriginalTransport
	}
	deadline, ok := original.Deadline()
	if !ok || c.OriginalDeadline.After(deadline) {
		return c, returned, ErrGuestOriginalTransport
	}
	body, err := json.Marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: c})
	if err != nil {
		return c, returned, err
	}
	returned, err = client.Original(original, http.MethodGet, GuestNotifyCanaryNoncePath, body)
	if err != nil {
		return c, returned, err
	}
	var nonce model.CapacityGuestNotifyCanaryNonce
	if GuestOriginalHTTPDecode(returned, &nonce) != nil || original.Err() != nil || !time.Now().Before(c.OriginalDeadline) {
		return c, returned, ErrGuestOriginalTransport
	}
	c.GuestNonce = nonce
	if err = ValidateGuestNotifyCanaryNonce(c, e); err != nil {
		return c, returned, err
	}
	c.Signature = ""
	c.Signature, err = GuestLifecycleSignature(key, c)
	return c, returned, err
}
