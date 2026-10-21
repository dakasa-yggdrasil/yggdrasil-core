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

// One invocation owns the actual original monotonic Core start before issue,
// nonce, possible-send, POST and complete Read/Close. None of these renew it.
// The nonce exchange is private source state, not workflow/HTTP input.
type GuestRetirementV2OriginalOwner struct {
	ctx            context.Context
	cancel         context.CancelFunc
	started        time.Time
	nonceAttempted bool
	request        model.CapacityGuestRetirementRequestV2
	nonceReturn    GuestOriginalHTTPReturn
	elapsed        time.Duration
	exchanged      bool
}

func NewGuestRetirementV2OriginalOwner(parent context.Context) (*GuestRetirementV2OriginalOwner, error) {
	if parent == nil || parent.Err() != nil {
		return nil, ErrGuestOriginalTransport
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	return &GuestRetirementV2OriginalOwner{ctx: ctx, cancel: cancel, started: started}, nil
}
func (o *GuestRetirementV2OriginalOwner) Context() context.Context { return o.ctx }
func (o *GuestRetirementV2OriginalOwner) Close() {
	if o != nil && o.cancel != nil {
		o.cancel()
	}
}

func (o *GuestRetirementV2OriginalOwner) AcquireNonce(client *GuestOriginalHTTPClient, key ed25519.PrivateKey, r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment) error {
	if o == nil || o.ctx == nil || o.nonceAttempted || o.ctx.Err() != nil || ValidateGuestRetirementV2Preflight(r, e, time.Now().UTC()) != nil || !GuestLifecycleKeyMatches(key, e.Statement.CoreIntentPublicKey) {
		return ErrGuestOriginalTransport
	}
	deadline, ok := o.ctx.Deadline()
	if !ok || r.Intent.OriginalDeadline.After(deadline) || r.Intent.IssuedAt.Before(o.started) {
		return ErrGuestOriginalTransport
	}
	// Shortening for the sampled remaining native lease preserves the same
	// original parent clock; it never replaces or extends that owner budget.
	clipped, stopClipped := context.WithDeadline(o.ctx, r.Intent.OriginalDeadline)
	oldCancel := o.cancel
	o.ctx = clipped
	o.cancel = func() { stopClipped(); oldCancel() }
	o.nonceAttempted = true // uncertainty never grants another nonce exchange.
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	returned, err := client.Original(o.ctx, http.MethodGet, model.GuestRetirementV2NoncePath, body)
	o.nonceReturn = returned
	if err != nil {
		return err
	}
	var nonce model.CapacityGuestRetirementNonceV2
	if GuestOriginalHTTPDecode(returned, &nonce) != nil || o.ctx.Err() != nil || !time.Now().Before(r.Intent.OriginalDeadline) {
		return ErrGuestOriginalTransport
	}
	elapsed := time.Since(o.started)
	if elapsed <= 0 || elapsed > 30*time.Second || nonce.IssuedMonotonicNS <= 0 || nonce.ExpiresMonotonicNS <= nonce.IssuedMonotonicNS || int64(elapsed) >= nonce.ExpiresMonotonicNS-nonce.IssuedMonotonicNS {
		return ErrGuestOriginalTransport
	}
	r.Intent.GuestNonce = nonce
	r.Intent.GuestExpiresMonotonicNS = nonce.ExpiresMonotonicNS - int64(elapsed)
	if ValidateGuestRetirementV2Nonce(r.Intent, e) != nil {
		return ErrGuestOriginalTransport
	}
	r.Signature, err = GuestLifecycleSignature(key, r.Intent)
	if err != nil || ValidateGuestRetirementV2Request(r, e, time.Now().UTC(), true) != nil {
		return ErrGuestOriginalTransport
	}
	o.request = r
	o.elapsed = elapsed
	o.exchanged = true
	return nil
}

// This exports an actual completed private source exchange, never a caller's
// elapsed duration. Persistence and possible-send must still commit separately.
func (o *GuestRetirementV2OriginalOwner) NonceExchange() (model.CapacityGuestRetirementRequestV2, GuestOriginalHTTPReturn, time.Duration, error) {
	if o == nil || !o.exchanged {
		return model.CapacityGuestRetirementRequestV2{}, GuestOriginalHTTPReturn{}, 0, fmt.Errorf("original retirement nonce exchange unavailable")
	}
	request := o.request
	request.Intent.Writers = append([]model.CapacityGuestRetirementWriter(nil), request.Intent.Writers...)
	returned := o.nonceReturn
	returned.Body = append([]byte(nil), returned.Body...)
	return request, returned, o.elapsed, nil
}
