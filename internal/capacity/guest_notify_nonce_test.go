package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestNotifyOriginalNonceScopeAndClockDomains(t *testing.T) {
	for _, kind := range []string{"original", "guest_clock_ahead", "guest_clock_behind", "missing_nonce", "wrong_phase", "foreign_preflight", "renewed_expiry", "foreign_actor", "foreign_writer", "unsigned_nonce", "zero_kernel_issue"} {
		t.Run(kind, func(t *testing.T) {
			c, e, r, core, observer, now := guestNotifyUnit(t)
			switch kind {
			case "missing_nonce":
				c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
			case "wrong_phase":
				c.GuestNonce.Phase = "publish"
			case "foreign_preflight":
				c.GuestNonce.PreflightSHA256 = strings.Repeat("e", 64)
			case "renewed_expiry":
				c.GuestNonce.ExpiresMonotonicNS++
			case "foreign_actor":
				c.GuestNonce.Actor.PID++
			case "foreign_writer":
				c.GuestNonce.Writer.Lifetime.PID++
			case "zero_kernel_issue":
				c.GuestNonce.IssuedMonotonicNS = 0
			}
			if kind != "original" && kind != "guest_clock_ahead" && kind != "guest_clock_behind" {
				c.GuestNonce.Signature = ""
				if kind != "unsigned_nonce" {
					c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
				}
				c.Signature = ""
				c.Signature, _ = GuestLifecycleSignature(core, c)
				r.ChallengeSHA256 = GuestRetirementSHA(c)
			}
			var frame GuestNotifyOriginalFrame
			if json.Unmarshal(r.NotifyOriginalReturn, &frame) != nil {
				t.Fatal("unit frame")
			}
			frame.RequestSHA256 = GuestRetirementSHA(c)
			if kind == "guest_clock_ahead" || kind == "guest_clock_behind" {
				offset := 12 * time.Hour
				if kind == "guest_clock_behind" {
					offset = -offset
				}
				r.CensusBefore.ObservedAt = r.CensusBefore.ObservedAt.Add(offset)
				r.CensusAfter.ObservedAt = r.CensusAfter.ObservedAt.Add(offset)
				r.OriginalReadStartedAt = r.OriginalReadStartedAt.Add(offset)
				r.OriginalRequestWriteReturnedAt = r.OriginalRequestWriteReturnedAt.Add(offset)
				r.OriginalFrameReadReturnedAt = r.OriginalFrameReadReturnedAt.Add(offset)
				r.ObservedAt = r.ObservedAt.Add(offset)
				frame.ReturnedAt = frame.ReturnedAt.Add(offset)
				*frame.CanaryReadStartedAt = frame.CanaryReadStartedAt.Add(offset)
				*frame.CanaryReadReturnedAt = frame.CanaryReadReturnedAt.Add(offset)
				*frame.CanaryReadDeadline = frame.CanaryReadDeadline.Add(offset)
			}
			raw, _ := json.Marshal(frame)
			r.NotifyOriginalReturn = append(raw, '\n')
			r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
			r.Signature = ""
			r.Signature, _ = GuestLifecycleSignature(observer, r)
			err := ValidateGuestNotifyCanaryEnvelope(c, e, r, now)
			if err == nil {
				_, err = GuestNotifyCanaryOriginalFrame(c, e, r)
			}
			positive := kind == "original" || kind == "guest_clock_ahead" || kind == "guest_clock_behind"
			if (err == nil) != positive {
				t.Fatalf("original local budget %s: %v", kind, err)
			}
		})
	}
}
