package capacity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Pure cryptographic operands and real bounded HTTP completion only. These
// tests create no native retirement authority or approved production profile.
func retirementV2Unit(t *testing.T) (model.CapacityGuestRetirementRequestV2, model.CapacityGuestRetirementEnrollment, ed25519.PrivateKey, ed25519.PrivateKey) {
	c, e, _, key, observer, now := guestNotifyUnit(t)
	nonce := strings.Repeat("1", 64)
	i := model.CapacityGuestRetirementIntentV2{CapacityGuestRetirementIntent: model.CapacityGuestRetirementIntent{Schema: GuestRetirementV2IntentSchema, Purpose: GuestRetirementV2Purpose, BindingName: e.Statement.BindingName, Slot: e.Statement.Tuple.Slot, RequestID: c.ChallengeID, AttemptID: c.RecordChallengeID, NonceSHA256: BusinessCreationSHA256([]byte(nonce)), EnrollmentSHA256: GuestRetirementSHA(e), Tuple: e.Statement.Tuple, Actor: e.Statement.Actor, PolicyID: c.PolicyID, PolicyChecksum: c.PolicyChecksum, WorkflowID: c.WorkflowID, WorkflowChecksum: c.WorkflowChecksum, Generation: 2, Fence: 3, LeaseOwner: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", WithdrawOperationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", WithdrawRequestSHA256: c.NonceSHA256, DrainOperationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", DrainRequestSHA256: c.NonceSHA256, IssuedAt: now, OriginalDeadline: now.Add(3 * time.Second)}, PreregistrationID: c.PreregistrationID, ProfileManifestSHA256: c.ProfileManifestSHA256, CoreSourceCommit: c.CoreSourceCommit, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256}
	r := model.CapacityGuestRetirementRequestV2{Intent: i, Nonce: nonce}
	r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
	return r, e, key, observer
}
func retirementV2UnitNonce(r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment, key ed25519.PrivateKey) model.CapacityGuestRetirementNonceV2 {
	n := model.CapacityGuestRetirementNonceV2{Schema: GuestRetirementV2NonceSchema, RequestID: r.Intent.RequestID, AttemptID: r.Intent.AttemptID, PreflightSHA256: GuestRetirementV2PreflightSHA(r.Intent), EnrollmentSHA256: GuestRetirementSHA(e), Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, NonceSHA256: strings.Repeat("2", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(r.Intent.OriginalDeadline.Sub(r.Intent.IssuedAt))}
	n.Signature, _ = GuestLifecycleSignature(key, n)
	return n
}
func TestGuestRetirementV2OriginalOwnerConsumesWholeBudgetOnce(t *testing.T) {
	for _, kind := range []string{"original", "shorter_lease_deadline", "wrong_nonce_scope", "late_close", "expired_before_io"} {
		t.Run(kind, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "late_close" {
				cancel()
				parent, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
				defer cancel()
			}
			owner, err := NewGuestRetirementV2OriginalOwner(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			r, e, key, observer := retirementV2Unit(t)
			r.Intent.OriginalDeadline, _ = owner.Context().Deadline()
			if kind == "shorter_lease_deadline" {
				r.Intent.OriginalDeadline = time.Now().Add(200 * time.Millisecond).UTC()
			}
			r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
			if kind == "expired_before_io" {
				r.Intent.IssuedAt = time.Now().Add(-2 * time.Second)
				r.Intent.OriginalDeadline = time.Now().Add(-time.Second)
				r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
			}
			calls := 0
			client := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				wireDeadline, hasDeadline := request.Context().Deadline()
				if !hasDeadline || !wireDeadline.Equal(r.Intent.OriginalDeadline) {
					t.Fatal("nonce transport did not preserve the shortened original deadline")
				}
				if request.Method != http.MethodGet || request.URL.Path != model.GuestRetirementV2NoncePath {
					t.Fatal("arbitrary nonce endpoint")
				}
				n := retirementV2UnitNonce(r, e, observer)
				if kind == "wrong_nonce_scope" {
					n.AttemptID = r.Intent.RequestID
					n.Signature = ""
					n.Signature, _ = GuestLifecycleSignature(observer, n)
				}
				raw, _ := json.Marshal(n)
				body := io.NopCloser(strings.NewReader(string(raw)))
				if kind == "late_close" {
					body = guestOriginalDeadlineBody{Reader: strings.NewReader(string(raw)), deadline: r.Intent.OriginalDeadline}
				}
				return &http.Response{StatusCode: 200, Body: body}, nil
			})}}
			err = owner.AcquireNonce(client, key, r, e)
			positive := kind == "original" || kind == "shorter_lease_deadline"
			if (err == nil) != positive {
				t.Fatal("invalid original nonce admitted", err)
			}
			final, returned, elapsed, exportErr := owner.NonceExchange()
			if positive {
				if exportErr != nil || elapsed <= 0 || !returned.CloseReturnedAt.Before(r.Intent.OriginalDeadline) || final.Intent.GuestExpiresMonotonicNS != final.Intent.GuestNonce.ExpiresMonotonicNS-int64(elapsed) || ValidateGuestRetirementV2Request(final, e, time.Now(), true) != nil {
					t.Fatal("original elapsed not conservatively subtracted", exportErr)
				}
				if owner.AcquireNonce(client, key, r, e) == nil || calls != 1 {
					t.Fatal("nonce retried or original owner renewed")
				}
			} else if exportErr == nil {
				t.Fatal("incomplete exchange exported a final signature")
			}
			if kind == "expired_before_io" && calls != 0 {
				t.Fatal("expired preflight reached sender")
			}
		})
	}
}

func TestGuestRetirementV2SeparatesKernelClockFromCoreWall(t *testing.T) {
	for _, kind := range []string{"original", "guest_clock_ahead", "guest_clock_behind", "late_kernel", "wrong_boot", "wrong_nonce_hash", "wrong_expiry", "mixed_original_clock"} {
		t.Run(kind, func(t *testing.T) {
			r, e, key, observer := retirementV2Unit(t)
			r.Intent.GuestNonce = retirementV2UnitNonce(r, e, observer)
			r.Intent.GuestExpiresMonotonicNS = r.Intent.GuestNonce.ExpiresMonotonicNS - 1000000
			r.Signature, _ = GuestLifecycleSignature(key, r.Intent)
			local := time.Now().UTC()
			if kind == "guest_clock_ahead" {
				local = local.Add(24 * time.Hour)
			}
			if kind == "guest_clock_behind" {
				local = local.Add(-24 * time.Hour)
			}
			clock := model.CapacityGuestRetirementClockV2{Schema: GuestRetirementV2ClockSchema, BootID: e.Statement.Actor.BootID, GuestNonceSHA256: GuestRetirementSHA(r.Intent.GuestNonce), ExpiresMonotonicNS: r.Intent.GuestExpiresMonotonicNS, StartedMonotonicNS: r.Intent.GuestNonce.IssuedMonotonicNS + 1, ReturnedMonotonicNS: r.Intent.GuestNonce.IssuedMonotonicNS + 10000000, GuestLocalStartedAt: local, GuestLocalDeadline: local.Add(time.Duration(r.Intent.GuestExpiresMonotonicNS - r.Intent.GuestNonce.IssuedMonotonicNS - 1))}
			switch kind {
			case "late_kernel":
				clock.ReturnedMonotonicNS = clock.ExpiresMonotonicNS
			case "wrong_boot":
				clock.BootID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			case "wrong_nonce_hash":
				clock.GuestNonceSHA256 = r.Intent.GuestNonce.NonceSHA256
			case "wrong_expiry":
				clock.ExpiresMonotonicNS++
			}
			record := model.CapacityGuestRetirementRecordV2{Schema: GuestRetirementV2RecordSchema, Sequence: 1, State: "possible_start", Intent: r.Intent, IntentSHA256: GuestRetirementSHA(r.Intent), EnrollmentSHA256: GuestRetirementSHA(e), PossibleStartAt: local.Add(time.Millisecond), WriterQuiescenceScope: "enrolled_roster_only", RecordedAt: local.Add(2 * time.Millisecond), Clock: clock}
			o := model.CapacityGuestRetirementObservationV2{Schema: GuestRetirementV2ObservationSchema, Record: record, RecordSHA256: GuestRetirementSHA(record), JournalComplete: true, HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: local.Add(3 * time.Millisecond), Clock: clock}
			if kind == "mixed_original_clock" {
				o.Clock.ReturnedMonotonicNS++
			}
			o.Signature, _ = GuestLifecycleSignature(observer, o)
			positive := kind == "original" || kind == "guest_clock_ahead" || kind == "guest_clock_behind"
			if (GuestRetirementV2Observation(o, e, r.Intent, false) == nil) != positive {
				t.Fatal("wallclock or renewed kernel completion changed authority")
			}
			if kind == "late_kernel" && !GuestRetirementV2ObservedReturnAuthentic(o, e, r.Intent) {
				t.Fatal("late original diagnostic could not be retained")
			}
		})
	}
}
