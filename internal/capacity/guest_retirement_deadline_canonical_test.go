package capacity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Real production context bounds and V1 DTO/signatures, with declared local
// cryptographic fixtures only. No Guest, SQL, provider or registry authority.
func TestGuestOriginalRetirementDeadlineCanonicalDurableIntent(t *testing.T) {
	for _, kind := range []string{"parent_monotonic", "parent_nonUTC_nanoseconds", "lease_nanoseconds", "thirty_second_cap"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			switch kind {
			case "parent_monotonic":
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
			case "parent_nonUTC_nanoseconds":
				cancel()
				bound := time.Now().Add(7*time.Second + 19*time.Nanosecond).In(time.FixedZone("declared-unit-offset", 19800))
				ctx, cancel = context.WithDeadline(t.Context(), bound)
				defer cancel()
			}
			issued := time.Now().UTC()
			lease := issued.Add(5 * time.Minute)
			if kind == "lease_nanoseconds" {
				lease = issued.Add(5*time.Second + 97*time.Nanosecond)
			}
			parent, _ := ctx.Deadline()
			want := parent
			for _, bound := range []time.Time{issued.Add(30 * time.Second), lease} {
				if bound.Before(want) {
					want = bound
				}
			}
			deadline, err := GuestOriginalRetirementDeadline(ctx, issued, lease)
			if err != nil || !deadline.Equal(want) || deadline.UnixNano() != want.UnixNano() || deadline.Location() != time.UTC {
				t.Fatal("original parent/lease/30s bound or nanoseconds changed", err)
			}

			_, enrollment, _, key, _, _ := guestNotifyUnit(t)
			nonce := strings.Repeat("e", 64)
			digest := strings.Repeat("a", 64)
			id := "11111111-1111-4111-8111-111111111111"
			intent := model.CapacityGuestRetirementIntent{
				Schema: GuestRetirementSchema, Purpose: GuestRetirementPurpose,
				BindingName: enrollment.Statement.BindingName, Slot: enrollment.Statement.Tuple.Slot,
				RequestID: id, AttemptID: id, NonceSHA256: BusinessCreationSHA256([]byte(nonce)),
				EnrollmentSHA256: GuestRetirementSHA(enrollment), Tuple: enrollment.Statement.Tuple, Actor: enrollment.Statement.Actor,
				PolicyID: id, PolicyChecksum: digest, WorkflowID: id, WorkflowChecksum: digest,
				Generation: 6, Fence: 15, LeaseOwner: id,
				WithdrawOperationID: id, WithdrawRequestSHA256: digest, DrainOperationID: id, DrainRequestSHA256: digest,
				OriginalDeadline: deadline, IssuedAt: issued,
			}
			request := model.CapacityGuestRetirementRequest{Intent: intent, Nonce: nonce}
			request.Signature, err = GuestLifecycleSignature(key, intent)
			if err != nil || GuestRetirementRequest(request, enrollment, issued, true) != nil {
				t.Fatal("declared signed V1 request refused", err)
			}
			// Issue persists this exact nonce-free durable request before Reserve.
			durable := request
			durable.Nonce = ""
			raw, err := json.Marshal(durable)
			if err != nil {
				t.Fatal(err)
			}
			var stored model.CapacityGuestRetirementRequest
			if err = DecodeGuestLifecycle(raw, &stored); err != nil {
				t.Fatal(err)
			}
			if stored.Intent != request.Intent || stored.Signature != request.Signature || GuestRetirementSHA(stored.Intent) != GuestRetirementSHA(request.Intent) || stored.Nonce != "" {
				t.Fatal("exact durable intent would fail original Reserve struct/signature equality")
			}
			for _, change := range []string{"nonce", "fence", "deadline"} {
				wrong := request
				switch change {
				case "nonce":
					wrong.Nonce = strings.Repeat("f", 64)
				case "fence":
					wrong.Intent.Fence++
				case "deadline":
					wrong.Intent.OriginalDeadline = wrong.Intent.OriginalDeadline.Add(time.Nanosecond)
				}
				if GuestRetirementRequest(wrong, enrollment, issued, true) == nil {
					t.Fatal("UTC normalization accepted changed signed/private field", change)
				}
			}
			if GuestRetirementRequest(request, enrollment, deadline, true) == nil {
				t.Fatal("original deadline expiry became a write renewal")
			}
		})
	}
}
