package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Actual issued DTO, strict decoder and local signing key. This does not
// qualify production Guest authority, a snapshot response or old read records.
func TestGuestAuthoritySnapshotChallengeCanonicalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	parent, _ := ctx.Deadline()
	now := time.Now().UTC()
	original, lease := now.Add(30*time.Second), now.Add(time.Minute)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, digest := uuid.NewString(), strings.Repeat("a", 64)
	makeChallenge := func(deadline time.Time) model.CapacityGuestRuntimeSnapshotChallenge {
		c := model.CapacityGuestRuntimeSnapshotChallenge{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: uuid.NewString(), BindingName: "declared-local-read", Slot: 1, PreregistrationID: id, PreregistrationNonceSHA256: digest, OriginalRegistrationSHA256: digest, OriginalCreateWitnessSHA256: digest, EnrollmentSHA256: digest, ProfileManifestSHA256: digest, Tuple: model.CapacityGuestNativeTuple{Provider: "aws", InstanceID: id, InstanceChecksum: digest, TypeID: id, TypeChecksum: digest, ScopeChecksum: digest, ProfileChecksum: digest, Profile: "notify-aws-elastic", Slot: 1, ResourceID: "declared-local-native", CreatedAt: "2026-01-01T00:00:00Z"}, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), IntentSHA256: digest, Phase: "before_start", PolicyID: id, PolicyChecksum: digest, WorkflowID: id, WorkflowChecksum: digest, Generation: 6, Fence: 16, LeaseOwner: uuid.NewString(), CoreSourceCommit: capacity.GuestD11ProtocolAuthority, IssuedAt: now, OriginalDeadline: deadline}
		c.Signature, err = capacity.GuestLifecycleSignature(key, c)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	roundtrip := func(c model.CapacityGuestRuntimeSnapshotChallenge) model.CapacityGuestRuntimeSnapshotChallenge {
		wire, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		var loaded model.CapacityGuestRuntimeSnapshotChallenge
		if e = capacity.DecodeGuestLifecycle(wire, &loaded); e != nil {
			t.Fatal(e)
		}
		return loaded
	}
	t.Run("legacy_raw_context_reproduces_strict_mismatch", func(t *testing.T) {
		raw := makeChallenge(parent)
		loaded := roundtrip(raw)
		if loaded == raw || !loaded.OriginalDeadline.Equal(raw.OriginalDeadline) || capacity.GuestRetirementSHA(raw) != capacity.GuestRetirementSHA(loaded) {
			t.Fatal("real context did not reproduce canonical-SHA/strict-struct mismatch")
		}
	})
	for _, name := range []string{"context_bound", "intent_bound", "lease_bound", "evidence_bound"} {
		t.Run(name, func(t *testing.T) {
			i, l, age, expected := original, lease, 60, parent
			switch name {
			case "intent_bound":
				i = now.Add(time.Second)
				expected = i
			case "lease_bound":
				l = now.Add(2 * time.Second)
				expected = l
			case "evidence_bound":
				age = 1
				expected = now.Add(time.Second)
			}
			deadline, e := guestAuthorityReadDeadline(ctx, now, i, &l, age)
			if e != nil || !deadline.Equal(expected) || deadline.After(parent) || deadline.After(i) || deadline.After(l) || deadline.After(now.Add(time.Duration(age)*time.Second)) || deadline.Location() != time.UTC {
				t.Fatal("original minimum changed", e)
			}
			c := makeChallenge(deadline)
			loaded := roundtrip(c)
			if loaded != c {
				t.Fatal("new signed challenge differs after durable strict decode")
			}
			sig, e := base64.StdEncoding.DecodeString(loaded.Signature)
			if e != nil {
				t.Fatal(e)
			}
			loaded.Signature = ""
			unsigned, e := json.Marshal(loaded)
			if e != nil || !ed25519.Verify(pub, unsigned, sig) {
				t.Fatal("same original signature did not verify", e)
			}
			loaded.OriginalDeadline = loaded.OriginalDeadline.Add(time.Nanosecond)
			changed, _ := json.Marshal(loaded)
			if ed25519.Verify(pub, changed, sig) {
				t.Fatal("changed signed original instant accepted")
			}
		})
	}
	t.Run("unbounded_cancelled_missing_lease_refused", func(t *testing.T) {
		if _, e := guestAuthorityReadDeadline(context.Background(), now, original, &lease, 60); e == nil {
			t.Fatal("unbounded context")
		}
		if _, e := guestAuthorityReadDeadline(ctx, now, original, nil, 60); e == nil {
			t.Fatal("missing lease")
		}
		expired, stop := context.WithDeadline(t.Context(), now.Add(-time.Second))
		defer stop()
		if _, e := guestAuthorityReadDeadline(expired, now, original, &lease, 60); e == nil {
			t.Fatal("expired context")
		}
		cancelled, stopNow := context.WithTimeout(t.Context(), 5*time.Second)
		stopNow()
		if _, e := guestAuthorityReadDeadline(cancelled, now, original, &lease, 60); e == nil {
			t.Fatal("cancelled context")
		}
	})
}
