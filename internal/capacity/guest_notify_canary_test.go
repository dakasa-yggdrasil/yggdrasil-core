package capacity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Cryptographic and closed-wire semantic operands only. No native SQL rows,
// publisher, provider grant or approved production registry entry is invented.
func guestNotifyUnit(t *testing.T) (model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestRetirementEnrollment, model.CapacityGuestNotifyCanaryRead, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	sha := strings.Repeat("a", 64)
	source := strings.Repeat("b", 40)
	life := func(pid int) model.CapacityGuestRetirementLifetime {
		return model.CapacityGuestRetirementLifetime{BootID: "11111111-1111-4111-8111-111111111111", ProcessNonceSHA256: sha, PID: pid, StartTicks: uint64(pid * 10), SourceCommit: source, BinarySHA256: sha, ServiceInvocationID: strings.Repeat("c", 32)}
	}
	tuple := model.CapacityGuestNativeTuple{Provider: "aws", ResourceID: "i-1234567890abcdef0", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), Slot: 2}
	e := model.CapacityGuestRetirementEnrollment{Statement: model.CapacityGuestRetirementEnrollmentStatement{BindingName: "unit-notify", Tuple: tuple, Actor: life(101), Runtime: life(102), Writers: []model.CapacityGuestRetirementWriter{{ID: "notify", Lifetime: life(103)}}, ObservationPublicKey: base64.StdEncoding.EncodeToString(observer.Public().(ed25519.PublicKey)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey)), CoreAuthoritySourceCommit: source}}
	e.Statement.WriterRosterSHA256 = GuestRetirementSHA(e.Statement.Writers)
	cid := "22222222-2222-4222-8222-222222222222"
	c := model.CapacityGuestNotifyCanaryChallenge{Schema: GuestNotifyCanaryChallengeSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: cid, RecordChallengeID: "33333333-3333-4333-8333-333333333333", NonceSHA256: sha, UsageClass: "before_retirement_floor", BindingName: e.Statement.BindingName, Slot: 2, PreregistrationID: "44444444-4444-4444-8444-444444444444", PreregistrationNonceSHA256: sha, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, EnrollmentSHA256: GuestRetirementSHA(e), ProfileManifestSHA256: sha, Tuple: tuple, PolicyID: "55555555-5555-4555-8555-555555555555", PolicyChecksum: sha, WorkflowID: "66666666-6666-4666-8666-666666666666", WorkflowChecksum: sha, Generation: 2, Fence: 3, LeaseOwner: "unit-lease-owner", CoreSourceCommit: source, IssuedAt: now.Add(-10 * time.Millisecond), OriginalDeadline: now.Add(4 * time.Second)}
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: "read", PreflightSHA256: GuestNotifyPreflightSHA(c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: strings.Repeat("d", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
	c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
	c.Signature, _ = GuestLifecycleSignature(core, c)
	census := func(at time.Time) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: 103, StartTicks: 1030}}, RawCensusSHA256: sha, ObservedAt: at}
	}
	r := model.CapacityGuestNotifyCanaryRead{Schema: GuestNotifyCanaryReadSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: cid, ChallengeSHA256: GuestRetirementSHA(c), PreregistrationID: c.PreregistrationID, EnrollmentSHA256: c.EnrollmentSHA256, Tuple: tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256, CensusBefore: census(now.Add(-7 * time.Millisecond)), CensusAfter: census(now.Add(-500 * time.Microsecond)), OriginalReadStartedAt: now.Add(-8 * time.Millisecond), OriginalRequestWriteReturnedAt: now.Add(-6 * time.Millisecond), OriginalFrameReadReturnedAt: now.Add(-time.Millisecond), HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: now}
	start, returned, deadline := now.Add(-5*time.Millisecond), now.Add(-3*time.Millisecond), c.OriginalDeadline
	f := GuestNotifyOriginalFrame{Schema: "notify_original_guest_writer_v1", Kind: "creation_canary", NonceSHA256: e.Statement.Writers[0].Lifetime.ProcessNonceSHA256, Identity: GuestNotifyIdentity{source, sha, 103, 1030, e.Statement.Actor.BootID, e.Statement.Actor.ServiceInvocationID}, EnrollmentSHA256: c.EnrollmentSHA256, OperationID: cid, RequestSHA256: GuestRetirementSHA(c), ReturnedAt: now.Add(-2 * time.Millisecond), Roster: append([]string(nil), guestNotifyRoster...), CanaryInstalled: true, Healthy: true, CanaryBody: []byte(`{"scope":"semantic unit only; no native business authority"}`), CanaryReadStartedAt: &start, CanaryReadReturnedAt: &returned, CanaryReadDeadline: &deadline, RecordChallengeID: c.RecordChallengeID}
	f.CanaryBodySHA256 = BusinessCreationSHA256(f.CanaryBody)
	raw, _ := json.Marshal(f)
	r.NotifyOriginalReturn = append(raw, '\n')
	r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
	r.Signature, _ = GuestLifecycleSignature(observer, r)
	return c, e, r, core, observer, now
}
func TestGuestNotifyCanaryChallengeAndOriginalProcessEnvelope(t *testing.T) {
	for _, kind := range []string{"original", "record_challenge_differs_for_read", "unsigned_core", "expired_challenge", "extended_challenge", "wrong_provider", "wrong_enrollment", "changed_generation", "unknown_usage", "unsigned_actor", "wrong_actor", "foreign_writer", "unknown_census_member", "different_census", "census_before_request", "census_after_return", "frame_late", "context_failed", "held", "changed_frame_hash", "frame_nonce", "frame_identity", "frame_record", "frame_wrong_operation", "frame_bad_body_hash", "frame_missing_read_deadline", "frame_publication_cannot_be_read", "frame_unknown_member", "frame_duplicate_member", "frame_trailing_value"} {
		t.Run(kind, func(t *testing.T) {
			c, e, r, _, observer, now := guestNotifyUnit(t)
			switch kind {
			case "unsigned_core":
				c.Signature = ""
			case "expired_challenge":
				c.OriginalDeadline = now
			case "extended_challenge":
				c.OriginalDeadline = c.IssuedAt.Add(6 * time.Second)
			case "wrong_provider":
				c.Tuple.Provider = "native-qemu"
			case "wrong_enrollment":
				c.EnrollmentSHA256 = strings.Repeat("e", 64)
			case "changed_generation":
				c.Generation++
			case "unknown_usage":
				c.UsageClass = "caller_useful"
			case "unsigned_actor":
				r.Signature = ""
			case "wrong_actor":
				r.Actor.PID++
			case "foreign_writer":
				r.Writers[0].Lifetime.PID++
			case "unknown_census_member":
				r.CensusAfter.Processes = append(r.CensusAfter.Processes, model.CapacityGuestRetirementNativeProcess{PID: 999, StartTicks: 1})
			case "different_census":
				r.CensusAfter.RawCensusSHA256 = strings.Repeat("e", 64)
			case "census_before_request":
				r.CensusBefore.ObservedAt = c.IssuedAt.Add(-time.Second)
			case "census_after_return":
				r.CensusAfter.ObservedAt = now.Add(time.Second)
			case "frame_late":
				r.OriginalFrameReadReturnedAt = c.OriginalDeadline
			case "context_failed":
				r.OriginalContextFailed = true
			case "held":
				r.HoldReasons = []string{"unknown publisher"}
			case "changed_frame_hash":
				r.NotifyOriginalReturnSHA256 = strings.Repeat("e", 64)
			}
			if strings.HasPrefix(kind, "frame_") && kind != "frame_late" {
				var f GuestNotifyOriginalFrame
				if json.Unmarshal(r.NotifyOriginalReturn, &f) != nil {
					t.Fatal("bad unitframe")
				}
				switch kind {
				case "frame_nonce":
					f.NonceSHA256 = strings.Repeat("e", 64)
				case "frame_identity":
					f.Identity.PID++
				case "frame_record":
					f.RecordChallengeID = c.ChallengeID
				case "frame_wrong_operation":
					f.OperationID = "foreign"
				case "frame_bad_body_hash":
					f.CanaryBodySHA256 = strings.Repeat("e", 64)
				case "frame_missing_read_deadline":
					f.CanaryReadDeadline = nil
				case "frame_publication_cannot_be_read":
					f.Kind = "creation_canary_publication"
				}
				raw, _ := json.Marshal(f)
				if kind == "frame_unknown_member" {
					raw = append(raw[:len(raw)-1], []byte(`,"useful":true}`)...)
				}
				if kind == "frame_duplicate_member" {
					raw = append(raw[:len(raw)-1], []byte(`,"kind":"creation_canary"}`)...)
				}
				if kind == "frame_trailing_value" {
					raw = append(raw, []byte(` {}`)...)
				}
				r.NotifyOriginalReturn = append(raw, '\n')
				r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
				r.Signature = ""
				r.Signature, _ = GuestLifecycleSignature(observer, r)
			}
			good := ValidateGuestNotifyCanaryEnvelope(c, e, r, now) == nil
			if good {
				_, err := GuestNotifyCanaryOriginalFrame(c, e, r)
				good = err == nil
			}
			if good != (kind == "original" || kind == "record_challenge_differs_for_read") {
				t.Fatalf("original envelope admission=%v for %s", good, kind)
			}
		})
	}
}
