package capacity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type guestOriginalTestTransport func(*http.Request) (*http.Response, error)

func (f guestOriginalTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type guestOriginalLateErrContext struct{ context.Context }

func (guestOriginalLateErrContext) Err() error { return nil }

type guestOriginalDeadlineBody struct {
	io.Reader
	deadline time.Time
}

func (b guestOriginalDeadlineBody) Close() error {
	timer := time.NewTimer(time.Until(b.deadline) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	return nil
}

func TestGuestOriginalHTTPLateCloseCannotRenewBudget(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	deadline, _ := base.Deadline()
	ctx := guestOriginalLateErrContext{base}
	calls := 0
	client := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: guestOriginalDeadlineBody{strings.NewReader(`{"ok":true}`), deadline}}, nil
	})}}
	returned, err := client.Original(ctx, http.MethodGet, GuestNotifyCanaryPath, []byte(`{}`))
	if calls != 1 || err == nil || !returned.OriginalContextFailed || returned.CloseReturnedAt.Before(deadline) || returned.ResponseBodyScope != GuestOriginalBodyCompleteRead {
		t.Fatal("late original Close accepted or native bounded read facts lost", err, returned)
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if GuestOriginalHTTPDecode(returned, &decoded) == nil {
		t.Fatal("late original admitted")
	}
	guestNativeV1ClockContracts(t)
}

func TestGuestOriginalHTTPOnlyClosedCanaryRoutes(t *testing.T) {
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{{http.MethodGet, GuestNotifyCanaryNoncePath, true}, {http.MethodGet, GuestNotifyCanaryPath, true}, {http.MethodPost, GuestNotifyCanaryPublicationPath, true}, {http.MethodPost, GuestNotifyCanaryPath, false}, {http.MethodGet, GuestNotifyCanaryPublicationPath, false}, {http.MethodPost, GuestNotifyCanaryNoncePath, false}, {http.MethodGet, GuestNotifyCanaryPath + "?caller=1", false}} {
		t.Run(test.method+test.path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			client := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}}
			_, err := client.Original(ctx, test.method, test.path, []byte(`{}`))
			if (err == nil) != test.allowed || calls != map[bool]int{true: 1, false: 0}[test.allowed] {
				t.Fatalf("closed route escaped: %v calls%d", err, calls)
			}
		})
	}
}

// Declared cryptographic/HTTP operands only, never Native capacity evidence.
func guestNativeV1ClockContracts(t *testing.T) {
	for _, skew := range []time.Duration{-time.Millisecond, 3 * time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		target := time.Now().Add(skew)
		if err := guestOriginalWaitCoreClock(ctx, target, target); err != nil || !time.Now().After(target) {
			t.Fatal("real Core clock did not satisfy strict original boundary", err)
		}
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if err := guestOriginalWaitCoreClock(ctx, time.Now().Add(50*time.Millisecond), time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation replaced", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	if guestOriginalWaitCoreClock(expired, time.Now().Add(-time.Second), time.Time{}) == nil {
		t.Fatal("expired original clock accepted")
	}
	stop()
	if guestOriginalWaitCoreClock(context.Background(), time.Now(), time.Time{}) == nil {
		t.Fatal("unbounded clock owner accepted")
	}

	b, e, i, snapshotRequest, snapshotResponse, snapshotAt := guestNativeClockSnapshotOperand(t, time.Now().Add(5*time.Millisecond))
	frame := guestOriginalNativeV1Clock{enrollment: e, intent: i, profileSHA: b.ProfileManifestSHA256}
	if target, strict, ok := frame.target(http.MethodGet, "/v1/runtime-snapshot", snapshotRequest, snapshotResponse); !ok || !target.Equal(snapshotAt) || !strict.IsZero() {
		t.Fatal("signed original snapshot clock target lost")
	}
	if _, _, ok := frame.target(http.MethodGet, "/v1/runtime-snapshot", snapshotRequest, []byte(`{"unknown":true}`)); ok {
		t.Fatal("malformed snapshot acquired clock behavior")
	}
	for _, cancelAfterRead := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		b, e, i, request, response, observed := guestNativeClockJournalOperand(t, time.Now().Add(100*time.Millisecond))
		frame := guestOriginalNativeV1Clock{enrollment: e, intent: i, profileSHA: b.ProfileManifestSHA256}
		floor, strict, ok := frame.target(http.MethodPost, "/v1/retirement", request, response)
		if !ok || !floor.Equal(observed) || !strict.Equal(observed) {
			t.Fatal("signed original journal time not joined to its private frame")
		}
		if _, _, ok := frame.target(http.MethodPost, "/v1/retirement", request, append(response, 'x')); ok {
			t.Fatal("malformed body became clock authority")
		}
		if _, _, ok := frame.target(http.MethodGet, "/v1/retirement/v2", request, response); ok {
			t.Fatal("V2 route acquired V1 clock behavior")
		}
		var observation model.CapacityGuestRetirementObservation
		if json.Unmarshal(response, &observation) != nil {
			t.Fatal("declared journal")
		}
		observation.Signature = "unsigned"
		unsigned, _ := json.Marshal(observation)
		if _, _, ok := frame.target(http.MethodGet, "/v1/retirement", request, unsigned); ok {
			t.Fatal("unsigned journal became clock authority")
		}
		body := &guestNativeClockBody{Reader: bytes.NewReader(response)}
		if cancelAfterRead {
			body.afterEOF = cancel
		}
		calls := 0
		base := &GuestOriginalHTTPClient{origin: "https://unit.invalid", client: &http.Client{Transport: guestOriginalTestTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: body}, nil
		})}}
		for _, foreign := range []string{"profile", "class", "origin", "issuer"} {
			bad := b
			switch foreign {
			case "profile":
				bad.ProfileManifest.Profile = "foreign"
			case "class":
				bad.EvidenceClass = "owned_provisioner_original"
			case "origin":
				bad.Members = []model.CapacityGuestRetirementMemberBinding{{Name: e.Statement.BindingName, Slot: e.Statement.Tuple.Slot, Origin: "https://foreign.invalid"}}
			case "issuer":
				bad.EnrollmentIssuerPublicKey = "unsigned"
			}
			if base.WithNativeV1ReturnClock(bad, e, i) != base {
				t.Fatal("foreign frame acquired Native clock state", foreign)
			}
		}
		client := base.WithNativeV1ReturnClock(b, e, i)
		if !GuestOriginalNativeQEMUProviderEnabled("native-qemu") {
			if client != base || client.nativeV1Clock != nil {
				t.Fatal("production client acquired Native clock state")
			}
			cancel()
			continue
		}
		if client == base || client.nativeV1Clock == nil {
			t.Fatal("Native private frame unavailable")
		}
		returned, err := client.Original(ctx, http.MethodPost, "/v1/retirement", request)
		if calls != 1 || body.closes != 1 || !bytes.Equal(returned.Body, response) || returned.ReadReturnedAt.IsZero() || returned.ReadReturnedAt.After(returned.CloseReturnedAt) || returned.CloseReturnedAt.After(returned.DriverReturnedAt) || returned.CloseReturnedAt.Before(body.closedAt) {
			t.Fatal("wait changed original request/Read/Close/bytes or first stamps")
		}
		if cancelAfterRead {
			if err == nil || !returned.OriginalContextFailed || !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled wait acquired a fresh return", err)
			}
		} else if err != nil || returned.OriginalContextFailed || !returned.CloseReturnedAt.After(observed) || returned.DriverReturnedAt.Before(observed) {
			t.Fatal("original Close/driver preceded signed Guest time", err)
		}
		cancel()
	}
}

type guestNativeClockBody struct {
	*bytes.Reader
	afterEOF func()
	closes   int
	closedAt time.Time
}

func (b *guestNativeClockBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.afterEOF != nil {
		done := b.afterEOF
		b.afterEOF = nil
		done()
	}
	return n, err
}
func (b *guestNativeClockBody) Close() error { b.closes++; b.closedAt = time.Now().UTC(); return nil }

func guestNativeClockJournalOperand(t *testing.T, at time.Time) (model.CapacityGuestRetirementBinding, model.CapacityGuestRetirementEnrollment, model.CapacityGuestRetirementIntent, []byte, []byte, time.Time) {
	t.Helper()
	c, e, _, core, observer, now := guestNotifyUnit(t)
	issuer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	e.Statement.Schema, e.Statement.Purpose = GuestRetirementSchema, GuestRetirementPurpose
	e.Statement.SourceClass = "native_qemu_qualification"
	e.Statement.Tuple.Provider = "native-qemu"
	e.Statement.IssuedAt = now.Add(-time.Second)
	e.Signature, _ = GuestLifecycleSignature(issuer, e.Statement)
	i := model.CapacityGuestRetirementIntent{Schema: GuestRetirementSchema, Purpose: GuestRetirementPurpose, BindingName: e.Statement.BindingName, Slot: e.Statement.Tuple.Slot, RequestID: "11111111-2222-4333-8444-555555555555", AttemptID: "22222222-3333-4444-8555-666666666666", NonceSHA256: c.NonceSHA256, EnrollmentSHA256: GuestRetirementSHA(e), Tuple: e.Statement.Tuple, Actor: e.Statement.Actor, PolicyID: c.PolicyID, PolicyChecksum: c.PolicyChecksum, WorkflowID: c.WorkflowID, WorkflowChecksum: c.WorkflowChecksum, Generation: c.Generation, Fence: c.Fence, LeaseOwner: c.LeaseOwner, IssuedAt: now.Add(-time.Second), OriginalDeadline: now.Add(time.Second)}
	rawNonce := strings.Repeat("n", 32)
	i.NonceSHA256 = BusinessCreationSHA256([]byte(rawNonce))
	r := model.CapacityGuestRetirementRequest{Intent: i, Nonce: rawNonce}
	r.Signature, _ = GuestLifecycleSignature(core, i)
	record := model.CapacityGuestRetirementRecord{Schema: GuestRetirementSchema, Sequence: 1, State: "possible_start", Intent: i, IntentSHA256: GuestRetirementSHA(i), EnrollmentSHA256: GuestRetirementSHA(e), PossibleStartAt: now, RecordedAt: at, WriterQuiescenceScope: "enrolled_roster_only"}
	o := model.CapacityGuestRetirementObservation{Schema: GuestRetirementSchema, Record: record, RecordSHA256: GuestRetirementSHA(record), JournalComplete: true, HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: at}
	o.Signature, _ = GuestLifecycleSignature(observer, o)
	b := model.CapacityGuestRetirementBinding{EvidenceClass: "native_qemu_qualification", CoreAuthoritySourceCommit: e.Statement.CoreAuthoritySourceCommit, EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(issuer.Public().(ed25519.PublicKey)), ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: GuestQualificationProfile, CoverageClass: "native_qualification_subset"}, Members: []model.CapacityGuestRetirementMemberBinding{{Name: e.Statement.BindingName, Slot: e.Statement.Tuple.Slot, Origin: "https://unit.invalid"}}}
	b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
	raw, _ := json.Marshal(r)
	reply, _ := json.Marshal(o)
	return b, e, i, raw, reply, at
}

func guestNativeClockSnapshotOperand(t *testing.T, at time.Time) (model.CapacityGuestRetirementBinding, model.CapacityGuestRetirementEnrollment, model.CapacityGuestRetirementIntent, []byte, []byte, time.Time) {
	t.Helper()
	b, e, i, _, _, _ := guestNativeClockJournalOperand(t, at)
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	sha := strings.Repeat("a", 64)
	challenge := model.CapacityGuestRuntimeSnapshotChallenge{Schema: GuestSnapshotSchema, Purpose: GuestSnapshotPurpose, ChallengeID: "33333333-4444-4555-8666-777777777777", Phase: "before_start", BindingName: e.Statement.BindingName, Slot: e.Statement.Tuple.Slot, PreregistrationID: "44444444-5555-4666-8777-888888888888", PreregistrationNonceSHA256: sha, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, EnrollmentSHA256: GuestRetirementSHA(e), ProfileManifestSHA256: b.ProfileManifestSHA256, Tuple: e.Statement.Tuple, RequestID: i.RequestID, AttemptID: i.AttemptID, IntentSHA256: GuestRetirementSHA(i), PolicyID: i.PolicyID, PolicyChecksum: i.PolicyChecksum, WorkflowID: i.WorkflowID, WorkflowChecksum: i.WorkflowChecksum, Generation: i.Generation, Fence: i.Fence, LeaseOwner: i.LeaseOwner, CoreSourceCommit: e.Statement.CoreAuthoritySourceCommit, IssuedAt: i.IssuedAt, OriginalDeadline: i.OriginalDeadline}
	challenge.Signature, _ = GuestLifecycleSignature(core, challenge)
	census := model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: 103, StartTicks: 1030}}, RawCensusSHA256: sha, ObservedAt: at.Add(-time.Millisecond)}
	snapshot := model.CapacityGuestRuntimeSnapshot{Schema: GuestSnapshotSchema, Purpose: GuestSnapshotPurpose, ChallengeID: challenge.ChallengeID, ChallengeSHA256: GuestRetirementSHA(challenge), PreregistrationID: challenge.PreregistrationID, OriginalRegistrationSHA256: challenge.OriginalRegistrationSHA256, OriginalCreateWitnessSHA256: challenge.OriginalCreateWitnessSHA256, ProfileManifestSHA256: challenge.ProfileManifestSHA256, EnrollmentSHA256: challenge.EnrollmentSHA256, Tuple: challenge.Tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Reader: e.Statement.Actor, Writers: e.Statement.Writers, WriterRosterSHA256: e.Statement.WriterRosterSHA256, ProtectedCensus: census, OriginalReadStartedAt: i.IssuedAt.Add(time.Millisecond), OriginalReadReturnedAt: at.Add(-500 * time.Microsecond), OriginalReadsReturned: true, OriginalClosesReturned: true, HoldReasons: []string{}, ObservedAt: at}
	snapshot.Signature, _ = GuestLifecycleSignature(observer, snapshot)
	request, _ := json.Marshal(model.CapacityGuestRuntimeSnapshotRequest{Challenge: challenge})
	response, _ := json.Marshal(snapshot)
	return b, e, i, request, response, at
}
