package capacity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeHCloudWitnessClosesEmptyAccountAndRequestIDGuards(t *testing.T) {
	for _, fault := range []string{"missing", "coreSource", "attempt", "policy", "poolEpoch", "generation", "fence", "launch", "physicalDigest", "readerScope", "readerTuple", "project", "action", "fakeRequestID", "observedClock"} {
		t.Run(fault, func(t *testing.T) {
			_, a, _, _, _, ack, now := nativeHCloudFixtureACK(t)
			w := CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
			switch fault {
			case "missing":
				w = nil
			case "coreSource":
				w.CoreSourceCommit = strings.Repeat("f", 40)
			case "attempt":
				w.AttemptID = uuid.NewString()
			case "policy":
				w.PolicyID = uuid.NewString()
			case "poolEpoch":
				w.PoolEpoch++
			case "generation":
				w.IntentGeneration++
			case "fence":
				w.FencingToken++
			case "launch":
				w.LaunchSHA256 = strings.Repeat("f", 64)
			case "physicalDigest":
				w.PhysicalIdentitySHA256 = strings.Repeat("f", 64)
			case "readerScope":
				w.Reader.ScopeSHA256 = strings.Repeat("f", 64)
			case "readerTuple":
				w.Reader.Adapter.Version++
			case "project":
				w.Observation.ProjectScope.DeclaredProjectID = "foreign"
			case "action":
				w.Acceptance.ActionCommand = "delete_server"
			case "fakeRequestID":
				w.Acceptance.RequestID = "action:987654"
			case "observedClock":
				ack.ObservedAt = ack.ObservedAt.Add(time.Nanosecond)
			}
			if w != nil {
				sealNativeHCloudFixture(&w.Observation)
				resealNativeHCloudWitnessFixture(w)
			}
			ack.HCloudWitness = w
			if NativeWorkerObservationValid(a, ack, now, 30) == nil {
				t.Fatal("incomplete, foreign or independently retimed witness qualified empty generic identity")
			}
		})
	}
	_, a, _, _, _, ack, _ := nativeHCloudFixtureACK(t)
	if NativeWorkerPhysicalValid(a, ack.IndependentCurrent) {
		t.Fatal("HCloud physical accepted without its sealed typed witness")
	}
	a.HCloudWitness = CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	if !NativeWorkerPhysicalValid(a, ack.IndependentCurrent) {
		t.Fatal("complete linked HCloud witness refused")
	}
}

func TestNativeHCloudWitnessCannotSelectItsOwnPolicyScope(t *testing.T) {
	p, a, _, _, _, ack, _ := nativeHCloudFixtureACK(t)
	w := CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	w.Reader.HCloudScope.DeclaredProjectID = "foreign-project"
	w.Observation.ProjectScope = *w.Reader.HCloudScope
	w.Reader.ScopeSHA256 = strings.Repeat("f", 64)
	w.Observation.BindingScopeSHA256 = w.Reader.ScopeSHA256
	sealNativeHCloudFixture(&w.Observation)
	resealNativeHCloudWitnessFixture(w)
	if !NativeWorkerHCloudWitnessValid(a, ack.IndependentCurrent, w) {
		t.Fatal("self-consistent alternate scope fixture was malformed")
	}
	if NativeWorkerHCloudWitnessBindingValid(p, a, w) {
		t.Fatal("a witness selected a different reader inventory/project instead of the policy pin")
	}
}

func TestNativeHCloudWitnessSurvivesBirthAttemptAndCopyWithoutPrivateOriginal(t *testing.T) {
	_, a, _, original, _, ack, _ := nativeHCloudFixtureACK(t)
	a.State, a.Physical, a.HCloudWitness = "acknowledged", &ack.IndependentCurrent, CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	birth := model.CapacityNativeWorkerBirth{Schema: NativeWorkerLifecycleMode, AttemptID: a.ID, PolicyID: a.PolicyID, Generation: a.Generation, FencingToken: a.FencingToken,
		PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, ExecutionAdapter: a.Execution.Adapter, ExecutionScopeSHA256: a.Execution.ScopeSHA256, LaunchSHA256: a.LaunchSHA256,
		Physical: ack.IndependentCurrent, HCloudWitness: CloneNativeWorkerHCloudWitness(a.HCloudWitness)}
	birthWire, err := json.Marshal(birth)
	if err != nil {
		t.Fatal(err)
	}
	a.BirthSHA256 = nativePrivateSHA(birthWire)
	attemptWire, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var restored model.CapacityNativeWorkerAttempt
	var restoredBirth model.CapacityNativeWorkerBirth
	if json.Unmarshal(attemptWire, &restored) != nil || json.Unmarshal(birthWire, &restoredBirth) != nil || restored.HCloudWitness == nil || restoredBirth.HCloudWitness == nil ||
		restored.HCloudWitness.EvidenceSHA256 != restoredBirth.HCloudWitness.EvidenceSHA256 || !NativeWorkerPhysicalValid(restored, *restored.Physical) {
		t.Fatal("a copy or persisted wire erased the provider-specific proof")
	}
	for _, wire := range [][]byte{birthWire, attemptWire} {
		if bytes.Contains(wire, []byte("CI-only-private-original-password")) || bytes.Contains(wire, []byte(nativePrivateSHA(original.Wire))) || bytes.Contains(wire, []byte("root_password")) {
			t.Fatal("public birth/attempt bound a raw-original digest or private provider metadata")
		}
	}
	copy := CloneNativeWorkerHCloudWitness(restored.HCloudWitness)
	copy.Reader.HCloudScope.DeclaredProjectID = "changed-copy"
	copy.Observation.PrimaryIPs[0].IP = "203.0.113.9"
	copy.Observation.Reads[0].Operation = "changed-copy"
	if restored.HCloudWitness.Reader.HCloudScope.DeclaredProjectID != "ci-reviewed-project" || restored.HCloudWitness.Observation.PrimaryIPs[0].IP != "203.0.113.8" ||
		restored.HCloudWitness.Observation.Reads[0].Operation != "GET /networks/{id}" {
		t.Fatal("copied witness retained mutable producer-owned storage")
	}
}

func TestNativeHCloudSealedWitnessDoesNotExpireButCannotFakeFreshInitialACK(t *testing.T) {
	_, a, _, _, _, ack, now := nativeHCloudFixtureACK(t)
	w := CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	shift := -time.Hour
	a.CreatedAt = a.CreatedAt.Add(shift)
	physical := ack.IndependentCurrent
	physical.CreatedAt = physical.CreatedAt.Add(shift)
	w.Acceptance.CreatedAt = w.Acceptance.CreatedAt.Add(shift)
	w.Observation.Physical.CreatedAt = w.Observation.Physical.CreatedAt.Add(shift)
	w.Observation.StartedAt = w.Observation.StartedAt.Add(shift)
	w.Observation.ObservedAt = w.Observation.ObservedAt.Add(shift)
	for i := range w.Observation.Reads {
		w.Observation.Reads[i].ObservedAt = w.Observation.Reads[i].ObservedAt.Add(shift)
	}
	sealNativeHCloudFixture(&w.Observation)
	wire, _ := json.Marshal(physical)
	w.PhysicalIdentitySHA256 = nativePrivateSHA(wire)
	resealNativeHCloudWitnessFixture(w)
	if !NativeWorkerHCloudWitnessValid(a, physical, w) {
		t.Fatal("immutable birth proof was incorrectly treated as a current quote")
	}
	ack.OriginalAcceptance, ack.IndependentCurrent, ack.HCloudWitness = physical, physical, w
	ack.ObservedAt = now
	if NativeWorkerObservationValid(a, ack, now, 30) == nil {
		t.Fatal("an aged independent read was retimed into a new fresh ACK")
	}
}

func TestNativeHCloudAbortUsesTypedWitnessRatherThanInventedAccount(t *testing.T) {
	p, a, _, _, _, ack, now := nativeHCloudFixtureACK(t)
	a.State, a.Physical, a.BirthSHA256, a.HCloudWitness = "acknowledged", &ack.IndependentCurrent, strings.Repeat("e", 64), CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
	p.NativeWorkerPoolBinding = &model.CapacityNativeWorkerPoolBinding{RealmUID: uuid.NewString(), PoolUID: a.PoolUID, Owner: "ci-native-owner", ExpectedPoolEpoch: a.PoolEpoch, RegistryRef: a.Registry,
		ProtectedNodes: []model.CapacityNativeProtectedNode{{NodeUID: uuid.NewString(), ProviderID: "hcloud://12345"}}}
	b := p.NativeWorkerPoolBinding
	o := model.CapacityNativeWorkerAbortObservation{ObservedAt: now, RealmUID: b.RealmUID, PoolUID: a.PoolUID, Owner: b.Owner, Epoch: a.PoolEpoch, Registry: a.Registry,
		RegistryResourceVersion: "17", ExecutionScopeSHA256: a.Execution.ScopeSHA256, Physical: *a.Physical, ProviderOutcome: "present", ProviderEvidenceSHA256: strings.Repeat("f", 64),
		NodeState: "none_confirmed", NodesComplete: true, PodsComplete: true, ApplicationPods: 0, NodeEvidenceSHA256: strings.Repeat("1", 64)}
	if !NativeWorkerAbortObservationValid(p, a, o, now) || !NativeWorkerAbortSendSafe(o) {
		t.Fatal("complete HCloud birth/header proof was refused solely for empty account")
	}
	without := a
	without.HCloudWitness = nil
	if NativeWorkerAbortObservationValid(p, without, o, now) {
		t.Fatal("empty account became a universal cleanup exception")
	}
	unknown := o
	unknown.NodeState = "unknown"
	unknown.NodesComplete = false
	if !NativeWorkerAbortObservationValid(p, a, unknown, now) || NativeWorkerAbortSendSafe(unknown) {
		t.Fatal("unknown Node inventory was fabricated as absence")
	}
	b.ProtectedNodes = append(b.ProtectedNodes, model.CapacityNativeProtectedNode{NodeUID: uuid.NewString(), ProviderID: a.Physical.ProviderID})
	if NativeWorkerAbortObservationValid(p, a, o, now) {
		t.Fatal("protected provider identity was permitted for cleanup")
	}
}

func TestNativeHCloudExceptionDoesNotRelaxAWSRequestIDs(t *testing.T) {
	p, a, launch, original, read, now := nativePhysicalFixture(t)
	ack, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"original", "independent", "foreignWitness"} {
		copy := ack
		switch which {
		case "original":
			copy.OriginalRequestID = ""
		case "independent":
			copy.IndependentRequestID = ""
		case "foreignWitness":
			copy.HCloudWitness = &model.CapacityNativeWorkerHCloudWitness{}
		}
		if NativeWorkerObservationValid(a, copy, now, 30) == nil {
			t.Fatal("HCloud empty-ID exception escaped its literal provider", which)
		}
	}
}
