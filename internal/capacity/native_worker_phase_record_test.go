package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativePhaseRecordFixture struct {
	f                        phaseReaderFixture
	physical                 NativeWorkerLifecycleRead
	register, admit, release NativeWorkerPhaseRecordEvidence
	now                      time.Time
}

func nativePhaseACKWire(t *testing.T, c model.CapacityNativeWorkerPhasePermit, entry model.CapacityNativeWorkerRegistryEntry) []byte {
	t.Helper()
	metadata := map[string]any{"name": c.Registry.Name, "namespace": c.Registry.Namespace, "uid": c.Registry.UID, "resourceVersion": "ack-" + c.Action}
	reg := nativePhaseRegistryACK{Schema: "native_worker_pool_registry_v1", RealmUID: c.RealmUID, PoolUID: c.PoolUID, Owner: c.Owner, Epoch: c.Epoch, CurrentProfile: c.Node.Profile, Registrations: []model.CapacityNativeWorkerRegistryEntry{entry}}
	annotation, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	metadata["annotations"] = map[string]string{"yggdrasil.io/native-worker-pool-v1": string(annotation)}
	o := map[string]any{"apiVersion": "coordination.k8s.io/v1", "kind": "Lease", "metadata": metadata, "spec": map[string]any{"holderIdentity": c.Owner, "leaseTransitions": c.Epoch}}
	if c.Action == "release_quarantine" {
		o = map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": c.Node.Name, "uid": c.Node.UID, "resourceVersion": "ack-release"}, "spec": map[string]any{"providerID": c.Node.ProviderID, "taints": []any{}}}
	}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newNativePhaseRecordFixture(t *testing.T, admitted bool) nativePhaseRecordFixture {
	t.Helper()
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	prep, err := PrepareNativeWorkerPhaseFromRead(f.p, f.a, "register", f.o, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	register := phaseReaderPermitScope(f, prep.Context)
	register.PermitID, register.AttemptID, register.PolicyID = uuid.New(), f.a.ID, f.a.PolicyID
	register.IntentGeneration, register.FencingToken = f.a.Generation, f.a.FencingToken
	register.BindingName = f.p.NativeWorkerLifecycleBinding.RegistryWriter.BindingName
	register.Operation = f.p.NativeWorkerLifecycleBinding.RegistryWriter.Capability
	register.WriterScopeSHA256 = f.p.NativeWorkerLifecycleBinding.RegistryWriter.ScopeSHA256
	register.ExpiresAt, register.PhaseState = now.Add(time.Minute), "observed"
	f.registered(false)
	makeEvidence := func(c model.CapacityNativeWorkerPhasePermit, entry model.CapacityNativeWorkerRegistryEntry) NativeWorkerPhaseRecordEvidence {
		return NativeWorkerPhaseRecordEvidence{Context: c, Redeemed: true, Original: model.CapacityNativeWorkerPhaseReceive{PermitID: c.PermitID, BindingName: c.BindingName, HTTPStatus: 200, TransportCompleted: true, OriginalReturn: nativePhaseACKWire(t, c, entry), CompletedAt: now}}
	}
	r := nativePhaseRecordFixture{f: f, register: makeEvidence(register, f.o.Registrations[0]), now: now}
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: f.a.Profile, Adapter: marketTestAdapter(), SourceCommit: strings.Repeat("f", 40), ScopeSHA256: marketTestSHA("2")}
	r.f.p.NativeWorkerLifecycleBinding.PhysicalObservers = []model.CapacityNativeWorkerPhysicalReadBinding{b}
	r.physical = NativeWorkerLifecycleRead{Physical: *f.a.Physical, ObservedAt: now, SourceCommit: b.SourceCommit, ScopeSHA256: b.ScopeSHA256, Adapter: b.Adapter, EvidenceSHA256: marketTestSHA("3"), CurrentRequestID: "current-read", BirthOriginalRequestID: "original-create", BirthIndependentRequestID: "historical-read", OriginalReturnSHA256: marketTestSHA("4")}
	if !admitted {
		r.f.a.State = "acknowledged"
		r.f.a.NodeUID = ""
		return r
	}
	prep, err = PrepareNativeWorkerPhaseFromRead(r.f.p, r.f.a, "admit_registry", r.f.o, &r.f.proof, now)
	if err != nil {
		t.Fatal(err)
	}
	admit := register
	admit.Action = "admit_registry"
	admit.PermitID = uuid.New()
	admit.Admission = prep.Context.Admission
	admit.Admission.ReceiptSHA256 = marketTestSHA("4")
	r.f.registered(true)
	r.admit = makeEvidence(admit, r.f.o.Registrations[0])
	release := admit
	release.Action = "release_quarantine"
	release.PermitID = uuid.New()
	r.release = makeEvidence(release, r.f.o.Registrations[0])
	r.f.o.Candidates[0].Taints = nil
	return r
}

func (f nativePhaseRecordFixture) project() (model.CapacityNativeWorkerObservation, error) {
	if f.f.a.State == "acknowledged" {
		return ProjectNativeWorkerPhaseRecord(f.f.p, f.f.a, f.physical, f.register, nil, nil, f.f.o, nil, f.now)
	}
	return ProjectNativeWorkerPhaseRecord(f.f.p, f.f.a, f.physical, f.register, &f.admit, &f.release, f.f.o, &f.f.proof, f.now)
}

func TestNativePhaseRecordRequiresOriginalCASAndCurrentSameBirth(t *testing.T) {
	f := newNativePhaseRecordFixture(t, false)
	o, err := f.project()
	if err != nil || o.State != "registered" || o.NodeUID != f.f.o.Candidates[0].NodeUID || o.OriginalRequestID != "original-create" || o.IndependentRequestID != "current-read" || o.RegistryBeforeResourceVersion == o.RegistryAfterResourceVersion {
		t.Fatalf("real record refused: %v", err)
	}
	t.Run("coherent registration scope substitution", func(t *testing.T) {
		bad := newNativePhaseRecordFixture(t, false)
		bad.register.Context.Node.RegistrationBindingSHA256 = marketTestSHA("9")
		// The original and private grant agree with each other, while the
		// independent current GET retains the Source-qualified registration.
		substituted := bad.f.o.Registrations[0]
		substituted.RegistrationBindingSHA256 = marketTestSHA("9")
		bad.register.Original.OriginalReturn = nativePhaseACKWire(t, bad.register.Context, substituted)
		if _, err := nativePhaseOriginalACK(bad.register); err != nil {
			t.Fatal("negative lost its coherent original", err)
		}
		if err := NativeWorkerPhaseHeaderValid(bad.f.p, bad.f.o, bad.now); err != nil {
			t.Fatal("negative lost its Source-qualified current GET", err)
		}
		if _, err := ObserveNativeWorkerPhaseFromRead(bad.f.p, bad.register.Context, bad.f.o, bad.now); err == nil {
			t.Fatal("current Source guard accepted substituted private grant")
		}
		if _, err := bad.project(); err == nil {
			t.Fatal("coherent self-consistency replaced the Source registration qualification")
		}
	})
	for _, name := range []string{"missing", "malformed", "different"} {
		t.Run("original registry epoch "+name, func(t *testing.T) {
			bad := newNativePhaseRecordFixture(t, false)
			var object map[string]any
			if err := json.Unmarshal(bad.register.Original.OriginalReturn, &object); err != nil {
				t.Fatal(err)
			}
			spec := object["spec"].(map[string]any)
			switch name {
			case "missing":
				delete(spec, "leaseTransitions")
			case "malformed":
				spec["leaseTransitions"] = "not-an-epoch"
			case "different":
				spec["leaseTransitions"] = bad.register.Context.Epoch + 1
			}
			var err error
			bad.register.Original.OriginalReturn, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ObserveNativeWorkerPhaseFromRead(bad.f.p, bad.register.Context, bad.f.o, bad.now); err != nil {
				t.Fatal("negative lost coherent current GET", err)
			}
			if _, err = bad.project(); err == nil {
				t.Fatal("current GET supplied missing/wrong original epoch")
			}
		})
	}
	// Expiry never reopens the permission, but a genuine original return
	// after its one redemption remains usable with a new current read.
	f.register.Context.ExpiresAt = f.now.Add(-time.Minute)
	if _, err = f.project(); err != nil {
		t.Fatal("late original truth discarded", err)
	}
	cases := map[string]func(*nativePhaseRecordFixture){
		"never redeemed":               func(f *nativePhaseRecordFixture) { f.register.Redeemed = false },
		"future original":              func(f *nativePhaseRecordFixture) { f.register.Original.CompletedAt = f.now.Add(time.Second) },
		"GET applied without original": func(f *nativePhaseRecordFixture) { f.register.Original.OriginalReturn = nil },
		"partial custody":              func(f *nativePhaseRecordFixture) { f.register.Original.TransportCompleted = false },
		"HTTP success is not ACK":      func(f *nativePhaseRecordFixture) { f.register.Original.OriginalReturn = []byte(`{"ok":true}`) },
		"unobserved permit":            func(f *nativePhaseRecordFixture) { f.register.Context.PhaseState = "received" },
		"substituted attempt":          func(f *nativePhaseRecordFixture) { f.register.Context.AttemptID = uuid.New() },
		"substituted fence":            func(f *nativePhaseRecordFixture) { f.register.Context.FencingToken++ },
		"writer file drift":            func(f *nativePhaseRecordFixture) { f.register.Context.WriterScopeSHA256 = marketTestSHA("1") },
		"node UID drift":               func(f *nativePhaseRecordFixture) { f.f.o.Candidates[0].NodeUID = marketTestUUID(999) },
		"physical identity drift":      func(f *nativePhaseRecordFixture) { f.physical.Physical.ProviderID += "/other" },
		"reader source drift":          func(f *nativePhaseRecordFixture) { f.physical.SourceCommit = strings.Repeat("e", 40) },
		"reader adapter drift":         func(f *nativePhaseRecordFixture) { f.physical.Adapter.ManifestID = marketTestUUID(998) },
		"future current physical":      func(f *nativePhaseRecordFixture) { f.physical.ObservedAt = f.now.Add(time.Second) },
		"future Node read":             func(f *nativePhaseRecordFixture) { f.f.o.ObservedAt = f.now.Add(time.Second) },
		"duplicate original key": func(f *nativePhaseRecordFixture) {
			f.register.Original.OriginalReturn = []byte(`{"apiVersion":"v1","apiVersion":"coordination.k8s.io/v1","kind":"Lease"}`)
		},
		"case alias": func(f *nativePhaseRecordFixture) {
			f.register.Original.OriginalReturn = []byte(strings.Replace(string(f.register.Original.OriginalReturn), `"kind":`, `"Kind":"Lease","kind":`, 1))
		},
		"trailing object": func(f *nativePhaseRecordFixture) {
			f.register.Original.OriginalReturn = append(f.register.Original.OriginalReturn, []byte(`{}`)...)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newNativePhaseRecordFixture(t, false)
			change(&f)
			if _, err := f.project(); err == nil {
				t.Fatal("unsafe registry record accepted")
			}
		})
	}
}

func TestNativePhaseRecordAdmissionNeedsReleasedNodeAndIndependentReadiness(t *testing.T) {
	f := newNativePhaseRecordFixture(t, true)
	o, err := f.project()
	if err != nil || o.State != "admitted" || o.AdmissionReceiptSHA256 != f.admit.Context.Admission.ReceiptSHA256 || o.NetworkEvidenceSHA256 != f.f.proof.NetworkEvidenceSHA256 {
		t.Fatalf("full admission refused: %v", err)
	}
	cases := map[string]func(*nativePhaseRecordFixture){
		"quarantine still present": func(f *nativePhaseRecordFixture) {
			f.f.o.Candidates[0].Taints = []model.CapacityNativeWorkerPhaseTaint{{Key: "dakasa.io/native-worker-unadmitted", Value: f.f.a.PoolUID, Effect: "NoSchedule"}}
		},
		"not Ready":                   func(f *nativePhaseRecordFixture) { f.f.o.Candidates[0].Ready = false },
		"stale heartbeat":             func(f *nativePhaseRecordFixture) { f.f.o.Candidates[0].Heartbeat.ObservedAt = f.now.Add(-time.Hour) },
		"warmup substituted":          func(f *nativePhaseRecordFixture) { f.f.proof.WarmupEvidenceSHA256 = marketTestSHA("9") },
		"wrong worker address":        func(f *nativePhaseRecordFixture) { f.f.proof.WorkerIPv4 = "10.81.0.99" },
		"expired readiness":           func(f *nativePhaseRecordFixture) { f.f.proof.ValidUntil = f.now },
		"expired qualification":       func(f *nativePhaseRecordFixture) { f.f.a.QualificationValidUntil = f.now },
		"release not observed":        func(f *nativePhaseRecordFixture) { f.release.Context.PhaseState = "unknown" },
		"release incomplete original": func(f *nativePhaseRecordFixture) { f.release.Original.TransportCompleted = false },
		"changed receipt":             func(f *nativePhaseRecordFixture) { f.release.Context.Admission.ReceiptSHA256 = marketTestSHA("9") },
		"registry member substituted": func(f *nativePhaseRecordFixture) { f.f.o.Registrations[0].CreationProofSHA256 = marketTestSHA("9") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newNativePhaseRecordFixture(t, true)
			change(&f)
			if _, err := f.project(); err == nil {
				t.Fatal("unsafe admission accepted")
			}
		})
	}
}

func TestNativePhaseRecordPrivateEvidenceDoesNotSerialize(t *testing.T) {
	f := newNativePhaseRecordFixture(t, true)
	for _, v := range []any{f.physical, f.register} {
		raw, err := json.Marshal(v)
		if err != nil || strings.Contains(string(raw), f.physical.OriginalReturnSHA256) || strings.Contains(string(raw), "original_return") || strings.Contains(string(raw), f.register.Context.PermitID.String()) {
			t.Fatal("private phase evidence leaked")
		}
	}
}
