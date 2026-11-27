package capacity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type phaseReaderFixture struct {
	p     model.CapacityPolicySpec
	a     model.CapacityNativeWorkerAttempt
	o     model.CapacityNativeWorkerPhaseReadObservation
	proof model.CapacityNativeWorkerReadinessProof
}

func newPhaseReaderFixture(t *testing.T, now time.Time) phaseReaderFixture {
	t.Helper()
	p, _, _ := plannerMarketFixture(now, 0)
	exec := marketTestAdapter()
	exec.ManifestID = marketTestUUID(900)
	lifecycle := &model.CapacityNativeWorkerLifecycleBinding{Mode: NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60}
	for _, profile := range p.MarketBinding.Profiles {
		lifecycle.Profiles = append(lifecycle.Profiles, model.CapacityNativeWorkerExecutionProfile{Profile: profile.Profile, Adapter: exec, BindingName: "owned/" + profile.Profile, SDKSourceCommit: strings.Repeat("b", 40), ScopeSHA256: marketTestSHA("f"), EnsureCapability: "ensure_worker", ObserveCapability: "observe_worker", DestroyCapability: "destroy_worker", LaunchTemplateSHA256: marketTestSHA("b"), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "native/overlay", OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}})
	}
	reader := marketTestAdapter()
	reader.ManifestID = marketTestUUID(901)
	lifecycle.PhaseObserver = &model.CapacityNativeWorkerPhaseReadBinding{Mode: NativeWorkerPhaseReadMode, Name: "workers-read", SourceCommit: strings.Repeat("d", 40), Adapter: reader, ScopeSHA256: marketTestSHA("9"), RealmNamespace: "realm", MaxAgeSeconds: 30, QuarantineTaintKey: "dakasa.io/native-worker-unadmitted"}
	writer := marketTestAdapter()
	writer.ManifestID = marketTestUUID(902)
	lifecycle.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: writer, BindingName: "workers-write", PrincipalID: "phase-writer/fixed", SourceCommit: strings.Repeat("e", 40), ScopeSHA256: marketTestSHA("8"), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 15}
	p.NativeWorkerLifecycleBinding = lifecycle
	if err := ValidateNativeWorkerLifecycleBinding(p); err != nil {
		t.Fatal("invalid source fixture", err)
	}
	pool := p.NativeWorkerPoolBinding
	a := model.CapacityNativeWorkerAttempt{ID: uuid.MustParse(marketTestUUID(70)), PolicyID: uuid.MustParse(marketTestUUID(71)), PolicyChecksum: marketTestSHA("a"), Generation: 3, FencingToken: 7, PoolUID: pool.PoolUID, PoolEpoch: pool.ExpectedPoolEpoch, Registry: pool.RegistryRef, Profile: "hcloud", Provider: "hcloud", Region: "hel1", ProviderIDPrefix: "hcloud://", SourceCommit: lifecycle.SourceCommit, Execution: lifecycle.Profiles[0], NetworkBindingSHA256: marketTestSHA("f"), PhysicalSpecSHA256: pool.Profiles[0].PhysicalSpecSHA256, QualificationEvidenceSHA256: marketTestSHA("a"), QualificationValidUntil: now.Add(10 * time.Minute), OverlayIPv4: "10.81.0.7", LaunchSHA256: marketTestSHA("c"), BirthSHA256: marketTestSHA("e"), CreatedAt: now.Add(-20 * time.Second), State: "acknowledged"}
	physical := model.CapacityNativeWorkerPhysical{ResourceID: "177895230", ProviderID: "hcloud://177895230", AccountID: "project/123", InstanceType: "cx43", NetworkID: "network-123", CreatedAt: now.Add(-10 * time.Second), ImageID: "image-123", Region: "hel1", Zone: "hel1-dc2", NativeIPv4: "10.0.0.7", MACAddress: "02:00:00:00:00:07", PhysicalSpecSHA256: a.PhysicalSpecSHA256, PhysicalBindingSHA256: marketTestSHA("b"), LaunchSHA256: a.LaunchSHA256}
	a.Physical = &physical
	n := model.CapacityNativeWorkerPhaseCandidate{NodeName: "worker-one", NodeUID: marketTestUUID(72), NodeResourceVersion: "31", ProviderID: physical.ProviderID, Addresses: []model.CapacityNativeWorkerPhaseAddress{{Type: "InternalIP", Address: a.OverlayIPv4}}, PoolUIDLabel: pool.PoolUID, Taints: []model.CapacityNativeWorkerPhaseTaint{{Key: lifecycle.PhaseObserver.QuarantineTaintKey, Value: pool.PoolUID, Effect: "NoSchedule"}}, Ready: true, Heartbeat: model.CapacityNativeWorkerPhaseHeartbeat{Present: true, Fresh: true, UID: marketTestUUID(73), ResourceVersion: "41", ObservedAt: now}, AllocatableKnown: true, AllocatableMilliCPU: 2000, AllocatableMemoryBytes: 2 << 30, Registrations: []model.CapacityNativeWorkerRegistryEntry{}}
	o := model.CapacityNativeWorkerPhaseReadObservation{Schema: NativeWorkerPhaseReadMode, SourceCommit: lifecycle.PhaseObserver.SourceCommit, Adapter: reader, BindingName: lifecycle.PhaseObserver.Name, BindingScopeSHA256: lifecycle.PhaseObserver.ScopeSHA256, RequestedProviderID: physical.ProviderID, RequestedCreationProofSHA256: a.BirthSHA256, ObservedAt: now, Complete: true, FullCollectionComplete: true, CollectionResourceVersion: "100", CandidateSelected: true, EvidenceSHA256: marketTestSHA("6"), Registry: model.CapacityNativeWorkerPhaseRegistry{Ref: pool.RegistryRef, RealmNamespace: "realm", RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: p.Owner, Epoch: pool.ExpectedPoolEpoch, CurrentProfile: "hcloud", ResourceVersion: "20", AnnotationSHA256: marketTestSHA("7")}, Registrations: []model.CapacityNativeWorkerRegistryEntry{}, RegistryRegistrationsComplete: true, Candidates: []model.CapacityNativeWorkerPhaseCandidate{n}}
	proof := model.CapacityNativeWorkerReadinessProof{AttemptID: a.ID, NodeUID: n.NodeUID, ProviderID: n.ProviderID, WorkerIPv4: a.OverlayIPv4, BirthSHA256: a.BirthSHA256, Physical: physical, NetworkBindingSHA256: a.NetworkBindingSHA256, NetworkEvidenceSHA256: marketTestSHA("b"), WarmupEvidenceSHA256: marketTestSHA("c"), PhysicalQualificationSHA256: a.QualificationEvidenceSHA256, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	return phaseReaderFixture{p, a, o, proof}
}

// Explicit fields avoid serializing the private fixture wrapper, whose members
// deliberately remain package-local.
func (f phaseReaderFixture) copy(t *testing.T) phaseReaderFixture {
	t.Helper()
	copyValue := func(in, out any) {
		raw, err := json.Marshal(in)
		if err != nil || json.Unmarshal(raw, out) != nil {
			t.Fatal("copy fixture")
		}
	}
	var out phaseReaderFixture
	copyValue(f.p, &out.p)
	copyValue(f.a, &out.a)
	copyValue(f.o, &out.o)
	copyValue(f.proof, &out.proof)
	return out
}
func (f *phaseReaderFixture) registered(admitted bool) {
	f.a.State = "registered"
	f.a.NodeUID = f.o.Candidates[0].NodeUID
	entry := model.CapacityNativeWorkerRegistryEntry{NodeUID: f.a.NodeUID, ProviderID: f.a.Physical.ProviderID, Profile: f.a.Profile, PhysicalSpecSHA256: f.a.PhysicalSpecSHA256, RegistrationBindingSHA256: f.p.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA, CapacityPolicyID: f.a.PolicyID.String(), IntentGeneration: f.a.Generation, FencingToken: f.a.FencingToken, CreationProofSHA256: f.a.BirthSHA256, Admission: model.CapacityNativeWorkerRegistryAdmission{State: "quarantined"}}
	if admitted {
		entry.Admission = model.CapacityNativeWorkerRegistryAdmission{State: "admitted", ReceiptSHA256: marketTestSHA("4"), NetworkBindingSHA256: f.proof.NetworkBindingSHA256, WarmupEvidenceSHA256: f.proof.WarmupEvidenceSHA256, PhysicalQualificationSHA256: f.proof.PhysicalQualificationSHA256}
	}
	f.o.Registrations = []model.CapacityNativeWorkerRegistryEntry{entry}
	f.o.Candidates[0].Registrations = []model.CapacityNativeWorkerRegistryEntry{entry}
}
func phaseReaderPermitScope(f phaseReaderFixture, c model.CapacityNativeWorkerPhasePermit) model.CapacityNativeWorkerPhasePermit {
	c.PoolUID = f.p.NativeWorkerPoolBinding.PoolUID
	c.Owner = f.p.Owner
	c.Epoch = f.p.NativeWorkerPoolBinding.ExpectedPoolEpoch
	return c
}

func TestPhaseReaderHeaderAuthorityIsNotAZeroWorkerSnapshot(t *testing.T) {
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	f.registered(false)
	f.o.CandidateSelected = false
	f.o.RequestedProviderID = ""
	f.o.RequestedCreationProofSHA256 = ""
	f.o.Candidates = []model.CapacityNativeWorkerPhaseCandidate{}
	if err := NativeWorkerPhaseHeaderValid(f.p, f.o, now); err != nil {
		t.Fatal(err)
	}
	if len(f.o.Registrations) != 1 || f.o.UsefulCapacityQualified || f.o.MutationAuthorized {
		t.Fatal("header rewrote actual registry into capacity/authority")
	}
	f.o.CandidateAbsenceProven = true
	if NativeWorkerPhaseHeaderValid(f.p, f.o, now) == nil {
		t.Fatal("authority-only read pretended to prove absence")
	}
}
func TestPhaseReaderHeaderRequiresExactFreshSourceAndScope(t *testing.T) {
	now := time.Now().UTC()
	base := newPhaseReaderFixture(t, now)
	cases := []struct {
		name   string
		change func(*phaseReaderFixture)
	}{
		{"scope", func(f *phaseReaderFixture) { f.o.BindingScopeSHA256 = marketTestSHA("0") }}, {"source", func(f *phaseReaderFixture) { f.o.SourceCommit = strings.Repeat("0", 40) }},
		{"adapter", func(f *phaseReaderFixture) { f.o.Adapter.ManifestID = marketTestUUID(99) }}, {"epoch", func(f *phaseReaderFixture) { f.o.Registry.Epoch++ }},
		{"owner", func(f *phaseReaderFixture) { f.o.Registry.Owner = "other" }}, {"registry", func(f *phaseReaderFixture) { f.o.Registry.Ref.UID = marketTestUUID(99) }},
		{"partial_nodes", func(f *phaseReaderFixture) { f.o.FullCollectionComplete = false }}, {"partial_registry", func(f *phaseReaderFixture) { f.o.RegistryRegistrationsComplete = false }},
		{"stale", func(f *phaseReaderFixture) { f.o.ObservedAt = now.Add(-time.Minute) }}, {"future", func(f *phaseReaderFixture) { f.o.ObservedAt = now.Add(time.Minute) }},
		{"useful_claim", func(f *phaseReaderFixture) { f.o.UsefulCapacityQualified = true }}, {"mutation_claim", func(f *phaseReaderFixture) { f.o.MutationAuthorized = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base.copy(t)
			tc.change(&f)
			if NativeWorkerPhaseHeaderValid(f.p, f.o, now) == nil {
				t.Fatal("forged or stale header accepted")
			}
		})
	}
}
func TestPhaseReaderRegistrationJoinsStoredBirthAndOptionalClaims(t *testing.T) {
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	prep, err := PrepareNativeWorkerPhaseFromRead(f.p, f.a, "register", f.o, nil, now)
	if err != nil || prep.Context.Node.UID != f.o.Candidates[0].NodeUID || prep.Context.Node.ProviderID != f.a.Physical.ProviderID || prep.Context.Node.CreationProofSHA256 != f.a.BirthSHA256 || prep.NodeReady || prep.NetworkVerified || prep.WarmupVerified || prep.PhysicalQualified {
		t.Fatalf("register minted readiness or lost birth: %+v %v", prep, err)
	}
	fields := []struct {
		name   string
		change func(*model.CapacityNativeWorkerPhaseCandidate)
	}{
		{"profile", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.ProfileLabel = "other" }}, {"physical", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.PhysicalSpecSHA256Label = marketTestSHA("0") }},
		{"template", func(n *model.CapacityNativeWorkerPhaseCandidate) {
			n.RegistrationBindingSHA256Label = marketTestSHA("0")
		}}, {"policy", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.PolicyIDLabel = marketTestUUID(99) }},
		{"generation", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.GenerationLabel = "999" }}, {"fence", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.FencingTokenLabel = "999" }}, {"birth", func(n *model.CapacityNativeWorkerPhaseCandidate) { n.CreationProofSHA256Label = marketTestSHA("0") }},
	}
	for _, tc := range fields {
		t.Run(tc.name, func(t *testing.T) {
			bad := f.copy(t)
			tc.change(&bad.o.Candidates[0])
			if _, err := PrepareNativeWorkerPhaseFromRead(bad.p, bad.a, "register", bad.o, nil, now); err == nil {
				t.Fatal("mismatched actual optional claim accepted")
			}
		})
	}
}
func TestPhaseReaderCandidateRequiresFullPhysicalNodeAndOverlayJoin(t *testing.T) {
	now := time.Now().UTC()
	base := newPhaseReaderFixture(t, now)
	cases := []struct {
		name   string
		change func(*phaseReaderFixture)
	}{
		{"echo_only", func(f *phaseReaderFixture) { f.o.RequestedCreationProofSHA256 = marketTestSHA("0") }}, {"provider", func(f *phaseReaderFixture) { f.o.Candidates[0].ProviderID = "hcloud://other" }},
		{"known_node_uid", func(f *phaseReaderFixture) { f.a.NodeUID = marketTestUUID(99) }}, {"overlay", func(f *phaseReaderFixture) { f.o.Candidates[0].Addresses[0].Address = "10.81.0.99" }},
		{"conflicting_internal_ipv4", func(f *phaseReaderFixture) {
			f.o.Candidates[0].Addresses = append(f.o.Candidates[0].Addresses, model.CapacityNativeWorkerPhaseAddress{Type: "InternalIP", Address: "10.81.0.99"})
		}},
		{"duplicate_overlay", func(f *phaseReaderFixture) {
			f.o.Candidates[0].Addresses = append(f.o.Candidates[0].Addresses, f.o.Candidates[0].Addresses[0])
		}},
		{"malformed_internal_ip", func(f *phaseReaderFixture) {
			f.o.Candidates[0].Addresses = append(f.o.Candidates[0].Addresses, model.CapacityNativeWorkerPhaseAddress{Type: "InternalIP", Address: "not-an-ip"})
		}},
		{"quarantine_missing", func(f *phaseReaderFixture) { f.o.Candidates[0].Taints = nil }}, {"quarantine_wrong_owner", func(f *phaseReaderFixture) { f.o.Candidates[0].Taints[0].Value = marketTestUUID(99) }},
		{"quarantine_wrong_effect", func(f *phaseReaderFixture) { f.o.Candidates[0].Taints[0].Effect = "PreferNoSchedule" }}, {"deleting", func(f *phaseReaderFixture) { f.o.Candidates[0].Deleting = true }},
		{"physical_lifetime", func(f *phaseReaderFixture) { f.a.Physical.CreatedAt = now.Add(-time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base.copy(t)
			tc.change(&f)
			if _, err := PrepareNativeWorkerPhaseFromRead(f.p, f.a, "register", f.o, nil, now); err == nil {
				t.Fatal("candidate did not retain its exact physical/overlay/quarantine identity")
			}
		})
	}
	good := base.copy(t)
	good.o.Candidates[0].Addresses = append(good.o.Candidates[0].Addresses, model.CapacityNativeWorkerPhaseAddress{Type: "InternalIP", Address: "fd81::7"}, model.CapacityNativeWorkerPhaseAddress{Type: "ExternalIP", Address: "203.0.113.7"})
	if _, err := PrepareNativeWorkerPhaseFromRead(good.p, good.a, "register", good.o, nil, now); err != nil {
		t.Fatal("canonical dual-stack or unrelated external address refused", err)
	}
}
func TestPhaseReaderAdmissionRequiresActualReadinessAndPrivateProof(t *testing.T) {
	now := time.Now().UTC()
	base := newPhaseReaderFixture(t, now)
	base.registered(false)
	prep, err := PrepareNativeWorkerPhaseFromRead(base.p, base.a, "admit_registry", base.o, &base.proof, now)
	if err != nil || !prep.NodeReady || !prep.NetworkVerified || !prep.WarmupVerified || !prep.PhysicalQualified || prep.Context.Admission.NetworkBindingSHA256 != base.a.NetworkBindingSHA256 {
		t.Fatalf("genuine readiness did not bind %+v %v", prep, err)
	}
	cases := []struct {
		name   string
		change func(*phaseReaderFixture)
	}{
		{"not_ready", func(f *phaseReaderFixture) { f.o.Candidates[0].Ready = false }}, {"heartbeat", func(f *phaseReaderFixture) { f.o.Candidates[0].Heartbeat.Fresh = false }},
		{"allocatable", func(f *phaseReaderFixture) { f.o.Candidates[0].AllocatableMilliCPU = 1 }}, {"attempt", func(f *phaseReaderFixture) { f.proof.AttemptID = uuid.New() }},
		{"node", func(f *phaseReaderFixture) { f.proof.NodeUID = marketTestUUID(99) }}, {"overlay", func(f *phaseReaderFixture) { f.proof.WorkerIPv4 = "10.81.0.99" }},
		{"physical", func(f *phaseReaderFixture) { f.proof.Physical.ImageID = "other" }}, {"network", func(f *phaseReaderFixture) { f.proof.NetworkBindingSHA256 = marketTestSHA("0") }},
		{"warmup", func(f *phaseReaderFixture) { f.proof.WarmupEvidenceSHA256 = "" }}, {"expired", func(f *phaseReaderFixture) { f.proof.ValidUntil = now }},
		{"old_qualification", func(f *phaseReaderFixture) { f.a.QualificationValidUntil = now }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base.copy(t)
			tc.change(&f)
			if _, err := PrepareNativeWorkerPhaseFromRead(f.p, f.a, "admit_registry", f.o, &f.proof, now); err == nil {
				t.Fatal("unqualified readiness became admission")
			}
		})
	}
	for _, action := range []string{"admit_registry", "release_quarantine"} {
		if _, err := PrepareNativeWorkerPhaseFromRead(base.p, base.a, action, base.o, nil, now); err == nil {
			t.Fatal("missing private readiness was replaced by labels or Node Ready", action)
		}
	}
}
func TestPhaseReaderReleaseAndLateGETUseExactPersistedAdmission(t *testing.T) {
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	f.registered(true)
	prep, err := PrepareNativeWorkerPhaseFromRead(f.p, f.a, "release_quarantine", f.o, &f.proof, now)
	if err != nil {
		t.Fatal(err)
	}
	c := phaseReaderPermitScope(f, prep.Context)
	c.ExpiresAt = now.Add(-time.Hour)
	f.o.Candidates[0].Taints = []model.CapacityNativeWorkerPhaseTaint{{Key: "other.example/keep", Value: "same", Effect: "PreferNoSchedule"}}
	observed, err := ObserveNativeWorkerPhaseFromRead(f.p, c, f.o, now)
	if err != nil || !observed.Applied || !observed.QuarantineAbsent || !observed.Ready || observed.AdmissionReceiptSHA256 != f.o.Registrations[0].Admission.ReceiptSHA256 {
		t.Fatalf("late GET-only receiving lost genuine admission %+v %v", observed, err)
	}
	f.o.Registrations[0].Admission.WarmupEvidenceSHA256 = marketTestSHA("0")
	if _, err := ObserveNativeWorkerPhaseFromRead(f.p, c, f.o, now); err == nil {
		t.Fatal("late readback changed the originally permitted admission")
	}
}
func TestPhaseReaderConstructorKeepsOwnedPolicyAndHasNoReadinessFallback(t *testing.T) {
	now := time.Now().UTC()
	f := newPhaseReaderFixture(t, now)
	original := f.p.NativeWorkerLifecycleBinding.PhaseObserver.Name
	headers := 0
	reads := 0
	read := func(_ context.Context, b model.CapacityNativeWorkerPhaseReadBinding, provider, birth string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		if b.Name != original {
			t.Fatal("mutable caller policy retained")
		}
		out := f.o
		if provider == "" && birth == "" {
			headers++
			out.CandidateSelected = false
			out.CandidateAbsenceProven = false
			out.RequestedProviderID = ""
			out.RequestedCreationProofSHA256 = ""
			out.Candidates = []model.CapacityNativeWorkerPhaseCandidate{}
		} else {
			reads++
			if provider != f.a.Physical.ProviderID || birth != f.a.BirthSHA256 {
				t.Fatal("callback selected another birth")
			}
		}
		return out, nil
	}
	reader, err := NewNativeWorkerPhaseReader(f.p, read, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.p.NativeWorkerLifecycleBinding.PhaseObserver.Name = "mutated-after-construction"
	if _, err := reader.ObservePhaseAuthority(context.Background(), model.Manifest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PreparePhase(context.Background(), f.a, "register"); err != nil {
		t.Fatal(err)
	}
	f.registered(false)
	if _, err := reader.PreparePhase(context.Background(), f.a, "admit_registry"); err == nil {
		t.Fatal("nil readiness callback fabricated network/warmup")
	}
	if headers != 1 || reads != 2 {
		t.Fatalf("unexpected read callback calls %d/%d", headers, reads)
	}
	if _, err := NewNativeWorkerPhaseReader(f.p, nil, nil); err == nil {
		t.Fatal("missing protected read callback accepted")
	}
}

func TestPhaseReaderBindingCannotBorrowMutationOrPricingInstances(t *testing.T) {
	now := time.Now().UTC()
	base := newPhaseReaderFixture(t, now)
	for _, role := range []string{"execution", "registry_writer", "pricing"} {
		t.Run(role, func(t *testing.T) {
			f := base.copy(t)
			switch role {
			case "execution":
				f.p.NativeWorkerLifecycleBinding.PhaseObserver.Adapter = f.p.NativeWorkerLifecycleBinding.Profiles[0].Adapter
			case "registry_writer":
				f.p.NativeWorkerLifecycleBinding.PhaseObserver.Adapter = f.p.NativeWorkerLifecycleBinding.RegistryWriter.Adapter
			case "pricing":
				f.p.NativeWorkerLifecycleBinding.PhaseObserver.Adapter = f.p.MarketBinding.Profiles[0].Adapter
			}
			if ValidateNativeWorkerPhaseReadBinding(f.p) == nil {
				t.Fatal("read-only phase binding borrowed another authority", role)
			}
		})
	}
}
