package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Actual PostgreSQL/manifest/parent/Attempt/command/journal fixture, with
// explicitly synthetic provider and Kubernetes SDK ports. Namespace "infra"
// matches the retained pool's real fixture namespace; no guard is rewritten to
// fit a different namespace. This does not qualify a Node, VM, path or warmup.
type nativeReadinessComposedOptions struct {
	NoOpen   bool
	QuoteTTL time.Duration
}

func nativeReadinessComposedFixture(t *testing.T, options ...nativeReadinessComposedOptions) (marketRepositoryFixture, model.CapacityNativeWorkerAttempt, *NativeWorkerReadinessProducer, nativeReadinessRun) {
	t.Helper()
	option := nativeReadinessComposedOptions{QuoteTTL: 300 * time.Second}
	if len(options) > 1 {
		t.Fatal("one closed fixture option required")
	}
	if len(options) == 1 {
		option = options[0]
		if option.QuoteTTL == 0 {
			option.QuoteTTL = 300 * time.Second
		}
	}
	db := nativeAttemptDatabase(t)
	now := time.Now().UTC()
	create := func(kind, name string, spec any) model.Manifest {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := CreateManifestVersion(t.Context(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: "infra", Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "ci/native", Owner: "ci-owner", Workflow: model.ManifestSelector{Namespace: "infra", Name: "scale-api"}, Currency: "USD", Floor: 0, Ceiling: 10, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 1, CooldownSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MaxUnits: 10, ValidationRef: "ci/qualified", ValidationValidUntil: now.Add(time.Hour)}}}
	value := .9
	f := marketRepoFixtureOnDB(t, db, create("capacity_policy", "base", p), model.CapacityAssessment{Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}})
	adapter := func(name string) model.CapacityMarketAdapterBinding {
		typeManifest := create("integration_type", name, map[string]any{"fixture": "separate synthetic SDK port"})
		instance := create("integration_instance", name, map[string]any{"type_ref": model.ManifestSelector{ManifestID: typeManifest.ID.String()}})
		return model.CapacityMarketAdapterBinding{ManifestID: instance.ID.String(), Version: instance.Version, Checksum: instance.Checksum, IntegrationTypeID: typeManifest.ID.String(), TypeChecksum: typeManifest.Checksum}
	}
	f.p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{{Profile: "hcloud", Adapter: adapter("native-provider"), BindingName: "ci-writer", SDKSourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("f", 64), EnsureCapability: "ensure_server", ObserveCapability: "observe_server", DestroyCapability: "destroy_server", LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "ci/" + uuid.NewString(), OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}, GuestIdentityPolicySHA256: strings.Repeat("1", 64)}}}
	phaseAuthorityTestBinding(&f.p)
	life, pool := f.p.NativeWorkerLifecycleBinding, f.p.NativeWorkerPoolBinding
	life.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: adapter("registry-writer"), BindingName: "ci-registry", PrincipalID: "ci-registry", SourceCommit: life.SourceCommit, ScopeSHA256: strings.Repeat("2", 64), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 30}
	floor := model.CapacityNativeWorkerNetworkFloorIdentity{NodeName: "ci-floor", NodeUID: uuid.NewString(), ProviderID: "hcloud://10000", ClusterUID: pool.RealmUID, CASHA256: strings.Repeat("3", 64), NativeIPv4: "10.70.1.2", NativeInterface: "enp7s0"}
	pool.ProtectedNodes = append(pool.ProtectedNodes, model.CapacityNativeProtectedNode{NodeUID: floor.NodeUID, ProviderID: floor.ProviderID})
	n := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: life.Profiles[0].BootstrapSourceCommit, Interface: "wg-dakasa", MTU: 1380, TransportCIDR: life.Profiles[0].OverlayCIDR, FloorPeerIPv4: "10.81.0.2", FloorPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: "172.29.0.0/16", ServiceCIDR: "172.30.0.0/16", ClusterDNSIPv4: "172.30.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
	life.Network = &model.CapacityNativeWorkerNetworkBinding{Mode: capacity.NativeWorkerNetworkMode, Writer: model.CapacityNativeWorkerNetworkWriterBinding{AdapterID: uuid.NewString(), PrincipalID: "ci-floor-writer", BindingName: "ci-floor-writer", SystemSourceCommit: n.GuestSystemSourceCommit, ScopeSHA256: strings.Repeat("4", 64)}, Reader: model.CapacityNativeWorkerNetworkReaderBinding{AdapterID: uuid.NewString(), BindingName: "ci-floor-reader", SystemSourceCommit: n.GuestSystemSourceCommit, ScopeSHA256: strings.Repeat("5", 64)}, Floor: floor, Template: n, TemplateSHA256: capacity.NativeWorkerNetworkTemplateSHA256(n), MaxPermitSeconds: 30}
	life.PhysicalObservers = []model.CapacityNativeWorkerPhysicalReadBinding{{Profile: f.p.Profiles[0].Name, Provider: f.p.Profiles[0].Provider, Region: f.p.Profiles[0].Region, Adapter: adapter("physical-reader"), BindingName: "ci-physical", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("6", 64), Capability: capacity.ObserveNativeWorkerPhysical}}
	b := model.CapacityNativeWorkerReadinessBinding{Mode: capacity.NativeWorkerReadinessMode, Name: "ci-readiness", Namespace: "infra", NamespaceUID: pool.RealmUID, ResourceWriter: model.CapacityNativeWorkerProbeResourceBinding{Adapter: adapter("probe-writer"), Name: "ci-probe-writer", PrincipalID: "ci-probe", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("7", 64)}, ResourceReader: model.CapacityNativeWorkerProbeResourceBinding{Adapter: adapter("probe-reader"), Name: "ci-probe-reader", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("8", 64)}, ProbeImage: "example.invalid/probe@sha256:" + strings.Repeat("a", 64), ProbeSourceCommit: life.SourceCommit, CoreWorkerImage: "example.invalid/core@sha256:" + strings.Repeat("b", 64), CoreWorkerSourceCommit: life.SourceCommit, StartupTemplateSHA256: strings.Repeat("c", 64)}
	life.ReadinessProducer = &b
	// Emit these synthetic collector/parent facts BEFORE Assess/Claim/reserve.
	// They model an explicit finite TTL accepted by both real collectors, not
	// a mutation/renewal of any previously issued command or permission.
	f.p.LeaseSeconds, f.p.MarketBinding.MaxQuoteAgeSeconds = 300, 300
	until := time.Now().UTC().Add(option.QuoteTTL)
	f.market.ValidUntil = until
	for i := range f.market.Profiles {
		q := &f.market.Profiles[i]
		q.ValidUntil = until
		q.Stock.ValidUntil, q.Registration.ValidUntil, q.Network.ValidUntil = until, until, until
		for j := range q.Quotas {
			q.Quotas[j].ValidUntil = until
		}
		for j := range q.Costs {
			if q.Costs[j].State == "known" {
				q.Costs[j].ValidUntil = until
			}
		}
	}
	if err := capacity.ValidatePolicy(f.p); err != nil {
		t.Fatal("composed fixture must satisfy the real complete policy validator", err)
	}
	f.policy = create("capacity_policy", "market", f.p)
	workflow := create("workflow", "scale-api", map[string]any{"authorization": map[string]any{}})
	f.store.WorkflowID = workflow.ID
	proposed, err := f.store.Assess(t.Context(), f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.Claim(t.Context(), f.policy, proposed.Generation, f.a)
	if err != nil {
		t.Fatal(err)
	}
	workers := CapacityNativeWorkerStore{Capacity: f.store, Runtime: &phaseAuthorityTestRuntime{nativeAttemptRuntime: &nativeAttemptRuntime{db: db, pool: f.pool}, header: phaseAuthorityTestHeader(f.p)}, Enabled: true}
	auth := model.CapacityNativeWorkerAuthority{Generation: claimed.Generation, FencingToken: claimed.FencingToken}
	a, err := workers.Reserve(t.Context(), f.policy, auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workers.Redeem(t.Context(), f.policy, auth, a.ID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"acknowledged", "registered"} {
		a, err = workers.Record(t.Context(), f.policy, auth, a.ID)
		if err != nil || a.State != state {
			t.Fatal("actual child ledger prerequisite", state, a.State, err)
		}
	}
	journal, err := newNativeReadinessRunJournal(db, f.policy, a.SourceCommit, strings.Repeat("9", 64), strings.Repeat("0", 64), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(journal.close)
	s := &nativeReadinessProducerState{running: map[uuid.UUID]bool{}, journal: journal, backend: nativeReadinessBackend{journal, b.ResourceWriter}, spec: f.p, config: nativeReadinessPrivateConfig{Binding: b}, pins: nativeReadinessObservationPins{Binding: b, MaxAge: 30 * time.Second}}
	var r nativeReadinessRun
	if !option.NoOpen {
		var keys []byte
		r, keys, err = journal.open(t.Context(), a, nativeReadinessGenerateKeys)
		clear(keys)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f, a, &NativeWorkerReadinessProducer{s}, r
}

func nativeReadinessComposedOriginal(t *testing.T, request model.NativeWorkerProbeResourceBootstrap, permit model.NativeWorkerProbeResourcePermit, created time.Time) model.NativeWorkerProbeResourceReceive {
	t.Helper()
	var wire map[string]any
	if err := json.Unmarshal(request.ObjectJSON, &wire); err != nil {
		t.Fatal(err)
	}
	meta := wire["metadata"].(map[string]any)
	meta["uid"], meta["resourceVersion"], meta["creationTimestamp"] = uuid.NewString(), "101", created.Truncate(time.Second).Format(time.RFC3339)
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return model.NativeWorkerProbeResourceReceive{BindingName: permit.Context.BindingName, RunID: permit.Context.RunID, Slot: permit.Context.Slot, SettlementToken: permit.SettlementToken, HTTPStatus: 201, CompletedAt: time.Now().UTC(), TransportCompleted: true, OriginalReturn: raw}
}

func nativeReadinessComposedAbsence(t *testing.T, s *nativeReadinessProducerState, r nativeReadinessRun, slot string) model.NativeWorkerProbeResourceObservation {
	t.Helper()
	name, kind, _ := nativeReadinessSlot(r, slot)
	api := "v1"
	if kind == "NetworkPolicy" {
		api = "networking.k8s.io/v1"
	}
	b := s.config.Binding
	o := model.NativeWorkerProbeResourceObservation{Schema: model.NativeWorkerProbeResourceObservationSchema, SourceCommit: b.ResourceReader.SourceCommit, BindingScopeSHA256: b.ResourceReader.ScopeSHA256, Adapter: b.ResourceReader.Adapter, BindingName: b.ResourceReader.Name, RunID: r.ID.String(), Slot: slot, ObservedAt: time.Now().UTC(), HTTPStatus: 404, ReadComplete: true, Namespace: model.NativeWorkerProbeResourceIdentity{APIVersion: "v1", Kind: "Namespace", Name: b.Namespace, UID: b.NamespaceUID, ResourceVersion: "90", CreatedAt: r.CreatedAt.Add(-time.Hour)}, Resource: model.NativeWorkerProbeResourceIdentity{APIVersion: api, Kind: kind, Namespace: b.Namespace, Name: name}}
	readinessObservationTestSeal(t, &o)
	return o
}

func TestNativeReadinessProducerPostgresRendererCallbacksCustodyAndUnknownNeverReplay(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		t.Run(fmt.Sprint("incomplete_", incomplete), func(t *testing.T) {
			f, a, p, r := nativeReadinessComposedFixture(t)
			s := p.state
			var sends, reads int
			var original model.NativeWorkerProbeResourceReceive
			s.ports.Mutate = func(ctx context.Context, b model.CapacityNativeWorkerProbeResourceBinding, op string, in model.NativeWorkerProbeResourceInput) error {
				sends++
				if b != s.config.Binding.ResourceWriter || op != capacity.EnsureNativeWorkerProbeResource || sends != 1 {
					t.Fatal("another capability/binding or repeated create")
				}
				before, err := p.Read(ctx, in)
				if err != nil || before.State != "requested" {
					t.Fatal("SDK invoked before durable private request", err)
				}
				bootstrap, err := p.Bootstrap(ctx, in)
				if err != nil || !strings.Contains(string(bootstrap.ObjectJSON), "admission.key") {
					t.Fatal("exact private renderer output unavailable before redeem", err)
				}
				permit, err := p.Redeem(ctx, in)
				if err != nil || permit.Context.State != "send_started" || !permit.Context.NotAfter.Equal(before.NotAfter) {
					t.Fatal("real one-send callback did not retain its context", err)
				}
				if _, err := p.Redeem(ctx, in); err == nil {
					t.Fatal("second redeem reopened authority")
				}
				original = nativeReadinessComposedOriginal(t, bootstrap, permit, r.CreatedAt)
				original.TransportCompleted = !incomplete
				if err := p.Receive(ctx, original); err != nil {
					t.Fatal("private original custody failed", err)
				}
				return errors.New("synthetic original SDK response lost after Core custody")
			}
			s.ports.Read = func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceObservation, error) {
				reads++
				return nativeReadinessComposedAbsence(t, s, r, "admission_secret"), nil
			}
			plan, err := s.plan(r, "admission_secret", "")
			if err != nil {
				t.Fatal(err)
			}
			plan.Data = map[string][]byte{"admission.key": []byte(strings.Repeat("private-pg-admission-only", 2))}
			next, err := s.ensure(t.Context(), a, r, plan, nil)
			if (err != nil) != incomplete {
				t.Fatal("custody-only completion became false observed or ignored qualified ACK", err)
			}
			r, err = s.journal.read(t.Context(), a.ID)
			if err != nil || len(r.Effects) != 1 || r.Effects[0].PrivateOriginal == nil {
				t.Fatal("original did not persist before projection", err)
			}
			if !incomplete {
				if next.ID != r.ID || r.Effects[0].State != "observed" || r.Effects[0].UID == "" {
					t.Fatal("qualified original did not select exact original identity")
				}
			} else if r.Effects[0].State != "received" || r.Effects[0].UID != "" {
				t.Fatal("incomplete original granted identity")
			}
			captured, err := s.journal.original(r, "admission_secret", false)
			want, marshalErr := original.MarshalPrivateJSON()
			if err != nil || marshalErr != nil || !bytes.Equal(captured, want) {
				t.Fatal("original bytes were replaced by interpretation")
			}
			clear(captured)
			clear(want)
			if err := p.Receive(t.Context(), original); err != nil {
				t.Fatal("identical original receiving did not deduplicate", err)
			}
			_, _ = s.ensure(t.Context(), a, r, plan, nil)
			if sends != 1 {
				t.Fatal("GET-only recovery repeated SDK create")
			}
			r, err = s.cleanup(t.Context(), a, r)
			if (err != nil) != incomplete || reads != map[bool]int{false: 1, true: 0}[incomplete] || sends != 1 {
				t.Fatal("unknown creation used 404 or repeated a mutation", err, reads, sends)
			}
			var ensured, destroyed int
			if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FILTER(WHERE type='kubernetes.native_worker_probe_resource.ensured'),count(*) FILTER(WHERE type='kubernetes.native_worker_probe_resource.destroyed') FROM public.event_log WHERE aggregate_id=$1`, r.ID.String()+"/admission_secret").Scan(&ensured, &destroyed); err != nil {
				t.Fatal(err)
			}
			if incomplete && (ensured != 0 || destroyed != 0) || !incomplete && (ensured != 1 || destroyed != 1 || r.Effects[0].State != "absent" || r.Effects[0].PrivateAbsence == nil) {
				t.Fatal("safe canonical event not atomic with actual qualification/independent absence")
			}
			var row []byte
			if err := f.db.QueryRowContext(t.Context(), `SELECT record FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1`, a.ID).Scan(&row); err != nil || bytes.Contains(row, []byte(original.SettlementToken)) || bytes.Contains(row, plan.Data["admission.key"]) || bytes.Contains(row, original.OriginalReturn) {
				t.Fatal("private original/request/token escaped encrypted journal", err)
			}
		})
	}
}

func TestNativeReadinessProducerPostgresPendingProofResumesCleanupWithoutNewPacketsOrClock(t *testing.T) {
	f, a, p, r := nativeReadinessComposedFixture(t)
	s := p.state
	var creates, reads int
	s.ports.Mutate = func(ctx context.Context, _ model.CapacityNativeWorkerProbeResourceBinding, op string, in model.NativeWorkerProbeResourceInput) error {
		creates++
		if op != capacity.EnsureNativeWorkerProbeResource || creates != 1 {
			t.Fatal("restart repeated diagnostic creation")
		}
		bootstrap, err := p.Bootstrap(ctx, in)
		if err != nil {
			return err
		}
		permit, err := p.Redeem(ctx, in)
		if err != nil {
			return err
		}
		return p.Receive(ctx, nativeReadinessComposedOriginal(t, bootstrap, permit, r.CreatedAt))
	}
	plan, err := s.plan(r, "admission_secret", "")
	if err != nil {
		t.Fatal(err)
	}
	plan.Data = map[string][]byte{"admission.key": []byte(strings.Repeat("private-pending-proof-key", 2))}
	r, err = s.ensure(t.Context(), a, r, plan, nil)
	if err != nil || len(r.Effects) != 1 || r.Effects[0].State != "observed" {
		t.Fatal("composed renderer/SDK callbacks/original qualification failed", err)
	}
	// Deliberately retained synthetic completed diagnostic effects isolate the
	// crash-after-seal path. They are NOT asserted to be real Kube objects,
	// packets, worker startup, provider evidence or a production readiness run.
	r, err = s.journal.edit(t.Context(), r, nil, func(current *nativeReadinessRun, now time.Time) error {
		for _, slot := range []string{"floor_pod", "candidate_pod", "floor_service", "candidate_service", "admission_secret", "floor_secret", "candidate_secret", "network_policy", "floor_initial", "candidate_initial", "floor_final", "candidate_final", "startup_challenge"} {
			if slot == "admission_secret" {
				continue // Preserve the actual composed Core-qualified original.
			}
			name, kind, _ := nativeReadinessSlot(*current, slot)
			nonce, sealed, err := s.journal.cryptPurpose(*current, "synthetic/completed/"+slot, nil, []byte("synthetic-retained-diagnostic-fixture"), true)
			if err != nil {
				return err
			}
			cipher := &nativeReadinessCipher{Nonce: nonce, Ciphertext: sealed}
			e := nativeReadinessEffect{Name: name, Kind: kind, TemplateSHA256: strings.Repeat("a", 64), State: "observed", EvidenceSHA256: strings.Repeat("b", 64), ObservedAt: now, PrivateOriginal: cipher}
			if nativeReadinessObjectKind(kind) {
				e.State, e.UID, e.ResourceVersion, e.PrivateAbsence = "absent", uuid.NewString(), "10", cipher
			}
			current.Effects = append(current.Effects, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := now.Add(4 * time.Second)
	for _, end := range []time.Time{r.NotAfter, a.QualificationValidUntil} {
		if end.Before(valid) {
			valid = end
		}
	}
	proof := model.CapacityNativeWorkerReadinessProof{AttemptID: a.ID, NodeUID: a.NodeUID, ProviderID: a.Physical.ProviderID, WorkerIPv4: a.OverlayIPv4, BirthSHA256: a.BirthSHA256, Physical: *a.Physical, NetworkBindingSHA256: a.NetworkBindingSHA256, NetworkEvidenceSHA256: strings.Repeat("c", 64), WarmupEvidenceSHA256: strings.Repeat("d", 64), PhysicalQualificationSHA256: a.QualificationEvidenceSHA256, ObservedAt: now, ValidUntil: valid}
	r, err = s.journal.sealProof(t.Context(), a, r, proof)
	if err != nil || r.PendingProof == nil {
		t.Fatal("same guarded PG seal path failed", err)
	}
	// No factory is configured. A resumed sealed proof may obtain fresh
	// independent cleanup GETs, but not guest/Node/Service readiness, SDK
	// creation, UDP/control or startup calls. First cleanup is deliberately
	// unavailable; the second invocation must preserve the SAME pending proof.
	s.ports.Mutate = func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, string, model.NativeWorkerProbeResourceInput) error {
		t.Fatal("sealed proof issued another mutation/packet")
		return errNativeReadinessRun
	}
	s.ports.Read = func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceObservation, error) {
		reads++
		if reads == 1 {
			return model.NativeWorkerProbeResourceObservation{}, errNativeReadinessRun
		}
		if reads != 2 {
			t.Fatal("already closed cleanup renewed an observation")
		}
		return nativeReadinessComposedAbsence(t, s, r, "admission_secret"), nil
	}
	s.ports.Phase = func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, string, string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		t.Fatal("sealed proof reobserved/reminted Node identity")
		return model.CapacityNativeWorkerPhaseReadObservation{}, errNativeReadinessRun
	}
	if got, err := p.Proof(t.Context(), a, model.CapacityNativeWorkerGuestWitness{}); err == nil || got != nil {
		t.Fatal("unknown cleanup became readiness")
	}
	held, err := s.journal.read(t.Context(), a.ID)
	if err != nil || held.Closed || held.Proof != nil || held.PendingProof == nil || !reflect.DeepEqual(held.PendingProof.value(), proof) {
		t.Fatal("cleanup failure lost or reminted the immutable pending proof", err)
	}
	var revision int64
	var closed nativeReadinessRun
	for range 3 { // same protected callback used by preparation/release/Record
		got, err := p.Proof(t.Context(), a, model.CapacityNativeWorkerGuestWitness{})
		if err != nil || got == nil || !reflect.DeepEqual(*got, proof) {
			t.Fatal("resume/phase/Record reminted evidence or its deadline", err)
		}
		current, err := s.journal.read(t.Context(), a.ID)
		if err != nil || !current.Closed || current.Proof == nil || !reflect.DeepEqual(*current.Proof, *current.PendingProof) {
			t.Fatal("sealed proof/cleanup not committed atomically", err)
		}
		if revision != 0 && current.Revision != revision {
			t.Fatal("read-only later phase rewrote the diagnostic lifetime")
		}
		revision = current.Revision
		closed = current
	}
	if creates != 1 || reads != 2 || closed.Effects[0].State != "absent" || closed.Effects[0].PrivateAbsence == nil {
		t.Fatal("composed cleanup did not retain the known original UID and fresh absence")
	}
	var events int
	if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.event_log WHERE aggregate_id=$1 AND type IN ('kubernetes.native_worker_probe_resource.ensured','kubernetes.native_worker_probe_resource.destroyed')`, r.ID.String()+"/admission_secret").Scan(&events); err != nil || events != 2 {
		t.Fatal("composed known-UID absence/event transaction did not complete once", err)
	}
	if _, err := nativeReadinessArchivedProof(closed, a, valid.Add(-time.Nanosecond)); err != nil {
		t.Fatal("closed archive lost its original pre-expiry validity", err)
	}
	if _, err := nativeReadinessArchivedProof(closed, a, valid); err == nil {
		t.Fatal("expiry boundary accepted as renewed readiness")
	}
	if _, err := f.db.ExecContext(t.Context(), `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, valid); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Proof(t.Context(), a, model.CapacityNativeWorkerGuestWitness{}); err == nil || got != nil {
		t.Fatal("expired archived proof became a fresh proof")
	}
	current, err := s.journal.read(t.Context(), a.ID)
	if err != nil || current.Revision != revision || !current.NotAfter.Equal(r.NotAfter) || !current.PendingProof.ValidUntil.Equal(valid) {
		t.Fatal("expiry reminted another run, timer or private identity", err)
	}
}
