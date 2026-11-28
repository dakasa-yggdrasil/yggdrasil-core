package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Synthetic Kube projections exercise the actual producer callback/PG/control
// join. The actual TCP/mTLS sockets below are local to the CI runner; no VM,
// Kubernetes creation, real probe datagram or warmup proof is claimed.
func nativeReadinessControlObservations(t *testing.T, s *nativeReadinessProducerState, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun) map[string]model.NativeWorkerProbeResourceObservation {
	t.Helper()
	base := readinessObservationTestFixtureFor(t)
	s.config.ProbeContainerName, s.config.CoreWorkerTemplate.Name = "probe", "core"
	s.pins.ProbeContainerName, s.pins.CoreContainerName = "probe", "core"
	s.pins.ProbeRuntimeDigests = []string{"sha256:" + strings.Repeat("1", 64)}
	s.pins.CoreRuntimeDigests = []string{"sha256:" + strings.Repeat("2", 64)}
	s.pins.PodCIDR, s.pins.ServiceCIDR = "127.0.0.0/8", s.spec.NativeWorkerLifecycleBinding.Network.Template.ServiceCIDR
	s.pins.FloorName = s.spec.NativeWorkerLifecycleBinding.Network.Floor.NodeName
	s.pins.FloorUID = s.spec.NativeWorkerLifecycleBinding.Network.Floor.NodeUID
	s.pins.FloorProviderID = s.spec.NativeWorkerLifecycleBinding.Network.Floor.ProviderID
	s.pins.RegistryUID, s.pins.RegistrationBindingSHA256 = a.Registry.UID, s.spec.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA
	out := map[string]model.NativeWorkerProbeResourceObservation{}
	for i, role := range []string{"floor", "candidate"} {
		p := readinessObservationTestCopy(t, base.pod)
		p.SourceCommit, p.BindingScopeSHA256, p.Adapter, p.BindingName = s.config.Binding.ResourceReader.SourceCommit, s.config.Binding.ResourceReader.ScopeSHA256, s.config.Binding.ResourceReader.Adapter, s.config.Binding.ResourceReader.Name
		p.RunID, p.AttemptID, p.Slot = r.ID.String(), a.ID.String(), role+"_pod"
		p.Namespace.Name, p.Namespace.UID = s.config.Binding.Namespace, s.config.Binding.NamespaceUID
		p.Resource.Namespace = s.config.Binding.Namespace
		p.Resource.Name, _, _ = nativeReadinessSlot(r, p.Slot)
		p.Resource.UID, p.Resource.CreatedAt = uuid.NewString(), r.CreatedAt
		p.Pod.PodIPv4 = []string{"127.0.0.2", "127.0.0.3"}[i]
		p.Pod.Image, p.Pod.ImageID, p.Pod.StartedAt = s.config.Binding.ProbeImage, "containerd://"+s.pins.ProbeRuntimeDigests[0], r.CreatedAt
		p.Pod.ContainerID = "containerd://synthetic-probe-" + role
		p.Pod.Containers[0].Image, p.Pod.Containers[0].ImageID, p.Pod.Containers[0].StartedAt, p.Pod.Containers[0].ContainerID = p.Pod.Image, p.Pod.ImageID, p.Pod.StartedAt, p.Pod.ContainerID
		if role == "floor" {
			p.Pod.NodeName, p.Node.Name, p.Node.UID, p.Node.ProviderID = s.pins.FloorName, s.pins.FloorName, s.pins.FloorUID, s.pins.FloorProviderID
			p.Pod.Containers = p.Pod.Containers[:1]
		} else {
			p.Pod.NodeName, p.Node.Name, p.Node.UID, p.Node.ProviderID = "candidate-ci", "candidate-ci", a.NodeUID, a.Physical.ProviderID
			p.Node.RegistrationEpoch, p.Node.Profile, p.Node.PhysicalSpecSHA256, p.Node.RegistrationBindingSHA256 = a.PoolEpoch, a.Profile, a.PhysicalSpecSHA256, s.pins.RegistrationBindingSHA256
			p.Node.CapacityPolicyID, p.Node.IntentGeneration, p.Node.FencingToken, p.Node.CreationProofSHA256 = a.PolicyID.String(), a.Generation, a.FencingToken, a.BirthSHA256
			p.Node.RegistryUID = a.Registry.UID
			core := &p.Pod.Containers[1]
			core.Image, core.ImageID, core.StartedAt = s.config.Binding.CoreWorkerImage, "containerd://"+s.pins.CoreRuntimeDigests[0], r.CreatedAt
		}
		out[p.Slot] = p
		service := readinessObservationTestCopy(t, base.service)
		service.SourceCommit, service.BindingScopeSHA256, service.Adapter, service.BindingName = p.SourceCommit, p.BindingScopeSHA256, p.Adapter, p.BindingName
		service.RunID, service.AttemptID, service.Slot, service.Namespace = r.ID.String(), a.ID.String(), role+"_service", p.Namespace
		service.Resource.Namespace = s.config.Binding.Namespace
		service.Resource.Name, _, _ = nativeReadinessSlot(r, service.Slot)
		service.Resource.UID, service.Resource.CreatedAt = uuid.NewString(), r.CreatedAt
		service.Service.ClusterIPv4 = []string{"172.30.0.11", "172.30.0.12"}[i]
		service.Service.SelectorRunID, service.Service.SelectorSlot = r.ID.String(), p.Slot
		slice := &service.EndpointSlices[0]
		slice.OwnerServiceUID = service.Resource.UID
		x := &slice.Endpoints[0]
		x.Addresses, x.NodeName, x.TargetNamespace, x.TargetName, x.TargetUID = []string{p.Pod.PodIPv4}, p.Pod.NodeName, s.config.Binding.Namespace, p.Resource.Name, p.Resource.UID
		out[service.Slot] = service
	}
	return out
}

func nativeReadinessIdleFixture(c nativeworkerprobe.Config, configSHA string, key ed25519.PrivateKey) nativeworkerprobe.Report {
	return nativeworkerprobe.Report{Schema: nativeworkerprobe.ReportSchema, SourceCommit: c.SourceCommit, ConfigSHA256: configSHA, Identity: c.Identity, ObservedAt: time.Now().UTC(), HardNotAfter: c.HardNotAfter, SigningPublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Initial: nativeworkerprobe.BatchReport{State: "idle"}, Final: nativeworkerprobe.BatchReport{State: "idle"}}
}

func nativeReadinessControlPhaseHeader(s *nativeReadinessProducerState, a model.CapacityNativeWorkerAttempt, now time.Time) model.CapacityNativeWorkerPhaseReadObservation {
	o := phaseAuthorityTestHeader(s.spec)
	o.ObservedAt = now
	o.CandidateSelected, o.RequestedProviderID, o.RequestedCreationProofSHA256 = true, a.Physical.ProviderID, a.BirthSHA256
	o.Candidates = []model.CapacityNativeWorkerPhaseCandidate{{NodeName: "candidate-ci", NodeUID: a.NodeUID, NodeResourceVersion: "100", ProviderID: a.Physical.ProviderID, PoolUIDLabel: a.PoolUID, Ready: true, Heartbeat: model.CapacityNativeWorkerPhaseHeartbeat{Present: true, Fresh: true, UID: uuid.NewString(), ResourceVersion: "101", ObservedAt: now}, AllocatableKnown: true, AllocatableMilliCPU: 1000, AllocatableMemoryBytes: 1 << 30, Taints: []model.CapacityNativeWorkerPhaseTaint{{Key: "dakasa.io/native-worker-unadmitted", Value: a.PoolUID, Effect: "NoSchedule"}}, Addresses: []model.CapacityNativeWorkerPhaseAddress{{Type: "InternalIP", Address: a.OverlayIPv4}}}}
	o.Registrations = []model.CapacityNativeWorkerRegistryEntry{{NodeUID: a.NodeUID, ProviderID: a.Physical.ProviderID, Profile: a.Profile, PhysicalSpecSHA256: a.PhysicalSpecSHA256, RegistrationBindingSHA256: s.pins.RegistrationBindingSHA256, CapacityPolicyID: a.PolicyID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, CreationProofSHA256: a.BirthSHA256, Admission: model.CapacityNativeWorkerRegistryAdmission{State: "quarantined"}}}
	return o
}

func TestNativeReadinessControlIdleRequiresBothUntouchedBatchesAndOriginalIdentity(t *testing.T) {
	f, r, key, peer, now := nativeReadinessEvidenceFixture("floor")
	defer clear(key)
	defer clear(peer)
	sha := strings.Repeat("a", 64)
	good := nativeReadinessIdleFixture(f, sha, key)
	good.ObservedAt = now
	if !nativeReadinessIdleReport(f, sha, good, key.Public().(ed25519.PublicKey), r, good.ObservedAt) {
		t.Fatal("synthetic idle transport baseline invalid")
	}
	for _, fault := range []string{"source", "config", "identity", "birth_config", "expiry", "key", "stale", "future", "started", "completed", "sent", "received", "echoed", "running", "final_started", "final_packets", "error"} {
		t.Run(fault, func(t *testing.T) {
			x, config := good, f
			switch fault {
			case "source":
				x.SourceCommit = strings.Repeat("c", 40)
			case "config":
				x.ConfigSHA256 = strings.Repeat("b", 64)
			case "identity":
				x.Identity.PodUID = uuid.NewString()
			case "birth_config":
				config.Identity.BirthSHA256, x.Identity.BirthSHA256 = strings.Repeat("b", 64), strings.Repeat("b", 64)
			case "expiry":
				x.HardNotAfter = x.HardNotAfter.Add(time.Second)
			case "key":
				x.SigningPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "stale":
				x.ObservedAt = good.ObservedAt.Add(-5 * time.Second)
			case "future":
				x.ObservedAt = good.ObservedAt.Add(time.Nanosecond)
			case "started":
				x.Initial.StartedAt = &good.ObservedAt
			case "completed":
				x.Initial.CompletedAt = &good.ObservedAt
			case "sent":
				x.Initial.Sent = []nativeworkerprobe.DatagramRecord{{}}
			case "received":
				x.Initial.Received = []nativeworkerprobe.DatagramRecord{{}}
			case "echoed":
				x.Initial.Echoed = []nativeworkerprobe.DatagramRecord{{}}
			case "running":
				x.Initial.State = "running"
			case "final_started":
				x.Final.StartedAt = &good.ObservedAt
			case "final_packets":
				x.Final.Sent = []nativeworkerprobe.DatagramRecord{{}}
			case "error":
				x.Final.ErrorClass = "unknown"
			}
			if nativeReadinessIdleReport(config, sha, x, key.Public().(ed25519.PublicKey), r, good.ObservedAt) {
				t.Fatal("foreign/non-idle report consumed initial POST authority")
			}
		})
	}
}

func TestNativeReadinessPostgresTwoProofInvocationsYieldBeforePOSTAndResumeSameRun(t *testing.T) {
	_, a, p, r := nativeReadinessComposedFixture(t)
	s := p.state
	observations := nativeReadinessControlObservations(t, s, a, r)
	var err error
	r, err = s.journal.edit(t.Context(), r, nil, func(current *nativeReadinessRun, now time.Time) error {
		// Original already-observed synthetic Kube effects isolate only the
		// real callback/GET-ready handoff. No Kube mutation or proof is claimed.
		for _, slot := range []string{"network_policy", "admission_secret", "floor_pod", "candidate_pod", "floor_service", "candidate_service", "floor_secret", "candidate_secret"} {
			name, kind, _ := nativeReadinessSlot(*current, slot)
			nonce, sealed, e := s.journal.cryptPurpose(*current, "synthetic/observed/"+slot, nil, []byte("synthetic Kube effect only"), true)
			if e != nil {
				return e
			}
			uid := uuid.NewString()
			if o, ok := observations[slot]; ok {
				uid = o.Resource.UID
			}
			current.Effects = append(current.Effects, nativeReadinessEffect{Name: name, Kind: kind, State: "observed", UID: uid, ResourceVersion: "100", TemplateSHA256: strings.Repeat("a", 64), EvidenceSHA256: strings.Repeat("b", 64), ObservedAt: now, PrivateOriginal: &nativeReadinessCipher{Nonce: nonce, Ciphertext: sealed}})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rawKeys, err := s.journal.open(t.Context(), a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) {
		t.Fatal("resume generated another run key")
		return nil, errNativeReadinessRun
	})
	if err != nil {
		t.Fatal(err)
	}
	originalKeys := append([]byte(nil), rawKeys...)
	defer clear(originalKeys)
	keys, err := newNativeReadinessKeys(rawKeys)
	clear(rawKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.close()
	fc, cc, err := s.configs(r, keys, observations["floor_pod"], observations["candidate_pod"], observations["floor_service"], observations["candidate_service"])
	if err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	var gets, posts, earlyPosts atomic.Int32
	var sawFloorIdle, sawCandidateIdle atomic.Bool
	configSHAs := map[string]string{}
	for index, config := range []nativeworkerprobe.Config{fc, cc} {
		data, sha, err := keys.secret(r, config)
		if err != nil {
			t.Fatal(err)
		}
		configSHAs[config.Identity.Role] = sha
		for _, value := range data {
			clear(value)
		}
		cert, private, ca, err := keys.leaf(r, index+2, config.Identity.Role, config.Identity.PodIPv4)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(cert, private)
		clear(private)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("run CA")
		}
		key, err := keys.key(index + 4)
		if err != nil {
			t.Fatal(err)
		}
		var started atomic.Bool
		server := &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, ReadHeaderTimeout: time.Second}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Yggdrasil-Source-Commit", config.SourceCommit)
			w.Header().Set("Content-Type", "application/json")
			if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
				t.Error("actual control GET lacked mutual TLS")
			}
			if req.Method == http.MethodGet && req.URL.Path == nativeworkerprobe.ReportPath {
				gets.Add(1)
				if config.Identity.Role == "candidate" && !ready.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"pending":true}`))
					return
				}
				if config.Identity.Role == "floor" {
					sawFloorIdle.Store(true)
				} else {
					sawCandidateIdle.Store(true)
				}
			} else if req.Method == http.MethodPost && req.URL.Path == nativeworkerprobe.InitialPath {
				posts.Add(1)
				if !sawFloorIdle.Load() || !sawCandidateIdle.Load() || !ready.Load() {
					earlyPosts.Add(1)
				}
				started.Store(true)
				w.WriteHeader(http.StatusAccepted)
			} else {
				t.Error("unplanned control route")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			report := nativeReadinessIdleFixture(config, sha, key)
			if started.Load() {
				// This transport fixture intentionally has no real UDP producer.
				// Unknown prevents fabricated packet/startup/readiness evidence.
				report.Initial.State = "unknown"
			}
			_ = json.NewEncoder(w).Encode(report)
		})
		listener, err := net.Listen("tcp4", net.JoinHostPort(config.Identity.PodIPv4, "9446"))
		if err != nil {
			t.Fatal(err)
		}
		returned := make(chan error, 1)
		go func() { returned <- server.ServeTLS(listener, "", "") }()
		t.Cleanup(func() {
			_ = server.Close()
			<-returned
			clear(key)
			if private, ok := pair.PrivateKey.(ed25519.PrivateKey); ok {
				clear(private)
			}
		})
	}
	s.ports.Mutate = func(context.Context, model.CapacityNativeWorkerProbeResourceBinding, string, model.NativeWorkerProbeResourceInput) error {
		t.Fatal("resume recreated a diagnostic resource")
		return errNativeReadinessRun
	}
	s.ports.Read = func(_ context.Context, _ model.CapacityNativeWorkerProbeResourceBinding, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceObservation, error) {
		o := readinessObservationTestCopy(t, observations[in.Slot])
		o.ObservedAt = time.Now().UTC()
		readinessObservationTestSeal(t, &o)
		return o, nil
	}
	s.ports.Phase = func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, string, string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		return nativeReadinessControlPhaseHeader(s, a, time.Now().UTC()), nil
	}
	witness := func() model.CapacityNativeWorkerGuestWitness {
		return model.CapacityNativeWorkerGuestWitness{Schema: "native_worker_guest_network_witness_v1", AttemptID: a.ID.String(), LaunchSHA256: a.LaunchSHA256, BindingSHA256: a.Physical.PhysicalBindingSHA256, NetworkTemplateSHA256: s.spec.NativeWorkerLifecycleBinding.Network.TemplateSHA256, SystemSourceCommit: s.spec.NativeWorkerLifecycleBinding.Network.Template.GuestSystemSourceCommit, InterfaceName: "wg-dakasa", MTU: 1380, InterfaceUp: true, WorkerIPv4Present: true, FloorTLSVerified: true, ObservedAt: time.Now().UTC()}
	}
	short, stopShort := context.WithTimeout(t.Context(), nativeReadinessControlReturnReserve/2)
	before, err := s.awaitInitialControl(short, r, keys, fc, cc, configSHAs["floor"], configSHAs["candidate"])
	if !errors.Is(err, errNativeReadinessPending) || short.Err() != nil || before.Revision != r.Revision || gets.Load() != 0 || posts.Load() != 0 {
		stopShort()
		t.Fatal("insufficient return margin started WAN or canceled the parent", err)
	}
	stopShort()
	canceled, stopCanceled := context.WithCancel(t.Context())
	stopCanceled()
	if _, err := s.awaitInitialControl(canceled, r, keys, fc, cc, configSHAs["floor"], configSHAs["candidate"]); err == nil || errors.Is(err, errNativeReadinessPending) || gets.Load() != 0 {
		t.Fatal("original parent cancellation became a retryable voluntary yield")
	}
	first, cancel := context.WithTimeout(t.Context(), nativeReadinessControlReturnReserve+800*time.Millisecond)
	got, err := p.Proof(first, a, witness())
	if got != nil || !errors.Is(err, errNativeReadinessPending) || first.Err() != nil || posts.Load() != 0 {
		cancel()
		t.Fatal("first proof canceled its parent or consumed POST before both idle", err, posts.Load())
	}
	cancel()
	current, err := s.journal.read(t.Context(), a.ID)
	if err != nil || current.ID != r.ID || !current.NotAfter.Equal(r.NotAfter) || len(current.Effects) != 8 || current.PendingProof != nil || current.Proof != nil || len(current.Reads) == 0 {
		t.Fatal("voluntary yield changed original run or lost read custody", err)
	}
	ready.Store(true)
	for range 2 {
		next, stop := context.WithTimeout(t.Context(), nativeReadinessControlReturnReserve+4*time.Second)
		got, err = p.Proof(next, a, witness())
		stop()
		if got != nil || err == nil || posts.Load() != 2 || earlyPosts.Load() != 0 {
			t.Fatal("resume did not gate both first POSTs or repeated an exposed one", err, posts.Load(), earlyPosts.Load())
		}
	}
	current, resumedKeys, err := s.journal.open(t.Context(), a, func(uuid.UUID, time.Time, time.Time) ([]byte, error) {
		t.Fatal("later proof minted new identity")
		return nil, errNativeReadinessRun
	})
	defer clear(resumedKeys)
	if err != nil || current.ID != r.ID || !current.NotAfter.Equal(r.NotAfter) || string(resumedKeys) != string(originalKeys) || len(current.Effects) != 10 || current.Proof != nil {
		t.Fatal("second/third proof renewed lifetime, keys or readiness", err)
	}
	for _, slot := range []string{"floor_initial", "candidate_initial"} {
		i, ok := nativeReadinessEffectIndex(current, slot)
		if !ok || current.Effects[i].PrivateOriginal == nil || current.Effects[i].State != "received" {
			t.Fatal("first original POST not retained behind immutable barrier")
		}
	}
}

func TestNativeReadinessPostgresFreshReportCannotRenewFinalFramesAtPhaseConsumer(t *testing.T) {
	_, a, p, r := nativeReadinessComposedFixture(t)
	s := p.state
	s.pins.RegistrationBindingSHA256 = s.spec.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA
	// A coherent future instant is a pure consumer vector, not a fabricated
	// live read or a database clock override. Old final frames remain inside
	// the retained run, but outside the existing phase evidence age.
	now := r.CreatedAt.Add(60 * time.Second)
	floorStart, candidateStart := now.Add(-31*time.Second), now.Add(-32*time.Second)
	floor := nativeworkerprobe.Report{ObservedAt: now, Final: nativeworkerprobe.BatchReport{StartedAt: &floorStart}}
	candidate := nativeworkerprobe.Report{ObservedAt: now, Final: nativeworkerprobe.BatchReport{StartedAt: &candidateStart}}
	startup := nativeworkerprobe.StartupInspection{ObservedAt: now, AdmissionObservedAt: now.Add(-time.Second)}
	observed, err := nativeReadinessFinalObservedAt(model.CapacityNativeWorkerGuestWitness{ObservedAt: now}, floor, candidate, startup, model.NativeWorkerProbeResourceObservation{ObservedAt: now})
	if err != nil || !observed.Equal(candidateStart) {
		t.Fatal("fresh GET replaced original final-frame observation", err)
	}
	header := nativeReadinessControlPhaseHeader(s, a, now)
	proof := model.CapacityNativeWorkerReadinessProof{AttemptID: a.ID, NodeUID: a.NodeUID, ProviderID: a.Physical.ProviderID, WorkerIPv4: a.OverlayIPv4, BirthSHA256: a.BirthSHA256, Physical: *a.Physical, NetworkBindingSHA256: a.NetworkBindingSHA256, NetworkEvidenceSHA256: strings.Repeat("c", 64), WarmupEvidenceSHA256: strings.Repeat("d", 64), PhysicalQualificationSHA256: a.QualificationEvidenceSHA256, ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Second)}
	if _, err := capacity.PrepareNativeWorkerPhaseFromRead(s.spec, a, "admit_registry", header, &proof, now); err != nil {
		t.Fatal("otherwise complete same-birth consumer baseline invalid", err)
	}
	proof.ObservedAt = observed
	// Even a still-future parent/qualification expiry cannot turn old final
	// frames into fresh evidence at the actual existing phase consumer.
	if out, err := capacity.PrepareNativeWorkerPhaseFromRead(s.spec, a, "admit_registry", header, &proof, now); err == nil || out.NetworkVerified || out.WarmupVerified {
		t.Fatal("actual phase consumer accepted old frames behind a fresh report")
	}
	proof.ValidUntil = observed.Add(s.pins.MaxAge)
	if !proof.ValidUntil.Before(now) || !proof.ObservedAt.Equal(candidateStart) {
		t.Fatal("original evidence validity was renewed")
	}
	if _, err := nativeReadinessFinalObservedAt(model.CapacityNativeWorkerGuestWitness{ObservedAt: now}, nativeworkerprobe.Report{ObservedAt: now}, candidate, startup); err == nil {
		t.Fatal("missing original final start became proof time")
	}
}
