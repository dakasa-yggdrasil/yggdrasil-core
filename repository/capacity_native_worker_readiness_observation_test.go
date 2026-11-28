package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These are synthetic independent read projections only. The fixture does not
// run a provider, claim PhysicalValid, create a Birth or qualify network/warmup.
type readinessObservationTestFixture struct {
	run          nativeReadinessRun
	attempt      model.CapacityNativeWorkerAttempt
	pins         nativeReadinessObservationPins
	pod, service model.NativeWorkerProbeResourceObservation
	now          time.Time
}

func readinessObservationTestSHA(c string) string { return strings.Repeat(c, 64) }
func readinessObservationTestID(n string) string  { return "12345678-1234-4234-8234-123456789a" + n }
func readinessObservationTestSeal(t *testing.T, o *model.NativeWorkerProbeResourceObservation) {
	t.Helper()
	o.EvidenceSHA256 = ""
	sha, e := nativeReadinessDigest(*o)
	if e != nil {
		t.Fatal(e)
	}
	o.EvidenceSHA256 = sha
}
func readinessObservationTestCopy(t *testing.T, o model.NativeWorkerProbeResourceObservation) model.NativeWorkerProbeResourceObservation {
	t.Helper()
	raw, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	var out model.NativeWorkerProbeResourceObservation
	if e = json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func readinessObservationTestFixtureFor(t *testing.T) readinessObservationTestFixture {
	t.Helper()
	now := time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)
	created := now.Add(-10 * time.Second)
	run := nativeReadinessRun{ID: uuid.MustParse(readinessObservationTestID("01")), CreatedAt: created, NotAfter: now.Add(time.Minute), Identity: nativeReadinessRunIdentity{AttemptID: uuid.MustParse(readinessObservationTestID("02"))}}
	attempt := model.CapacityNativeWorkerAttempt{ID: run.Identity.AttemptID, PolicyID: uuid.MustParse(readinessObservationTestID("03")), NodeUID: readinessObservationTestID("04"), PoolEpoch: 7, Profile: "candidate", PhysicalSpecSHA256: readinessObservationTestSHA("5"), BirthSHA256: readinessObservationTestSHA("6"), Generation: 8, FencingToken: 9, Physical: &model.CapacityNativeWorkerPhysical{ProviderID: "aws:///us-east-1a/i-0123456789abcdef0"}}
	pins := nativeReadinessObservationPins{Binding: model.CapacityNativeWorkerReadinessBinding{Namespace: "diagnostic-ci", NamespaceUID: readinessObservationTestID("05"), ProbeImage: "example.invalid/probe@sha256:" + readinessObservationTestSHA("1"), CoreWorkerImage: "example.invalid/core@sha256:" + readinessObservationTestSHA("3"), ResourceReader: model.CapacityNativeWorkerProbeResourceBinding{Name: "diagnostic-reader", SourceCommit: strings.Repeat("b", 40), ScopeSHA256: readinessObservationTestSHA("8"), Adapter: model.CapacityMarketAdapterBinding{ManifestID: readinessObservationTestID("06"), Version: 2, Checksum: readinessObservationTestSHA("a"), IntegrationTypeID: readinessObservationTestID("07"), TypeChecksum: readinessObservationTestSHA("b")}}}, ProbeContainerName: "probe", CoreContainerName: "core", ProbeRuntimeDigests: []string{"sha256:" + readinessObservationTestSHA("2")}, CoreRuntimeDigests: []string{"sha256:" + readinessObservationTestSHA("4")}, FloorName: "floor", FloorUID: readinessObservationTestID("08"), FloorProviderID: "hcloud://123456", RegistryUID: readinessObservationTestID("09"), RegistrationBindingSHA256: readinessObservationTestSHA("7"), PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", MaxAge: 30 * time.Second}
	podName, _, _ := nativeReadinessSlot(run, "candidate_pod")
	started := created.Add(time.Second)
	probe := model.NativeWorkerProbeContainerObservation{Name: pins.ProbeContainerName, ContainerID: "containerd://actual-probe", Image: pins.Binding.ProbeImage, ImageID: "containerd://" + pins.ProbeRuntimeDigests[0], StartedAt: started, Running: true}
	core := model.NativeWorkerProbeContainerObservation{Name: pins.CoreContainerName, ContainerID: "containerd://actual-core", Image: pins.Binding.CoreWorkerImage, ImageID: "example.invalid/core@" + pins.CoreRuntimeDigests[0], StartedAt: started, Running: true, Ready: true}
	pod := model.NativeWorkerProbeResourceObservation{Schema: model.NativeWorkerProbeResourceObservationSchema, SourceCommit: pins.Binding.ResourceReader.SourceCommit, BindingScopeSHA256: pins.Binding.ResourceReader.ScopeSHA256, Adapter: pins.Binding.ResourceReader.Adapter, BindingName: pins.Binding.ResourceReader.Name, RunID: run.ID.String(), AttemptID: run.Identity.AttemptID.String(), Slot: "candidate_pod", ObservedAt: now.Add(-time.Second), HTTPStatus: 200, ReadComplete: true, Found: true, Namespace: model.NativeWorkerProbeResourceIdentity{APIVersion: "v1", Kind: "Namespace", Name: pins.Binding.Namespace, UID: pins.Binding.NamespaceUID, ResourceVersion: "10", CreatedAt: created.Add(-time.Hour)}, Resource: model.NativeWorkerProbeResourceIdentity{APIVersion: "v1", Kind: "Pod", Namespace: pins.Binding.Namespace, Name: podName, UID: readinessObservationTestID("10"), ResourceVersion: "11", CreatedAt: created}, Pod: &model.NativeWorkerProbePodObservation{Phase: "Running", PodIPv4: "10.42.1.9", NodeName: "candidate-node", ContainerName: probe.Name, ContainerID: probe.ContainerID, Image: probe.Image, ImageID: probe.ImageID, StartedAt: probe.StartedAt, Running: true, Containers: []model.NativeWorkerProbeContainerObservation{probe, core}}, Node: &model.NativeWorkerProbeNodeObservation{Name: "candidate-node", UID: attempt.NodeUID, ResourceVersion: "20", ProviderID: attempt.Physical.ProviderID, RegistrationFound: true, RegistrationEpoch: attempt.PoolEpoch, Profile: attempt.Profile, PhysicalSpecSHA256: attempt.PhysicalSpecSHA256, RegistrationBindingSHA256: pins.RegistrationBindingSHA256, CapacityPolicyID: attempt.PolicyID.String(), IntentGeneration: attempt.Generation, FencingToken: attempt.FencingToken, CreationProofSHA256: attempt.BirthSHA256, RegistryUID: pins.RegistryUID, RegistryResourceVersion: "21"}, EndpointSlices: []model.NativeWorkerProbeEndpointSlice{}}
	readinessObservationTestSeal(t, &pod)
	service := readinessObservationTestCopy(t, pod)
	service.Slot = "candidate_service"
	serviceName, _, _ := nativeReadinessSlot(run, service.Slot)
	service.Resource.Kind = "Service"
	service.Resource.Name = serviceName
	service.Resource.UID = readinessObservationTestID("11")
	service.Pod = nil
	service.Node = nil
	service.EndpointSlicesComplete = true
	service.EndpointSliceCollectionResourceVersion = "30"
	service.Service = &model.NativeWorkerProbeServiceObservation{ClusterIPv4: "10.43.1.9", Type: "ClusterIP", SelectorRunID: run.ID.String(), SelectorSlot: "candidate_pod", Ports: []model.NativeWorkerProbeServicePort{{Name: "probe-udp", Protocol: "UDP", Port: 9446, TargetPort: "9446"}}}
	// EndpointSlice.EndpointPort has no targetPort; the normal Kubernetes
	// controller also omits ObjectReference.APIVersion for a Pod target.
	no := false
	service.EndpointSlices = []model.NativeWorkerProbeEndpointSlice{{Name: serviceName + "-native", UID: readinessObservationTestID("12"), ResourceVersion: "31", AddressType: "IPv4", OwnerServiceUID: service.Resource.UID, Ports: []model.NativeWorkerProbeServicePort{{Name: "probe-udp", Protocol: "UDP", Port: 9446}}, Endpoints: []model.NativeWorkerProbeEndpoint{{Addresses: []string{pod.Pod.PodIPv4}, Ready: &no, Serving: &no, Terminating: &no, NodeName: pod.Pod.NodeName, TargetKind: "Pod", TargetNamespace: pins.Binding.Namespace, TargetName: pod.Resource.Name, TargetUID: pod.Resource.UID}}}}
	readinessObservationTestSeal(t, &service)
	return readinessObservationTestFixture{run, attempt, pins, pod, service, now}
}

func TestNativeReadinessActualObservationHeaderBindsCurrentSourceAndOriginalUID(t *testing.T) {
	f := readinessObservationTestFixtureFor(t)
	if e := nativeReadinessObservationHeader(f.run, f.pins, f.pod, "candidate_pod", f.pod.Resource.UID, f.now); e != nil {
		t.Fatal("synthetic read baseline invalid", e)
	}
	cases := map[string]func(*model.NativeWorkerProbeResourceObservation){"source": func(o *model.NativeWorkerProbeResourceObservation) { o.SourceCommit = strings.Repeat("c", 40) }, "scope": func(o *model.NativeWorkerProbeResourceObservation) {
		o.BindingScopeSHA256 = readinessObservationTestSHA("9")
	}, "adapter": func(o *model.NativeWorkerProbeResourceObservation) { o.Adapter.Version++ }, "namespace_uid": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Namespace.UID = readinessObservationTestID("90")
	}, "namespace_rv_missing": func(o *model.NativeWorkerProbeResourceObservation) { o.Namespace.ResourceVersion = "" }, "namespace_deleting": func(o *model.NativeWorkerProbeResourceObservation) { o.Namespace.Deleting = true }, "attempt": func(o *model.NativeWorkerProbeResourceObservation) { o.AttemptID = readinessObservationTestID("91") }, "run": func(o *model.NativeWorkerProbeResourceObservation) { o.RunID = readinessObservationTestID("92") }, "uid": func(o *model.NativeWorkerProbeResourceObservation) { o.Resource.UID = readinessObservationTestID("93") }, "resource_namespace": func(o *model.NativeWorkerProbeResourceObservation) { o.Resource.Namespace = "foreign" }, "incomplete": func(o *model.NativeWorkerProbeResourceObservation) { o.ReadComplete = false }, "mutation_authority": func(o *model.NativeWorkerProbeResourceObservation) { o.MutationAuthorized = true }, "fake_readiness": func(o *model.NativeWorkerProbeResourceObservation) { o.ReadinessQualified = true }, "fake_absence": func(o *model.NativeWorkerProbeResourceObservation) { o.AbsenceProven = true }, "future": func(o *model.NativeWorkerProbeResourceObservation) { o.ObservedAt = f.now.Add(time.Nanosecond) }, "stale_boundary": func(o *model.NativeWorkerProbeResourceObservation) { o.ObservedAt = f.now.Add(-f.pins.MaxAge) }, "predates_run": func(o *model.NativeWorkerProbeResourceObservation) {
		o.ObservedAt = f.run.CreatedAt.Add(-time.Nanosecond)
	}, "resource_predates_run": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Resource.CreatedAt = f.run.CreatedAt.Add(-time.Second)
	}}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := readinessObservationTestCopy(t, f.pod)
			change(&o)
			readinessObservationTestSeal(t, &o)
			if nativeReadinessObservationHeader(f.run, f.pins, o, "candidate_pod", f.pod.Resource.UID, f.now) == nil {
				t.Fatal("coherently hashed foreign read accepted")
			}
		})
	}
	bad := readinessObservationTestCopy(t, f.pod)
	bad.Resource.ResourceVersion = "new"
	if nativeReadinessObservationHeader(f.run, f.pins, bad, "candidate_pod", f.pod.Resource.UID, f.now) == nil {
		t.Fatal("unretained raw projection mutation accepted")
	}
	absent := readinessObservationTestCopy(t, f.pod)
	absent.Found = false
	absent.HTTPStatus = 404
	absent.AttemptID = ""
	absent.Resource.UID = ""
	absent.Resource.ResourceVersion = ""
	absent.Pod = nil
	absent.Node = nil
	readinessObservationTestSeal(t, &absent)
	if nativeReadinessObservationHeader(f.run, f.pins, absent, "candidate_pod", f.pod.Resource.UID, f.now) != nil || absent.AbsenceProven {
		t.Fatal("fresh404 is not preserved as only a read result")
	}
	if nativeReadinessObservationHeader(f.run, f.pins, absent, "candidate_pod", "", f.now) == nil {
		t.Fatal("404 without original journal UID accepted")
	}
}

func TestNativeReadinessActualPodRequiresBirthAndPublishedRuntimeChildren(t *testing.T) {
	f := readinessObservationTestFixtureFor(t)
	if e := nativeReadinessPod(f.run, f.attempt, f.pins, f.pod, "candidate", true); e != nil {
		t.Fatal("actual candidate shape baseline invalid", e)
	}
	cases := map[string]func(*model.NativeWorkerProbeResourceObservation){"foreign_node_uid": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.UID = readinessObservationTestID("90") }, "provider": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Node.ProviderID = "aws:///other-zone/i-0123456789abcdef0"
	}, "epoch": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.RegistrationEpoch++ }, "registry": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Node.RegistryUID = readinessObservationTestID("91")
	}, "registration_binding": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Node.RegistrationBindingSHA256 = readinessObservationTestSHA("9")
	}, "birth": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Node.CreationProofSHA256 = readinessObservationTestSHA("a")
	}, "generation": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.IntentGeneration++ }, "fence": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.FencingToken++ }, "policy": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Node.CapacityPolicyID = readinessObservationTestID("92")
	}, "profile": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.Profile = "foreign" }, "unregistered": func(o *model.NativeWorkerProbeResourceObservation) { o.Node.RegistrationFound = false }, "node_assignment": func(o *model.NativeWorkerProbeResourceObservation) { o.Pod.NodeName = "other" }, "wrong_pod_cidr": func(o *model.NativeWorkerProbeResourceObservation) { o.Pod.PodIPv4 = "10.43.1.9" }, "index_is_not_child": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Pod.ImageID = f.pins.Binding.ProbeImage
		o.Pod.Containers[0].ImageID = o.Pod.ImageID
	}, "probe_restart": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Pod.RestartCount = 1
		o.Pod.Containers[0].RestartCount = 1
	}, "core_restart": func(o *model.NativeWorkerProbeResourceObservation) { o.Pod.Containers[1].RestartCount = 1 }, "core_wrong_image": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Pod.Containers[1].Image = "example.invalid/core:latest"
	}, "core_not_ready": func(o *model.NativeWorkerProbeResourceObservation) { o.Pod.Containers[1].Ready = false }, "extra_sidecar": func(o *model.NativeWorkerProbeResourceObservation) {
		c := o.Pod.Containers[0]
		c.Name = "unreviewed"
		o.Pod.Containers = append(o.Pod.Containers, c)
	}, "duplicate_container": func(o *model.NativeWorkerProbeResourceObservation) { o.Pod.Containers[1] = o.Pod.Containers[0] }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := readinessObservationTestCopy(t, f.pod)
			change(&o)
			if nativeReadinessPod(f.run, f.attempt, f.pins, o, "candidate", true) == nil {
				t.Fatal("unqualified actual Pod accepted")
			}
		})
	}
	waiting := readinessObservationTestCopy(t, f.pod)
	waiting.Pod.Containers[1].Ready = false
	if nativeReadinessPod(f.run, f.attempt, f.pins, waiting, "candidate", false) != nil {
		t.Fatal("initial probe before real Core warmup incorrectly requires final readiness")
	}
	floor := readinessObservationTestCopy(t, f.pod)
	floor.Pod.Containers = floor.Pod.Containers[:1]
	floor.Pod.NodeName = f.pins.FloorName
	floor.Node.Name = f.pins.FloorName
	floor.Node.UID = f.pins.FloorUID
	floor.Node.ProviderID = f.pins.FloorProviderID
	floor.Node.RegistrationFound = false
	if nativeReadinessPod(f.run, f.attempt, f.pins, floor, "floor", false) != nil {
		t.Fatal("exact protected floor refused")
	}
	floor.Node.UID = f.attempt.NodeUID
	if nativeReadinessPod(f.run, f.attempt, f.pins, floor, "floor", false) == nil {
		t.Fatal("candidate substituted for protected floor")
	}
}

func TestNativeReadinessActualServiceUsesRealEndpointSliceShapeAndSamePod(t *testing.T) {
	f := readinessObservationTestFixtureFor(t)
	if e := nativeReadinessObservationHeader(f.run, f.pins, f.service, "candidate_service", f.service.Resource.UID, f.now); e != nil {
		t.Fatal(e)
	}
	if e := nativeReadinessService(f.run, f.pins, f.service, f.pod, "candidate"); e != nil {
		t.Fatal("actual targetPort/APIVersion omissions refused", e)
	}
	explicit := readinessObservationTestCopy(t, f.service)
	explicit.EndpointSlices[0].Endpoints[0].TargetAPIVersion = "v1"
	if nativeReadinessService(f.run, f.pins, explicit, f.pod, "candidate") != nil {
		t.Fatal("explicit nativev1 target refused")
	}
	cases := map[string]func(*model.NativeWorkerProbeResourceObservation){"incomplete_pages": func(o *model.NativeWorkerProbeResourceObservation) { o.EndpointSlicesComplete = false }, "collection_rv": func(o *model.NativeWorkerProbeResourceObservation) { o.EndpointSliceCollectionResourceVersion = "" }, "wrong_service_cidr": func(o *model.NativeWorkerProbeResourceObservation) { o.Service.ClusterIPv4 = "10.42.1.9" }, "tcp_business": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Service.Ports[0].Protocol = "TCP"
		o.Service.Ports[0].Port = 9080
	}, "service_target_port": func(o *model.NativeWorkerProbeResourceObservation) { o.Service.Ports[0].TargetPort = "9080" }, "invented_slice_target_port": func(o *model.NativeWorkerProbeResourceObservation) { o.EndpointSlices[0].Ports[0].TargetPort = "9446" }, "foreign_owner": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].OwnerServiceUID = readinessObservationTestID("90")
	}, "wrong_run_selector": func(o *model.NativeWorkerProbeResourceObservation) {
		o.Service.SelectorRunID = readinessObservationTestID("91")
	}, "wrong_role": func(o *model.NativeWorkerProbeResourceObservation) { o.Service.SelectorSlot = "floor_pod" }, "target_namespace": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].TargetNamespace = "foreign"
	}, "target_uid": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].TargetUID = readinessObservationTestID("92")
	}, "target_name": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].TargetName = "foreign"
	}, "target_api": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].TargetAPIVersion = "apps/v1"
	}, "target_kind": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].TargetKind = "Deployment"
	}, "target_ip": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].Addresses[0] = "10.42.1.10"
	}, "target_node": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints[0].NodeName = "foreign"
	}, "extra_endpoint": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices[0].Endpoints = append(o.EndpointSlices[0].Endpoints, o.EndpointSlices[0].Endpoints[0])
	}, "extra_slice": func(o *model.NativeWorkerProbeResourceObservation) {
		o.EndpointSlices = append(o.EndpointSlices, o.EndpointSlices[0])
	}, "terminating": func(o *model.NativeWorkerProbeResourceObservation) {
		yes := true
		o.EndpointSlices[0].Endpoints[0].Terminating = &yes
	}}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := readinessObservationTestCopy(t, f.service)
			change(&o)
			if nativeReadinessService(f.run, f.pins, o, f.pod, "candidate") == nil {
				t.Fatal("coherent foreign endpoint accepted")
			}
		})
	}
	if f.service.EndpointSlices[0].Endpoints[0].Ready == nil || *f.service.EndpointSlices[0].Endpoints[0].Ready {
		t.Fatal("fixture replaced publishNotReady behavior with readiness proof")
	}
}

func TestNativeReadinessSamePodKeepsProcessLifetimeAcrossOpaqueRVs(t *testing.T) {
	f := readinessObservationTestFixtureFor(t)
	after := readinessObservationTestCopy(t, f.pod)
	after.Resource.ResourceVersion = "opaque-new"
	after.Namespace.ResourceVersion = "opaque-ns"
	after.Node.ResourceVersion = "opaque-node"
	after.Node.RegistryResourceVersion = "opaque-registry"
	after.Pod.Containers[1].Ready = false
	if !nativeReadinessSamePod(f.pod, after) {
		t.Fatal("RV/readiness change replaced stable process identity")
	}
	for _, field := range []string{"uid", "container_id", "restart", "started_at", "pod_ip", "provider", "registry", "birth"} {
		t.Run(field, func(t *testing.T) {
			o := readinessObservationTestCopy(t, after)
			switch field {
			case "uid":
				o.Resource.UID = readinessObservationTestID("90")
			case "container_id":
				o.Pod.Containers[1].ContainerID = "containerd://replacement"
			case "restart":
				o.Pod.Containers[1].RestartCount++
			case "started_at":
				o.Pod.Containers[1].StartedAt = o.Pod.Containers[1].StartedAt.Add(time.Second)
			case "pod_ip":
				o.Pod.PodIPv4 = "10.42.1.10"
			case "provider":
				o.Node.ProviderID = "aws:///foreign/i-0123456789abcdef0"
			case "registry":
				o.Node.RegistryUID = readinessObservationTestID("91")
			case "birth":
				o.Node.CreationProofSHA256 = readinessObservationTestSHA("9")
			}
			if nativeReadinessSamePod(f.pod, o) {
				t.Fatal("new process/lifetime became original initialization")
			}
		})
	}
}
