package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeHCloudPhysicalFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerPhysicalObservation, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	factory, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer factory.Close()
	a.Provider, a.Region, a.ProviderIDPrefix = "hetzner", "hel1", "hcloud://"
	a.Execution.DestroyCapability = "destroy_native_worker"
	factory.config.Execution = a.Execution
	factory.template.Provider = nativePrivateProvider{Kind: "hetzner", Region: "eu-central", Zone: "hel1", ImageID: "123456", NativeNetworkCIDR: "10.90.0.0/24"}
	prepared, err := factory.Prepare(a)
	if err != nil {
		t.Fatal(err)
	}
	a.LaunchSHA256, a.SourceCommit = nativePrivateSHA(prepared.PublicJSON), strings.Repeat("c", 40)
	a.State, a.PhysicalSpecSHA256, a.CreatedAt = "send_started", strings.Repeat("d", 64), now.Add(-5*time.Second)
	scope := &model.CapacityNativeWorkerHCloudProjectScope{DeclaredProjectID: "ci-reviewed-project", ProofKind: "reviewed_token_and_network_anchor_v1",
		AnchorID: "10", AnchorCreated: now.Add(-24 * time.Hour), AnchorOwnerLabelKey: "owner", AnchorOwnerLabelValue: "ci-native"}
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: a.Profile, Provider: "hetzner", Region: "hel1",
		Adapter:     model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 4, Checksum: strings.Repeat("5", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("6", 64)},
		BindingName: "ci-hcloud-independent-read", SourceCommit: strings.Repeat("7", 40), ScopeSHA256: strings.Repeat("8", 64), Capability: ObserveNativeWorkerPhysical, HCloudScope: scope}
	policy := model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: a.Profile, Provider: "hetzner", Region: "hel1"}},
		NativeWorkerLifecycleBinding: &model.CapacityNativeWorkerLifecycleBinding{SourceCommit: a.SourceCommit, MaxReadAgeSeconds: 30, Profiles: []model.CapacityNativeWorkerExecutionProfile{a.Execution}, PhysicalObservers: []model.CapacityNativeWorkerPhysicalReadBinding{b}},
		MarketBinding:                &model.CapacityMarketBinding{Profiles: []model.CapacityMarketProfileBinding{{Profile: a.Profile, Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString()}}}}}
	facts := model.CapacityNativeWorkerHCloudPhysicalFacts{ResourceID: "43210", ProviderID: "hcloud://43210", AccountID: "", InstanceType: "cpx32", NetworkID: "20",
		NativeNetworkCIDR: "10.90.0.0/24", CreatedAt: now.Add(-time.Second), ImageID: "123456", Region: "hel1", Zone: "hel1", NetworkZone: "eu-central",
		NativeIPv4: "10.90.0.8", MACAddress: "02:00:00:00:00:08", PhysicalSpecSHA256: a.PhysicalSpecSHA256, LaunchSHA256: a.LaunchSHA256}
	o := model.CapacityNativeWorkerHCloudPhysicalObservation{Schema: "hcloud_native_worker_physical_observation_v1", SourceCommit: b.SourceCommit, Adapter: b.Adapter,
		BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: facts.ResourceID, LaunchSHA256: a.LaunchSHA256},
		StartedAt: now.Add(-500 * time.Millisecond), ObservedAt: now.Add(-time.Millisecond), Complete: true, ProjectScope: *scope,
		ActualLabels:       model.CapacityNativeWorkerHCloudObservedLabels{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256Base32: nativeHCloudLaunchLabel(a.LaunchSHA256)},
		ActualLaunchSHA256: a.LaunchSHA256, ServerName: "nw-" + strings.ReplaceAll(a.ID.String(), "-", ""), InstanceState: "running", Physical: facts,
		RootStorage: model.CapacityNativeWorkerHCloudRootStorage{Kind: "server_local", SizeGiB: 20, ProviderEncryptionProven: false}, FirewallIDs: []string{"30"},
		TransportEndpointIPv4: "203.0.113.8", PrimaryIPs: []model.CapacityNativeWorkerHCloudObservedPrimaryIP{{ResourceID: "40", Type: "ipv4", IP: "203.0.113.8", AssigneeID: facts.ResourceID, AutoDelete: true}},
		Reads: []model.CapacityNativeWorkerHCloudObservedRPC{}}
	for i, op := range []string{"GET /networks/{id}", "GET /servers/{id}", "GET /networks/{id}", "GET /firewalls/{id}", "GET /primary_ips/{id}", "GET /servers/{id}", "GET /networks/{id}"} {
		o.Reads = append(o.Reads, model.CapacityNativeWorkerHCloudObservedRPC{Operation: op, HTTPStatus: 200, ObservedAt: now.Add(time.Duration(-100+i) * time.Millisecond)})
	}
	sealNativeHCloudFixture(&o)
	body, err := json.Marshal(map[string]any{
		"server": map[string]any{"id": 43210, "name": o.ServerName, "created": facts.CreatedAt,
			"labels":      map[string]string{"yggdrasil.io/native-worker-attempt": a.ID.String(), "dakasa.io/native-worker-pool": a.PoolUID, "yggdrasil.io/native-worker-launch-sha256": o.ActualLabels.LaunchSHA256Base32},
			"server_type": map[string]any{"id": 1, "name": facts.InstanceType}, "image": map[string]any{"id": 123456},
			"location":    map[string]any{"id": 2, "name": "hel1", "network_zone": "eu-central"},
			"private_net": []map[string]any{{"network": 20, "ip": facts.NativeIPv4, "mac_address": facts.MACAddress, "alias_ips": []string{}}}},
		"action":        map[string]any{"id": 987654, "command": "create_server", "status": "running", "error": nil, "resources": []map[string]any{{"type": "server", "id": 43210}}},
		"root_password": "CI-only-private-original-password-never-public", "next_actions": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(nativeHCloudOriginal{Schema: nativeHCloudOriginalSchema, AttemptID: a.ID.String(), HTTPStatus: 201, TransportCompleted: true, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return policy, a, prepared.PublicJSON, model.CapacityNativeWorkerOriginalReturn{Wire: wire, CaptureComplete: true}, model.CapacityNativeWorkerPhysicalObservation{HCloud: &o}, now
}

func sealNativeHCloudFixture(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
	o.EvidenceSHA256 = ""
	wire, _ := json.Marshal(o)
	o.EvidenceSHA256 = nativePrivateSHA(wire)
}

func resealNativeHCloudWitnessFixture(w *model.CapacityNativeWorkerHCloudWitness) {
	w.EvidenceSHA256 = ""
	wire, _ := json.Marshal(w)
	w.EvidenceSHA256 = nativePrivateSHA(wire)
}

func nativeHCloudFixtureACK(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerPhysicalObservation, model.CapacityNativeWorkerObservation, time.Time) {
	t.Helper()
	p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
	ack, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if err != nil {
		t.Fatalf("valid HCloud fixture refused: %v", err)
	}
	return p, a, launch, original, read, ack, now
}
