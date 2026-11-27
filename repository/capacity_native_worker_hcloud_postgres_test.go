package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This fixture drives the real JSONB child/original/birth stores against the
// isolated loopback CI database. Its runtime has no provider or mutation port.
func nativeHCloudRepositoryFixture(t *testing.T) (marketRepositoryFixture, CapacityNativeWorkerStore, *nativeHCloudRepositoryRuntime, model.CapacityNativeWorkerAuthority) {
	t.Helper()
	db := nativeAttemptDatabase(t)
	ctx := t.Context()
	now := time.Now().UTC()
	ns := "native-hcloud-" + uuid.NewString()
	create := func(kind, name string, spec any) model.Manifest {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	p := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "ci/native", Owner: "ci-owner", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale-api"}, Currency: "USD", Floor: 0, Ceiling: 10, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MinUnits: 0, MaxUnits: 10, ValidationRef: "ci/qualified", ValidationValidUntil: now.Add(time.Hour)}}}
	value := 0.9
	assessment := model.CapacityAssessment{Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	f := marketRepoFixtureOnDB(t, db, create("capacity_policy", "base", p), assessment)
	f.p.Profiles[0].Provider = "hetzner"
	f.p.MarketBinding.Profiles[0].Provider = "hetzner"
	f.p.NativeWorkerPoolBinding.Profiles[0].Provider = "hetzner"
	f.market.Profiles[0].Provider = "hetzner"
	adapter := func(name string) model.CapacityMarketAdapterBinding {
		typ := create("integration_type", name, map[string]any{"fixture": name})
		inst := create("integration_instance", name, map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
		return model.CapacityMarketAdapterBinding{ManifestID: inst.ID.String(), Version: inst.Version, Checksum: inst.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	}
	execution := model.CapacityNativeWorkerExecutionProfile{Profile: f.p.Profiles[0].Name, Adapter: adapter("hcloud-create"), BindingName: "ci-hcloud-create", SDKSourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("f", 64), EnsureCapability: "ensure_native_worker", ObserveCapability: "observe_native_worker", DestroyCapability: "destroy_native_worker", LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "ci/" + uuid.NewString(), OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}}
	read := model.CapacityNativeWorkerPhysicalReadBinding{Profile: execution.Profile, Provider: "hetzner", Region: "hel1", Adapter: adapter("hcloud-independent-read"), BindingName: "ci-hcloud-read", SourceCommit: strings.Repeat("7", 40), ScopeSHA256: strings.Repeat("8", 64), Capability: capacity.ObserveNativeWorkerPhysical,
		HCloudScope: &model.CapacityNativeWorkerHCloudProjectScope{DeclaredProjectID: "ci-reviewed-project", ProofKind: "reviewed_token_and_network_anchor_v1", AnchorID: "10", AnchorCreated: now.Add(-24 * time.Hour), AnchorOwnerLabelKey: "owner", AnchorOwnerLabelValue: "ci-native"}}
	f.p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{execution}, PhysicalObservers: []model.CapacityNativeWorkerPhysicalReadBinding{read}}
	f.policy = create("capacity_policy", "market", f.p)
	f.store.WorkflowID = create("workflow", f.p.Workflow.Name, map[string]any{"authorization": map[string]any{}}).ID
	proposal, err := f.store.Assess(ctx, f.policy, f.a)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.Claim(ctx, f.policy, proposal.Generation, f.a)
	if err != nil || claimed.MarketReservation == nil || claimed.MarketReservation.Units != 1 {
		t.Fatal("real market reservation missing", err)
	}
	runtime := &nativeHCloudRepositoryRuntime{db: db, policy: f.p, pool: f.pool}
	return f, CapacityNativeWorkerStore{Capacity: f.store, Runtime: runtime, Enabled: true}, runtime, model.CapacityNativeWorkerAuthority{Generation: claimed.Generation, FencingToken: claimed.FencingToken}
}

type nativeHCloudRepositoryRuntime struct {
	db           *sql.DB
	policy       model.CapacityPolicySpec
	pool         *model.CapacityNativeWorkerPoolObservation
	captures     int
	reads        int
	foreignScope bool
}

func (*nativeHCloudRepositoryRuntime) SourceCommit() string { return strings.Repeat("a", 40) }
func (r *nativeHCloudRepositoryRuntime) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	out := *r.pool
	out.ObservedAt = time.Now().UTC()
	return &out, nil
}

func nativeHCloudRepositoryJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func (*nativeHCloudRepositoryRuntime) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	// Canonical System Launch declaration order, with only CI fixture values.
	// No binary, cloud, private renderer or bootstrap material is invoked.
	q := nativeHCloudRepositoryJSON
	raw := fmt.Sprintf("{\"schema\":1,\"mode\":\"native_k3s_worker_v1\",\"source_commit\":%s,\"pool_id\":\"ci-workers\",\"pool_uid\":%s,\"registry\":%s,\"policy_id\":%s,\"policy_sha256\":%s,\"expected_pool_epoch\":%d,\"intent_generation\":%d,\"fencing_token\":%d,\"reservation_id\":%s,\"intent_sha256\":%s,\"provider\":{\"kind\":\"hetzner\",\"account_id\":\"\",\"region\":\"eu-central\",\"zone\":\"hel1\",\"image_id\":\"123456\",\"native_network_cidr\":\"10.90.0.0/24\"},\"floor\":{\"node_name\":\"ci-floor\",\"node_uid\":\"00000000-0000-4000-8000-000000000001\",\"provider_id\":\"hcloud://1\",\"cluster_uid\":\"00000000-0000-4000-8000-000000000002\",\"api_endpoint\":\"https://10.80.0.2:6443\",\"ca_sha256\":%s,\"node_network_cidr\":\"10.80.0.0/24\"},\"network\":{\"mode\":\"wireguard_routed_v1\",\"transport_cidr\":\"10.81.0.0/24\",\"worker_ipv4\":%s,\"floor_peer_ipv4\":\"10.81.0.2\",\"floor_peer_endpoint\":\"203.0.113.2:51820\",\"floor_peer_public_key\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\",\"worker_public_key\":\"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\",\"pod_cidr\":\"10.82.0.0/16\",\"service_cidr\":\"10.83.0.0/16\"},\"operator\":{\"source_commit\":%s,\"sha256\":%s,\"bytes\":12345,\"capability_ref\":\"native-private://operator-capability\",\"expected_hostname\":\"ci-fixture.s3.us-east-1.amazonaws.com\"},\"reserve\":{\"kube_milli_cpu\":100,\"kube_memory_mib\":128,\"system_milli_cpu\":100,\"system_memory_mib\":128,\"eviction_memory_mib\":128}}",
		q(a.Execution.BootstrapSourceCommit), q(a.PoolUID), q(a.Registry), q(a.PolicyID.String()), q(strings.TrimPrefix(a.PolicyChecksum, "sha256:")), a.PoolEpoch, a.Generation, a.FencingToken, q(a.ID.String()), q(a.IntentSHA256), q(strings.Repeat("d", 64)), q(a.OverlayIPv4), q(a.Execution.BootstrapSourceCommit), q(strings.Repeat("e", 64)))
	return model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: a.Execution.LaunchTemplateSHA256, PublicJSON: []byte(raw)}, nil
}

func nativeHCloudRepositoryLabel(launch string) string {
	raw, _ := hex.DecodeString(launch)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
}

func (r *nativeHCloudRepositoryRuntime) CaptureOriginalReturn(_ context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	r.captures++
	body, _ := json.Marshal(map[string]any{
		"server": map[string]any{"id": 43210, "name": "nw-" + strings.ReplaceAll(a.ID.String(), "-", ""), "created": a.CreatedAt,
			"labels":      map[string]string{"yggdrasil.io/native-worker-attempt": a.ID.String(), "dakasa.io/native-worker-pool": a.PoolUID, "yggdrasil.io/native-worker-launch-sha256": nativeHCloudRepositoryLabel(a.LaunchSHA256)},
			"server_type": map[string]any{"id": 1, "name": "cpx32"}, "image": map[string]any{"id": 123456}, "location": map[string]any{"id": 2, "name": "hel1", "network_zone": "eu-central"}},
		"action":        map[string]any{"id": 987654, "command": "create_server", "status": "running", "error": nil, "resources": []map[string]any{{"type": "server", "id": 43210}}},
		"root_password": "ci-private-original-password-never-in-birth"})
	wire, _ := json.Marshal(struct {
		Schema             string `json:"schema"`
		AttemptID          string `json:"attempt_id"`
		HTTPStatus         int    `json:"http_status"`
		RequestID          string `json:"request_id"`
		RequestIDObserved  bool   `json:"request_id_observed"`
		TransportCompleted bool   `json:"transport_completed"`
		Body               []byte `json:"body"`
	}{"hcloud_native_worker_original_return_v1", a.ID.String(), 201, "", false, true, body})
	return model.CapacityNativeWorkerOriginalReturn{Wire: wire, CaptureComplete: true}, nil
}

func (r *nativeHCloudRepositoryRuntime) read(a model.CapacityNativeWorkerAttempt, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest) model.CapacityNativeWorkerPhysicalObservation {
	r.reads++
	now := time.Now().UTC()
	o := model.CapacityNativeWorkerHCloudPhysicalObservation{Schema: "hcloud_native_worker_physical_observation_v1", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: request,
		StartedAt: now, ObservedAt: now, Complete: true, ProjectScope: *b.HCloudScope, ActualLabels: model.CapacityNativeWorkerHCloudObservedLabels{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256Base32: nativeHCloudRepositoryLabel(a.LaunchSHA256)}, ActualLaunchSHA256: a.LaunchSHA256,
		ServerName: "nw-" + strings.ReplaceAll(a.ID.String(), "-", ""), InstanceState: "running", TransportEndpointIPv4: "203.0.113.8",
		Physical:    model.CapacityNativeWorkerHCloudPhysicalFacts{ResourceID: "43210", ProviderID: "hcloud://43210", InstanceType: "cpx32", NetworkID: "20", NativeNetworkCIDR: "10.90.0.0/24", CreatedAt: a.CreatedAt, ImageID: "123456", Region: "hel1", Zone: "hel1", NetworkZone: "eu-central", NativeIPv4: "10.90.0.8", MACAddress: "02:00:00:00:00:08", PhysicalSpecSHA256: a.PhysicalSpecSHA256, LaunchSHA256: a.LaunchSHA256},
		RootStorage: model.CapacityNativeWorkerHCloudRootStorage{Kind: "server_local", SizeGiB: 20}, FirewallIDs: []string{"30"}, PrimaryIPs: []model.CapacityNativeWorkerHCloudObservedPrimaryIP{{ResourceID: "40", Type: "ipv4", IP: "203.0.113.8", AssigneeID: "43210", AutoDelete: true}},
		Reads: []model.CapacityNativeWorkerHCloudObservedRPC{}}
	for _, op := range []string{"GET /networks/{id}", "GET /servers/{id}", "GET /networks/{id}", "GET /firewalls/{id}", "GET /primary_ips/{id}", "GET /servers/{id}", "GET /networks/{id}"} {
		o.Reads = append(o.Reads, model.CapacityNativeWorkerHCloudObservedRPC{Operation: op, HTTPStatus: 200, ObservedAt: now})
	}
	raw, _ := json.Marshal(o)
	o.EvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	return model.CapacityNativeWorkerPhysicalObservation{HCloud: &o}
}

func (r *nativeHCloudRepositoryRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, raw model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	var count int
	if err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1 AND wire=$2", a.ID, raw.Wire).Scan(&count); err != nil || count != 1 {
		return model.CapacityNativeWorkerObservation{}, errors.New("independent HCloud read preceded committed original custody")
	}
	q, err := capacity.NewNativeWorkerACKQualifier(r.policy, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		return r.read(a, b, request), nil
	})
	if err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	launch, err := r.Prepare(a)
	if err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	out, err := q.QualifyACK(ctx, a, launch.PublicJSON, raw)
	if err == nil && r.foreignScope {
		// A self-consistent alternate reader is still not the policy's reader.
		out.HCloudWitness.Reader.ScopeSHA256 = strings.Repeat("9", 64)
		out.HCloudWitness.Observation.BindingScopeSHA256 = strings.Repeat("9", 64)
		out.HCloudWitness.Observation.EvidenceSHA256 = ""
		wire, _ := json.Marshal(out.HCloudWitness.Observation)
		out.HCloudWitness.Observation.EvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(wire))
		out.HCloudWitness.EvidenceSHA256 = ""
		wire, _ = json.Marshal(out.HCloudWitness)
		out.HCloudWitness.EvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(wire))
	}
	return out, err
}

func TestNativeHCloudBirthWitnessPersistsThroughTheActualPostgresRecord(t *testing.T) {
	f, store, runtime, authority := nativeHCloudRepositoryFixture(t)
	ctx := t.Context()
	a, err := store.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	a, err = store.Redeem(ctx, f.policy, authority, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	runtime.foreignScope = true
	if _, err = store.Record(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("self-consistent witness chose a reader outside the immutable policy pin")
	}
	var births int
	if err = f.db.QueryRowContext(ctx, "SELECT count(*) FROM public.capacity_native_worker_events WHERE attempt_id=$1 AND record ? 'birth'", a.ID).Scan(&births); err != nil || births != 0 {
		t.Fatal("refused reader still created a birth", err)
	}
	runtime.foreignScope = false
	sealed, err := store.Record(ctx, f.policy, authority, a.ID)
	if err != nil || sealed.State != "acknowledged" || sealed.Physical == nil || sealed.HCloudWitness == nil || !capacity.NativeWorkerPhysicalValid(sealed, *sealed.Physical) {
		t.Fatal("real HCloud witness failed the child store", err)
	}
	var attemptRaw, birthRaw []byte
	if err = f.db.QueryRowContext(ctx, "SELECT attempt FROM public.capacity_native_worker_attempts WHERE id=$1", a.ID).Scan(&attemptRaw); err != nil {
		t.Fatal(err)
	}
	if err = f.db.QueryRowContext(ctx, "SELECT record->'birth' FROM public.capacity_native_worker_events WHERE attempt_id=$1 AND record ? 'birth'", a.ID).Scan(&birthRaw); err != nil {
		t.Fatal(err)
	}
	var got model.CapacityNativeWorkerAttempt
	var birth model.CapacityNativeWorkerBirth
	if json.Unmarshal(attemptRaw, &got) != nil || json.Unmarshal(birthRaw, &birth) != nil || got.HCloudWitness == nil || birth.HCloudWitness == nil ||
		got.HCloudWitness.EvidenceSHA256 != birth.HCloudWitness.EvidenceSHA256 || !capacity.NativeWorkerHCloudWitnessBindingValid(f.p, got, birth.HCloudWitness) ||
		birth.OriginalRequestID != "" || birth.IndependentRequestID != "" || birth.Physical.AccountID != "" || birth.HCloudWitness.Acceptance.ActionID != "987654" {
		t.Fatal("JSONB roundtrip erased the typed witness or fabricated account/HTTP IDs")
	}
	canonical, _ := json.Marshal(birth)
	if fmt.Sprintf("%x", sha256.Sum256(canonical)) != got.BirthSHA256 {
		t.Fatal("immutable birth digest does not cover the complete safe witness")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = marketNativeAttemptBirthsTx(ctx, tx, f.policy, f.p, &model.CapacityNativeWorkerPoolObservation{Nodes: []model.CapacityNativeWorkerNode{{NodeUID: uuid.NewString(), ProviderID: sealed.Physical.ProviderID, Profile: sealed.Profile, CapacityPolicyID: sealed.PolicyID.String(), IntentGeneration: sealed.Generation, FencingToken: sealed.FencingToken, RegistrationReceiptSHA256: sealed.BirthSHA256}}})
	rollbackErr := tx.Rollback()
	if err != nil || rollbackErr != nil {
		t.Fatal("persisted HCloud witness could not join the real market child-birth reader", err, rollbackErr)
	}
	for _, forbidden := range []string{"ci-private-original-password-never-in-birth", "\"original_return\"", "\"body\"", "\"root_password\""} {
		if strings.Contains(string(attemptRaw), forbidden) || strings.Contains(string(birthRaw), forbidden) {
			t.Fatal("private original escaped into public typed evidence")
		}
	}
	if runtime.captures != 1 || runtime.reads != 2 {
		t.Fatal("read-only Record continuation recaptured or skipped the original/SDK join", runtime.captures, runtime.reads)
	}
	if _, err = store.Redeem(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("persisting a witness reopened the one-shot creation grant")
	}
}
