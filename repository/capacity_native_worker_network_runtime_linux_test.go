//go:build linux && nativefactoryqualification

package repository

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only this dedicated CI job owns 10.80.0.2/32 on its isolated runner. The
// production constructors and their real fixed-IP TLS transports have NO dial
// override. Provider/floor facts below are explicit fixtures, not live proofs.
func nativeNetworkRuntimeBase(t *testing.T) marketRepositoryFixture {
	t.Helper()
	db := nativeAttemptDatabase(t)
	now := time.Now().UTC()
	raw, _ := json.Marshal(model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "ci/native", Owner: "ci-owner", Workflow: model.ManifestSelector{Namespace: "ci", Name: "scale-api"}, Currency: "USD", Floor: 0, Ceiling: 10, Step: 1, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MinUnits: 0, MaxUnits: 10, ValidationRef: "ci/qualified", ValidationValidUntil: now.Add(time.Hour)}}})
	namespace := "network-" + uuid.NewString()
	create := func(kind, name string, v json.RawMessage) model.Manifest {
		t.Helper()
		m, e := CreateManifestVersion(t.Context(), db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: namespace, Name: name}, Spec: v}, fmt.Sprintf("%x", sha256.Sum256(v)))
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	original := create("capacity_policy", "base", raw)
	value := .9
	assessment := model.CapacityAssessment{Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	f := marketRepoFixtureOnDB(t, db, original, assessment)
	typ := create("integration_type", "writer", json.RawMessage(`{"fixture":"separate-execution"}`))
	instance := create("integration_instance", "writer", json.RawMessage(fmt.Sprintf(`{"type_ref":{"manifest_id":%q}}`, typ.ID)))
	adapter := model.CapacityMarketAdapterBinding{ManifestID: instance.ID.String(), Version: instance.Version, Checksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	f.p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: capacity.NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60, Profiles: []model.CapacityNativeWorkerExecutionProfile{{Profile: f.p.Profiles[0].Name, Adapter: adapter, BindingName: "ci-writer", SDKSourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("f", 64), LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "ci/" + uuid.NewString(), OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}}}}
	f.p.Workflow.Namespace = f.policy.Metadata.Namespace
	f.market.Profiles[0].Provider, f.market.Profiles[0].Region = "aws", "us-east-1"
	return f
}

type nativeNetworkRuntimeFixture struct {
	network                                *CapacityNativeWorkerNetworkStore
	abort                                  *abortPGRuntime
	recovery                               uuid.UUID
	f                                      marketRepositoryFixture
	store                                  CapacityNativeWorkerStore
	auth                                   model.CapacityNativeWorkerAuthority
	workers                                *NativeWorkerConcreteRuntime
	runtime                                *NativeWorkerConcreteNetworkRuntime
	reader, writer                         *capacity.NativeWorkerNetworkRPCClient
	providerReads, floorReads, writerCalls atomic.Int32
	credentials                            *atomic.Int32
	observation                            model.CapacityNativeWorkerPhysicalObservation
	original                               model.CapacityNativeWorkerOriginalReturn
	installed                              atomic.Bool
	writerFailure                          atomic.Bool
}

func newNativeNetworkRuntimeFixture(t *testing.T) *nativeNetworkRuntimeFixture {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("NATIVE_NETWORK_ISOLATED_ALIAS") != "10.80.0.2" {
		t.Fatal("dedicated isolated CI alias required; no skip or local use")
	}
	systemSource, binary, binarySHA := os.Getenv("NATIVE_FACTORY_SYSTEM_SOURCE"), os.Getenv("NATIVE_FACTORY_SYSTEM_CLI"), os.Getenv("NATIVE_FACTORY_SYSTEM_SHA256")
	size, err := strconv.ParseInt(os.Getenv("NATIVE_FACTORY_SYSTEM_BYTES"), 10, 64)
	if len(systemSource) != 40 || !filepath.IsAbs(binary) || len(binarySHA) != 64 || err != nil || size < 1 {
		t.Fatal("actual published System factory artifact required; no skip or replacement")
	}
	f := nativeNetworkRuntimeBase(t)
	p := f.p
	for i := range p.Profiles {
		p.Profiles[i].Provider, p.Profiles[i].Region = "aws", "us-east-1"
	}
	for i := range p.MarketBinding.Profiles {
		p.MarketBinding.Profiles[i].Provider, p.MarketBinding.Profiles[i].Region = "aws", "us-east-1"
	}
	for i := range p.NativeWorkerPoolBinding.Profiles {
		p.NativeWorkerPoolBinding.Profiles[i].Provider = "aws"
		p.NativeWorkerPoolBinding.Profiles[i].ProviderIDPrefix = "aws:///"
	}
	execution := p.NativeWorkerLifecycleBinding.Profiles[0]
	execution.EnsureCapability, execution.ObserveCapability, execution.DestroyCapability = "ensure_native_worker", "observe_native_worker", "destroy_native_worker"
	execution.BootstrapSourceCommit = systemSource
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI-only-runtime-factory"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI-only-runtime-factory"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	hash := func(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
	floorKey, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// A fixed public System template fixture, in that published wire's exact
	// declaration order. It contains no live identity, key, token or account grant.
	template := []byte(fmt.Sprintf(`{"schema":1,"mode":"native_k3s_worker_v1","source_commit":%q,"pool_id":"ci-native-worker","pool_uid":"","registry":{"kind":"","namespace":"","name":"","uid":""},"policy_id":"","policy_sha256":"","expected_pool_epoch":0,"intent_generation":0,"fencing_token":0,"reservation_id":"","intent_sha256":"","provider":{"kind":"aws","account_id":"153828470928","region":"us-east-1","zone":"us-east-1a","image_id":"ami-11111111111111111","native_network_cidr":"10.90.0.0/24"},"floor":{"node_name":"ci-floor","node_uid":"33333333-3333-4333-8333-333333333333","provider_id":"hcloud://12345","cluster_uid":"44444444-4444-4444-8444-444444444444","api_endpoint":"https://10.80.0.2:6443","ca_sha256":%q,"node_network_cidr":"10.80.0.0/24"},"network":{"mode":"wireguard_routed_v1","transport_cidr":"10.81.0.0/24","worker_ipv4":"","floor_peer_ipv4":"10.81.0.2","floor_peer_endpoint":"203.0.113.2:51820","floor_peer_public_key":%q,"worker_public_key":"","pod_cidr":"10.82.0.0/16","service_cidr":"10.83.0.0/16"},"operator":{"source_commit":%q,"sha256":%q,"bytes":%d,"capability_ref":"native-private://operator-capability","expected_hostname":"ci-fixture.s3.us-east-1.amazonaws.com"},"reserve":{"kube_milli_cpu":100,"kube_memory_mib":128,"system_milli_cpu":100,"system_memory_mib":128,"eviction_memory_mib":128}}`, systemSource, hash(ca), base64.StdEncoding.EncodeToString(floorKey.PublicKey().Bytes()), systemSource, binarySHA, size))
	execution.LaunchTemplateSHA256 = hash(template)
	p.NativeWorkerLifecycleBinding.Profiles[0] = execution
	reader := execution.Adapter
	reader.ManifestID, reader.IntegrationTypeID = uuid.NewString(), uuid.NewString()
	p.NativeWorkerLifecycleBinding.PhaseObserver = &model.CapacityNativeWorkerPhaseReadBinding{Mode: capacity.NativeWorkerPhaseReadMode, Name: "ci-phase", SourceCommit: strings.Repeat("d", 40), Adapter: reader, ScopeSHA256: strings.Repeat("8", 64), RealmNamespace: "ci", MaxAgeSeconds: 30, QuarantineTaintKey: "dakasa.io/native-worker-unadmitted"}
	writer := execution.Adapter
	writer.ManifestID, writer.IntegrationTypeID = uuid.NewString(), uuid.NewString()
	p.NativeWorkerLifecycleBinding.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: writer, BindingName: "ci-registry", PrincipalID: "ci/registry-writer", SourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("7", 64), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 15}
	physical := execution.Adapter
	physical.ManifestID, physical.IntegrationTypeID = uuid.NewString(), uuid.NewString()
	p.NativeWorkerLifecycleBinding.PhysicalObservers = []model.CapacityNativeWorkerPhysicalReadBinding{{Profile: execution.Profile, Provider: "aws", Region: "us-east-1", Adapter: physical, BindingName: "ci-physical", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("9", 64), Capability: capacity.ObserveNativeWorkerPhysical}}

	floor := model.CapacityNativeWorkerNetworkFloorIdentity{NodeName: "ci-floor", NodeUID: "33333333-3333-4333-8333-333333333333", ProviderID: "hcloud://12345", ClusterUID: "44444444-4444-4444-8444-444444444444", CASHA256: hash(ca), NativeIPv4: "10.80.0.2", NativeInterface: "enp7s0"}
	p.NativeWorkerPoolBinding.RealmUID = floor.ClusterUID
	f.pool.RealmUID = floor.ClusterUID
	p.NativeWorkerPoolBinding.ProtectedNodes = append(p.NativeWorkerPoolBinding.ProtectedNodes, model.CapacityNativeProtectedNode{NodeUID: floor.NodeUID, ProviderID: floor.ProviderID})
	network := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: systemSource, Interface: "wg-dakasa", MTU: 1380, TransportCIDR: execution.OverlayCIDR, FloorPeerIPv4: execution.ExcludedIPv4[0], FloorPublicKey: base64.StdEncoding.EncodeToString(floorKey.PublicKey().Bytes()), ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: "10.82.0.0/16", ServiceCIDR: "10.83.0.0/16", ClusterDNSIPv4: "10.83.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
	p.NativeWorkerLifecycleBinding.Network = &model.CapacityNativeWorkerNetworkBinding{Mode: capacity.NativeWorkerNetworkMode, Writer: model.CapacityNativeWorkerNetworkWriterBinding{AdapterID: uuid.NewString(), PrincipalID: "ci/floor-writer", BindingName: "ci-floor-writer", SystemSourceCommit: systemSource, ScopeSHA256: strings.Repeat("1", 64)}, Reader: model.CapacityNativeWorkerNetworkReaderBinding{AdapterID: uuid.NewString(), BindingName: "ci-floor-reader", SystemSourceCommit: systemSource, ScopeSHA256: strings.Repeat("2", 64)}, Floor: floor, Template: network, TemplateSHA256: capacity.NativeWorkerNetworkTemplateSHA256(network), MaxPermitSeconds: 30}
	p.NativeWorkerLifecycleBinding.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: p.Workflow.Namespace, Name: "cleanup-network"}, MaxPermitSeconds: 30}
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: "runtime-composition"}, Spec: spec}, hash(spec))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cli := filepath.Join(dir, "actual-published-system")
	in, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(cli, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, size+1))
	closeErr := errors.Join(in.Close(), out.Close())
	if copyErr != nil || closeErr != nil || n != size {
		t.Fatal("actual published CLI copy incomplete", copyErr, closeErr)
	}
	var credentials atomic.Int32
	factory, err := capacity.NewNativeWorkerPrivateFactory(capacity.NativeWorkerPrivateFactoryConfig{Execution: execution, TemplateFile: write("template.json", template, 0600), TemplateSHA256: hash(template), CLIFile: cli, CLISHA256: binarySHA, CLIBytes: size, SystemBuildSource: systemSource, AgentTokenFile: write("agent-token", []byte("K10"+strings.Repeat("a", 64)+"::node:"+strings.Repeat("x", 32)), 0600), CAFile: write("ca.pem", ca, 0644), WireGuardMasterFile: write("master", bytes.Repeat([]byte{7}, 32), 0600), ArtifactBucket: "ci-fixture", ArtifactKey: "qualified/operator", ArtifactVersionID: "ci-source-version"}, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials.Add(1)
		return aws.Credentials{}, fmt.Errorf("Prepare must never resolve credentials")
	}))
	if err != nil {
		t.Fatal("real published factory handle refused", err)
	}
	t.Cleanup(func() { _ = factory.Close() })

	f.p, f.policy = p, policy
	workflowRaw := json.RawMessage(`{"authorization":{}}`)
	workflow, e := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: p.Workflow.Name}, Spec: workflowRaw}, hash(workflowRaw))
	if e != nil {
		t.Fatal(e)
	}
	f.store.WorkflowID = workflow.ID
	proposed, e := f.store.Assess(t.Context(), policy, f.a)
	if e != nil {
		t.Fatal("real Assess", e)
	}
	claimed, e := f.store.Claim(t.Context(), policy, proposed.Generation, f.a)
	if e != nil || claimed.MarketReservation == nil || claimed.MarketReservation.Units != 1 {
		t.Fatal("real Claim", e)
	}
	x := &nativeNetworkRuntimeFixture{f: f, auth: model.CapacityNativeWorkerAuthority{Generation: claimed.Generation, FencingToken: claimed.FencingToken}, credentials: &credentials}
	cfg := NativeWorkerConcreteRuntimeConfig{DB: f.db, Policy: policy, Factories: map[string]*capacity.NativeWorkerPrivateFactory{execution.Profile: factory}, PhaseRead: func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, string, string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		h := phaseAuthorityTestHeader(p)
		h.Registrations[0].ProviderID = "aws:///us-east-1a/i-22222222222222222"
		return h, nil
	}, PhysicalRead: func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		x.providerReads.Add(1)
		if b != p.NativeWorkerLifecycleBinding.PhysicalObservers[0] || in != x.observation.Requested {
			t.Error("provider reader lost stored selectors")
		}
		v := x.observation
		now := time.Now().UTC()
		v.StartedAt, v.ObservedAt = now.Add(-2*time.Millisecond), now.Add(-time.Millisecond)
		for i := range v.Reads {
			v.Reads[i].ObservedAt = now.Add(-time.Millisecond)
		}
		v.EvidenceSHA256 = ""
		raw, _ := json.Marshal(v)
		v.EvidenceSHA256 = hash(raw)
		return v, nil
	}}
	workers, e := newNativeWorkerConcreteRuntime(cfg, p.NativeWorkerLifecycleBinding.SourceCommit)
	if e != nil {
		t.Fatal("real borrowed runtime", e)
	}
	x.workers = workers
	t.Cleanup(func() { _ = workers.Close() })
	x.reader, x.writer = nativeNetworkRuntimeClients(t, x, ca, caDER, key)
	networkConfig := NativeWorkerConcreteNetworkRuntimeConfig{DB: f.db, Policy: policy, Workers: workers, Reader: x.reader, Writer: x.writer}
	bad := networkConfig
	bad.Policy.Kind = "workflow"
	if _, e = newNativeWorkerConcreteNetworkRuntime(bad, workers.SourceCommit()); e == nil || !x.reader.Matches("reader", *p.NativeWorkerLifecycleBinding.Network) || !x.writer.Matches("writer", *p.NativeWorkerLifecycleBinding.Network) {
		t.Fatal("failed constructor stole clients")
	}
	x.runtime, e = newNativeWorkerConcreteNetworkRuntime(networkConfig, workers.SourceCommit())
	if e != nil {
		t.Fatal("real network composition", e)
	}
	t.Cleanup(func() { _ = x.runtime.Close() })
	birth := &nativeNetworkBirthRuntime{nativeAttemptRuntime: &nativeAttemptRuntime{db: f.db, pool: f.pool}, x: x}
	x.store = CapacityNativeWorkerStore{Capacity: f.store, Runtime: birth, Enabled: true}
	recovery, e := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: "cleanup-network"}, Spec: workflowRaw}, hash(workflowRaw))
	if e != nil {
		t.Fatal(e)
	}
	x.recovery = recovery.ID
	x.abort = &abortPGRuntime{nativeAttemptRuntime: birth.nativeAttemptRuntime, p: p}
	x.network = &CapacityNativeWorkerNetworkStore{Workers: x.store, Runtime: x.runtime, AbortRuntime: x.abort, RecoveryWorkflowID: recovery.ID, Enabled: true}
	return x
}

// The only fixture substitutions are provider/floor facts. Prepare, independent
// qualifier, DB archive, send ledger, and all TLS clients are real products.
type nativeNetworkBirthRuntime struct {
	*nativeAttemptRuntime
	x *nativeNetworkRuntimeFixture
}

func (r *nativeNetworkBirthRuntime) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	return r.x.workers.Prepare(a)
}
func (r *nativeNetworkBirthRuntime) ObservePhaseAuthority(ctx context.Context, p model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	return r.x.workers.ObservePhaseAuthority(ctx, p)
}
func (r *nativeNetworkBirthRuntime) CaptureOriginalReturn(_ context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	r.x.original, r.x.observation = nativeNetworkRuntimeProviderFacts(a, r.x.f.p)
	return r.x.original, nil
}
func (r *nativeNetworkBirthRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, o model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	return r.x.workers.Qualify(ctx, a, o)
}

func nativeNetworkRuntimeProviderFacts(a model.CapacityNativeWorkerAttempt, p model.CapacityPolicySpec) (model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerPhysicalObservation) {
	now := time.Now().UTC()
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	created := a.CreatedAt
	facts := model.CapacityNativeWorkerPhysicalFacts{ResourceID: "i-0123456789abcdef0", ProviderID: "aws:///us-east-1a/i-0123456789abcdef0", AccountID: "153828470928", InstanceType: "m7a.large", NetworkID: "vpc-0123456789abcdef0", NativeNetworkCIDR: "10.90.0.0/24", CreatedAt: created, ImageID: "ami-11111111111111111", Region: "us-east-1", Zone: "us-east-1a", NativeIPv4: "10.90.0.8", MACAddress: "02:00:00:00:00:08", PhysicalSpecSHA256: a.PhysicalSpecSHA256, LaunchSHA256: a.LaunchSHA256}
	o := model.CapacityNativeWorkerPhysicalObservation{Schema: "aws_native_worker_physical_observation_v1", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: facts.ResourceID, LaunchSHA256: a.LaunchSHA256}, StartedAt: now.Add(-500 * time.Millisecond), ObservedAt: now.Add(-time.Millisecond), Complete: true, ActualTags: model.CapacityNativeWorkerObservedTags{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256: a.LaunchSHA256}, ActualClientToken: a.ID.String(), InstanceState: "running", Physical: facts, RootVolume: model.CapacityNativeWorkerObservedVolume{ResourceID: "vol-0123456789abcdef0", DeviceName: "/dev/sda1", AttachedInstanceID: facts.ResourceID, Encrypted: true, KMSKeyARN: "arn:aws:kms:us-east-1:153828470928:key/11111111-1111-4111-8111-111111111111", VolumeType: "gp3", VolumeGiB: 20, IOPS: 3000, Throughput: 125, DeleteOnTermination: true}, PrimaryInterface: model.CapacityNativeWorkerObservedInterface{ResourceID: "eni-0123456789abcdef0", NetworkID: facts.NetworkID, SubnetID: "subnet-0123456789abcdef0", NativeIPv4: facts.NativeIPv4, MACAddress: facts.MACAddress, AttachedInstanceID: facts.ResourceID, AttachmentID: "eni-attach-0123456789abcdef0", DeleteOnTermination: true}}
	for i, op := range []string{"GetCallerIdentity", "DescribeInstances", "DescribeSubnets", "DescribeSecurityGroups", "DescribeVolumes", "DescribeNetworkInterfaces", "DescribeInstances"} {
		o.Reads = append(o.Reads, model.CapacityNativeWorkerObservedRPC{Operation: op, Role: []string{"caller", "before", "network", "security", "root_volume", "primary_interface", "after"}[i], RequestID: fmt.Sprintf("actual-request-%d", i), ObservedAt: now.Add(-100 * time.Millisecond)})
	}
	o.TransportEndpointIPv4 = "203.0.113.8"
	raw, _ := json.Marshal(o)
	o.EvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	xml := fmt.Sprintf(`<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>original-request</requestId><reservationId>r-0123456789abcdef0</reservationId><ownerId>%s</ownerId><instancesSet><item><instanceId>%s</instanceId><imageId>%s</imageId><instanceType>%s</instanceType><instanceState><code>0</code><name>pending</name></instanceState><launchTime>%s</launchTime><placement><availabilityZone>%s</availabilityZone></placement><architecture>x86_64</architecture><vpcId>%s</vpcId><subnetId>%s</subnetId><privateIpAddress>%s</privateIpAddress><clientToken>%s</clientToken><rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>%s</volumeId><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping><networkInterfaceSet><item><networkInterfaceId>%s</networkInterfaceId><vpcId>%s</vpcId><subnetId>%s</subnetId><privateIpAddress>%s</privateIpAddress><macAddress>%s</macAddress><attachment><deviceIndex>0</deviceIndex><deleteOnTermination>true</deleteOnTermination></attachment></item></networkInterfaceSet><tagSet><item><key>yggdrasil.io/native-worker-attempt</key><value>%s</value></item><item><key>dakasa.io/native-worker-pool</key><value>%s</value></item><item><key>yggdrasil.io/native-worker-launch-sha256</key><value>%s</value></item></tagSet></item></instancesSet></RunInstancesResponse>`, facts.AccountID, facts.ResourceID, facts.ImageID, facts.InstanceType, created.Format(time.RFC3339Nano), facts.Zone, facts.NetworkID, o.PrimaryInterface.SubnetID, facts.NativeIPv4, a.ID, o.RootVolume.ResourceID, o.PrimaryInterface.ResourceID, facts.NetworkID, o.PrimaryInterface.SubnetID, facts.NativeIPv4, facts.MACAddress, a.ID, a.PoolUID, a.LaunchSHA256)
	wire, _ := json.Marshal(struct {
		Schema             string `json:"schema"`
		AttemptID          string `json:"attempt_id"`
		HTTPStatus         int    `json:"http_status"`
		RequestID          string `json:"request_id"`
		TransportCompleted bool   `json:"transport_completed"`
		Body               []byte `json:"body"`
	}{Schema: "aws_native_worker_original_return_v1", AttemptID: a.ID.String(), HTTPStatus: 200, TransportCompleted: true, Body: []byte(xml)})
	return model.CapacityNativeWorkerOriginalReturn{Wire: wire, CaptureComplete: true}, o
}

func nativeNetworkRuntimeClients(t *testing.T, x *nativeNetworkRuntimeFixture, caPEM, caDER []byte, caKey ed25519.PrivateKey) (*capacity.NativeWorkerNetworkRPCClient, *capacity.NativeWorkerNetworkRPCClient) {
	t.Helper()
	b := *x.f.p.NativeWorkerLifecycleBinding.Network
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	hash := func(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }
	cert := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		t.Helper()
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "CI-only-floor-RPC"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			leaf.IPAddresses = []net.IP{net.ParseIP(b.Floor.NativeIPv4)}
		}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyRaw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return pair, certPEM, keyPEM
	}
	makeClient := func(role, port string) *capacity.NativeWorkerNetworkRPCClient {
		t.Helper()
		serverCert, _, _ := cert(11, x509.ExtKeyUsageServerAuth)
		_, clientPEM, clientKey := cert(12, x509.ExtKeyUsageClientAuth)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) != 1 || r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" || r.Host != net.JoinHostPort(b.Floor.NativeIPv4, port) || r.Header.Get("Authorization") != "" {
				t.Error("actual mTLS, fixed role address or callback separation lost")
				w.WriteHeader(403)
				return
			}
			raw, e := io.ReadAll(io.LimitReader(r.Body, 65537))
			if e != nil || len(raw) > 65536 {
				t.Error("RPC body not bounded")
				w.WriteHeader(400)
				return
			}
			var request struct {
				Operation  string          `json:"operation"`
				Capability string          `json:"capability"`
				Input      json.RawMessage `json:"input"`
			}
			if capacity.DecodeNativeCapacity(json.RawMessage(raw), &request) != nil || request.Operation != request.Capability {
				t.Error("actual three-key System envelope changed")
				w.WriteHeader(400)
				return
			}
			var output any
			if role == "reader" {
				x.floorReads.Add(1)
				var selector model.CapacityNativeWorkerNetworkObserveInput
				if capacity.DecodeNativeCapacity(request.Input, &selector) != nil || request.Operation != capacity.ObserveNativeWorkerNetwork {
					t.Error("reader acquired different selectors")
					w.WriteHeader(400)
					return
				}
				output = nativeNetworkRuntimeFloor(b, selector, x.installed.Load())
			} else {
				x.writerCalls.Add(1)
				var input model.CapacityNativeWorkerNetworkMutationInput
				var keys map[string]json.RawMessage
				_ = json.Unmarshal(request.Input, &keys)
				if len(keys) != 2 || capacity.DecodeNativeCapacity(request.Input, &input) != nil || input.BindingName != b.Writer.BindingName || request.Operation != capacity.NativeWorkerNetworkInstall && request.Operation != capacity.NativeWorkerNetworkRemove {
					t.Error("writer acquired parameters beyond stored permit")
					w.WriteHeader(400)
					return
				}
				if x.writerFailure.Load() {
					w.WriteHeader(503)
					return
				}
				// CI System-side callback fixture delegates all one-send and custody
				// authority to the real Store117. It does not run a host batch.
				if x.network == nil {
					t.Error("missing actual Store117")
					w.WriteHeader(500)
					return
				}
				action := "install"
				if request.Operation == capacity.NativeWorkerNetworkRemove {
					action = "remove"
				}
				caller := networkPGCaller(x.f.p, action)
				id := uuid.MustParse(input.PermitID)
				callback, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				defer cancel()
				grant, e := x.network.Redeem(callback, x.f.policy, id, caller)
				if e != nil {
					w.WriteHeader(409)
					return
				}
				if !grant.MutationPermitted {
					t.Error("fake System received no original one-use grant")
					w.WriteHeader(500)
					return
				}
				if e = x.network.Receive(callback, x.f.policy, caller, networkPGOriginal(grant, true)); e != nil {
					t.Error("actual private custody", e)
					w.WriteHeader(500)
					return
				}
				output = capacity.NativeWorkerNetworkRPCMutationResult{PermitID: input.PermitID, State: "unknown", GetOnlyRecovery: true}
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Yggdrasil-Source-Commit", b.Writer.SystemSourceCommit)
			_ = json.NewEncoder(w).Encode(map[string]any{"operation": request.Operation, "capability": request.Capability, "status": "observed", "output": output, "metadata": map[string]bool{"network_admission_qualified": false, "useful_capacity_qualified": false}})
		}))
		listener, e := net.Listen("tcp", net.JoinHostPort(b.Floor.NativeIPv4, port))
		if e != nil {
			t.Fatal("isolated runner private alias", e)
		}
		_ = server.Listener.Close()
		server.Listener = listener
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
		server.StartTLS()
		t.Cleanup(server.Close)
		c := capacity.NativeWorkerNetworkRPCConfig{Role: role, Floor: b.Floor, Template: b.Template, TemplateSHA256: b.TemplateSHA256, MaxReadAgeSeconds: 30, ServerCAFile: write(role+"-ca.pem", caPEM), ServerCASHA256: hash(caPEM), ServerCertificateSHA256: hash(serverCert.Certificate[0]), ClientCertificateFile: write(role+"-client.pem", clientPEM), ClientKeyFile: write(role+"-client.key", clientKey)}
		if role == "reader" {
			c.AdapterID, c.BindingName, c.SystemSourceCommit, c.ScopeSHA256 = b.Reader.AdapterID, b.Reader.BindingName, b.Reader.SystemSourceCommit, b.Reader.ScopeSHA256
		} else {
			c.AdapterID, c.BindingName, c.SystemSourceCommit, c.ScopeSHA256 = b.Writer.AdapterID, b.Writer.BindingName, b.Writer.SystemSourceCommit, b.Writer.ScopeSHA256
		}
		client, e := capacity.NewNativeWorkerNetworkRPCClient(c)
		if e != nil {
			t.Fatal("public real RPC constructor", e)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	return makeClient("reader", "9444"), makeClient("writer", "9443")
}

func nativeNetworkRuntimeFloor(b model.CapacityNativeWorkerNetworkBinding, in model.CapacityNativeWorkerNetworkObserveInput, installed bool) model.CapacityNativeWorkerNetworkObservation {
	o := model.CapacityNativeWorkerNetworkObservation{Schema: model.CapacityNativeWorkerNetworkObservationSchema, BindingName: b.Reader.BindingName, AdapterSourceCommit: b.Reader.SystemSourceCommit, ReaderScopeSHA256: b.Reader.ScopeSHA256, Requested: in, ObservedAt: time.Now().UTC(), Floor: model.CapacityNativeWorkerNetworkFloorFacts{Bound: b.Floor, Observed: model.CapacityNativeWorkerNetworkHostIdentity{Hostname: b.Floor.NodeName, CASHA256: b.Floor.CASHA256, CAOrigin: "source_bound_local_certificate", NativeInterfaceIndex: 2, NativeInterfaceUp: true, NativeIPv4Present: true}}, NetworkTemplateSHA256: b.TemplateSHA256, MTU: 1380, Interface: model.CapacityNativeWorkerNetworkInterfaceFacts{Name: b.Template.Interface, Addresses: []string{}}, Peers: []model.CapacityNativeWorkerNetworkPeerFacts{}, Routes: []model.CapacityNativeWorkerNetworkRouteFacts{}, Firewall: model.CapacityNativeWorkerNetworkFirewallFacts{Chain: "inet/dakasa_native/DAKASA_NATIVE", Rules: []string{}, Complete: true}, KernelSettings: model.CapacityNativeWorkerNetworkKernelSettings{IPForward: 1, AllRPFilter: 2, NativeRPFilter: 2}, KernelInventoryComplete: true}
	if installed {
		o.Interface = model.CapacityNativeWorkerNetworkInterfaceFacts{Present: true, Name: b.Template.Interface, IfIndex: 20, MTU: 1380, Up: true, Addresses: []string{b.Template.FloorPeerIPv4 + "/32"}, PublicKey: b.Template.FloorPublicKey, ListenPort: b.Template.ListenPort}
		o.Peers = []model.CapacityNativeWorkerNetworkPeerFacts{{PublicKey: in.WorkerPublicKey, AllowedIPs: []string{in.WorkerIPv4 + "/32"}, Endpoint: "203.0.113.8:52345", LastHandshakeUnix: time.Now().Unix()}}
		o.Routes = []model.CapacityNativeWorkerNetworkRouteFacts{{Destination: in.WorkerIPv4 + "/32", Device: b.Template.Interface, PreferredSource: b.Floor.NativeIPv4}}
		o.Firewall.Rules = []string{"dakasa-native:" + in.AttemptID + "|203.0.113.8", "dakasa-native:drop"}
		o.KernelSettings.WireGuardRPFilter = 2
		o.KernelSettings.WireGuardRPFilterObserved = true
	}
	o.Firewall.RulesSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(o.Firewall.Rules, "\n")+"\n")))
	return o
}

func (x *nativeNetworkRuntimeFixture) child(t *testing.T) model.CapacityNativeWorkerAttempt {
	t.Helper()
	a, e := x.store.Reserve(t.Context(), x.f.policy, x.auth)
	if e != nil {
		t.Fatal("real Reserve", e)
	}
	if _, e = x.store.Redeem(t.Context(), x.f.policy, x.auth, a.ID); e != nil {
		t.Fatal("real Redeem", e)
	}
	a, e = x.store.Record(t.Context(), x.f.policy, x.auth, a.ID)
	if e != nil || a.Physical == nil || a.State != "acknowledged" {
		t.Fatal("real original custody/physical birth", e)
	}
	return a
}

func TestNativeNetworkRuntimePublishedFactoryPrivateArchiveAndOneStoreDispatch(t *testing.T) {
	x := newNativeNetworkRuntimeFixture(t)
	a := x.child(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if !x.runtime.BoundToDatabase(x.f.db) || x.runtime.SourceCommit() != x.workers.SourceCommit() || x.credentials.Load() != 0 {
		t.Fatal("binding changed or pure preparation used WAN")
	}
	beforeProvider, beforeFloor := x.providerReads.Load(), x.floorReads.Load()
	prepared, e := x.runtime.PrepareNetwork(ctx, x.f.policy, a, "install")
	if e != nil || prepared.Physical != *a.Physical || prepared.TransportEndpointIPv4 != "203.0.113.8" || x.providerReads.Load() != beforeProvider+1 || x.floorReads.Load() != beforeFloor+1 {
		t.Fatal("install did not join one actual independent read and real floor client", e)
	}
	grant, e := x.network.Begin(ctx, x.f.policy, a.ID, "install")
	if e != nil {
		t.Fatal("real Store117 Begin", e)
	}
	id := uuid.MustParse(grant.PermitID)
	result, e := x.runtime.RequestNetworkMutation(ctx, x.f.policy, "install", id)
	if e != nil || result.State != "unknown" || !result.GetOnlyRecovery || result.NetworkQualified || result.SchedulingAdmitted || x.writerCalls.Load() != 1 {
		t.Fatal("single RPC disposition became proof or retried", e)
	}
	retained, e := x.network.load(ctx, x.f.policy, id)
	if e != nil || retained.Original == nil || !retained.OriginalCallerClosed || retained.Context.State != "unknown" || retained.Original.CaptureComplete || !reflect.DeepEqual(retained.Attempt, a) {
		t.Fatal("real original custody lost or capture confused with closure", e)
	}
	if _, e = x.network.Redeem(ctx, x.f.policy, id, networkPGCaller(x.f.p, "install")); e == nil {
		t.Fatal("second batch authority exposed")
	}
	var revisions int
	if e = x.f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_network_events WHERE permit_id=$1`, id).Scan(&revisions); e != nil || revisions != 3 {
		t.Fatal("actual issued/redeemed/custody events missing", e, revisions)
	}
	// A writer reply cannot qualify a network. Separate Source-pinned reader
	// receiving is required; this toggle represents only a CI host-facts fixture.
	beforeProvider = x.providerReads.Load()
	observed, e := x.runtime.ObserveNetwork(ctx, x.f.policy, a, grant)
	if e != nil || observed.Interface.Present || x.providerReads.Load() != beforeProvider {
		t.Fatal("receiving called provider or echoed writer", e)
	}
	x.installed.Store(true)
	observed, e = x.runtime.ObserveNetwork(ctx, x.f.policy, a, grant)
	if e != nil || !capacity.NativeWorkerNetworkDesired(*x.f.p.NativeWorkerLifecycleBinding.Network, grant, observed) || x.writerCalls.Load() != 1 {
		t.Fatal("independent readback failed or effect replayed", e)
	}
	stored, e := x.network.Reconcile(ctx, x.f.policy, id, networkPGCaller(x.f.p, "install"))
	if e != nil || stored.State != "observed" || stored.Redeemable || stored.MutationPermitted {
		t.Fatal("Store alone did not receive configuration truth", e)
	}
	// Known physical cleanup may finish before network compensation. The
	// original exposed install, not a new provider read, supplies its endpoint.
	cleanup := CapacityNativeWorkerAbortStore{Workers: x.store, Runtime: x.abort, RecoveryWorkflowID: x.recovery, Enabled: true}
	abort, e := cleanup.Begin(ctx, x.f.policy, a.ID)
	if e != nil {
		t.Fatal("original caller closed but abort could not fence worker", e)
	}
	current, e := x.store.Read(ctx, x.f.policy, a.ID)
	if e != nil || current.State != "aborting" {
		t.Fatal(e)
	}
	if abort.AttemptID != a.ID {
		t.Fatal("cleanup selected another child")
	}
	x.abort.mu.Lock()
	x.abort.settled = true
	x.abort.keepNetwork = true
	x.abort.mu.Unlock()
	beforeProvider = x.providerReads.Load()
	removed, e := x.runtime.PrepareNetwork(ctx, x.f.policy, current, "remove")
	if e != nil || removed.Physical != *a.Physical || !removed.PhysicalObservedAt.IsZero() || removed.PhysicalEvidenceSHA256 != "" || removed.TransportEndpointIPv4 != "" || x.providerReads.Load() != beforeProvider {
		t.Fatal("provider absence was fabricated as present or endpoint guessed", e)
	}
	remove, e := x.network.Begin(ctx, x.f.policy, a.ID, "remove")
	if e != nil || remove.Peer.TransportEndpointIPv4 != grant.Peer.TransportEndpointIPv4 || x.providerReads.Load() != beforeProvider {
		t.Fatal("sealed install endpoint was not retained after provider absence", e)
	}
	// Historical independent receiving does not acquire a new send grant.
	historical := grant
	historical.ExpiresAt = time.Now().Add(-time.Hour)
	inactive := x.f.policy
	inactive.Metadata.Active = false
	beforeProvider = x.providerReads.Load()
	if _, e = x.runtime.ObserveNetwork(ctx, inactive, current, historical); e != nil || x.providerReads.Load() != beforeProvider {
		t.Fatal("historical floor receiving depended on live provider/permission", e)
	}
	// Value copies share Close. Closing the composition closes only its own
	// reader/writer, leaving the borrowed worker factories and DB available.
	copy := *x.runtime
	if e = copy.Close(); e != nil || x.runtime.SourceCommit() != "" || x.reader.Matches("reader", *x.f.p.NativeWorkerLifecycleBinding.Network) || x.writer.Matches("writer", *x.f.p.NativeWorkerLifecycleBinding.Network) || x.workers.SourceCommit() == "" || !x.workers.factories[a.Profile].MatchesExecution(a.Execution) {
		t.Fatal("composition ownership escaped its handles", e)
	}
	if e = x.f.db.PingContext(ctx); e != nil {
		t.Fatal("borrowed DB was closed", e)
	}
	if _, e = x.runtime.PrepareNetwork(ctx, x.f.policy, a, "install"); e == nil {
		t.Fatal("closed network runtime performed another read")
	}
}

func TestNativeNetworkRuntimeRefusesSubstitutionMissingArchiveAndInvalidDispatchBeforeRPC(t *testing.T) {
	x := newNativeNetworkRuntimeFixture(t)
	a := x.child(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	provider, floor, writes := x.providerReads.Load(), x.floorReads.Load(), x.writerCalls.Load()
	for _, fault := range []string{"unknownAction", "zeroAttempt", "missingArchive", "staleAttempt", "wrongSource", "wrongScope", "wrongPolicy", "wrongProfile", "wrongRegion"} {
		t.Run(fault, func(t *testing.T) {
			bad, policy, action := a, x.f.policy, "install"
			switch fault {
			case "unknownAction":
				action = "ensure"
			case "zeroAttempt":
				bad.ID = uuid.Nil
			case "missingArchive":
				bad.ID = uuid.New()
			case "staleAttempt":
				bad.Revision++
			case "wrongSource":
				bad.SourceCommit = strings.Repeat("f", 40)
			case "wrongScope":
				bad.Execution.ScopeSHA256 = strings.Repeat("0", 64)
			case "wrongPolicy":
				policy.Checksum = "other"
			case "wrongProfile":
				bad.Profile = "other"
			case "wrongRegion":
				bad.Region = "us-west-2"
			}
			if _, e := x.runtime.PrepareNetwork(ctx, policy, bad, action); e == nil {
				t.Fatal("substituted target reached a reader")
			}
		})
	}
	for _, action := range []string{"", "ensure", "INSTALL", "destroy_native_worker_network"} {
		if _, e := x.runtime.RequestNetworkMutation(ctx, x.f.policy, action, uuid.New()); e == nil {
			t.Fatal("unknown action dispatched")
		}
	}
	if _, e := x.runtime.RequestNetworkMutation(ctx, x.f.policy, "install", uuid.Nil); e == nil {
		t.Fatal("nil permit dispatched")
	}
	if _, e := x.runtime.RequestNetworkMutation(ctx, x.f.policy, "install", uuid.New()); e == nil {
		t.Fatal("nonexistent retained permit dispatched")
	}
	if x.providerReads.Load() != provider || x.floorReads.Load() != floor || x.writerCalls.Load() != writes {
		t.Fatal("invalid input performed protected network/provider I/O")
	}
	// The runtime and its copies are redacted without copying a mutex or private
	// credentials. The original actual factory was never rendered or resolved.
	for _, value := range []any{x.runtime, *x.runtime} {
		raw, e := json.Marshal(value)
		if e != nil || !bytes.Equal(raw, []byte(`{"private_native_network_runtime":"redacted"}`)) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), "agent-token") {
			t.Fatal("private runtime serialization leaked material")
		}
	}
	var zero NativeWorkerConcreteNetworkRuntime
	if zero.SourceCommit() != "" || zero.BoundToDatabase(x.f.db) || zero.Close() != nil {
		t.Fatal("zero handle granted authority")
	}
	cfg := NativeWorkerConcreteNetworkRuntimeConfig{DB: x.f.db, Policy: x.f.policy, Workers: x.workers, Reader: x.reader, Writer: x.writer}
	if _, e := newNativeWorkerConcreteNetworkRuntime(cfg, strings.Repeat("f", 40)); e == nil {
		t.Fatal("caller source replaced compiled authority")
	}
	bad := cfg
	bad.Reader, bad.Writer = bad.Writer, bad.Reader
	if _, e := newNativeWorkerConcreteNetworkRuntime(bad, x.workers.SourceCommit()); e == nil {
		t.Fatal("reader/writer roles mixed")
	}
	grant, e := x.network.Begin(ctx, x.f.policy, a.ID, "install")
	if e != nil {
		t.Fatal(e)
	}
	x.writerFailure.Store(true)
	if _, e = x.runtime.RequestNetworkMutation(ctx, x.f.policy, "install", uuid.MustParse(grant.PermitID)); e == nil || x.writerCalls.Load() != writes+1 {
		t.Fatal("failed original RPC was accepted or automatically retried", e)
	}
	retained, e := x.network.load(ctx, x.f.policy, uuid.MustParse(grant.PermitID))
	if e != nil || retained.Context.State != "issued" || retained.Original != nil {
		t.Fatal("failed RPC invented custody/effect or freed the command", e)
	}
	// A failed ctor owns nothing; closing the borrowed handle independently must
	// fence future use without silently closing otherwise caller-owned clients.
	if e := x.workers.Close(); e != nil {
		t.Fatal(e)
	}
	if x.runtime.SourceCommit() != "" || x.runtime.BoundToDatabase(x.f.db) || !x.reader.Matches("reader", *x.f.p.NativeWorkerLifecycleBinding.Network) {
		t.Fatal("borrowed handle Close was ignored or stole a client")
	}
	if _, e := x.runtime.PrepareNetwork(ctx, x.f.policy, a, "install"); e == nil {
		t.Fatal("closed borrowed workers still used")
	}
	if x.credentials.Load() != 0 {
		t.Fatal("non-rendering integration used artifact credentials")
	}
}
