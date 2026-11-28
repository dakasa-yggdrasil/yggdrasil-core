//go:build linux && nativefactoryqualification

package repository

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
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

func TestNativeConcreteHCloudRuntimePublishedFactoryPreservesCanonicalScopeAndOwnership(t *testing.T) {
	systemSource, binary, binarySHA := os.Getenv("NATIVE_FACTORY_SYSTEM_SOURCE"), os.Getenv("NATIVE_FACTORY_SYSTEM_CLI"), os.Getenv("NATIVE_FACTORY_SYSTEM_SHA256")
	size, err := strconv.ParseInt(os.Getenv("NATIVE_FACTORY_SYSTEM_BYTES"), 10, 64)
	if len(systemSource) != 40 || !filepath.IsAbs(binary) || len(binarySHA) != 64 || err != nil || size < 1 {
		t.Fatal("actual published System factory artifact required; no skip or replacement")
	}
	f, _, _, _ := nativeAttemptFixture(t)
	p := f.p
	for i := range p.Profiles {
		p.Profiles[i].Provider, p.Profiles[i].Region = "hetzner", "hel1"
	}
	for i := range p.MarketBinding.Profiles {
		p.MarketBinding.Profiles[i].Provider, p.MarketBinding.Profiles[i].Region = "hetzner", "hel1"
	}
	for i := range p.NativeWorkerPoolBinding.Profiles {
		p.NativeWorkerPoolBinding.Profiles[i].Provider = "hetzner"
		p.NativeWorkerPoolBinding.Profiles[i].ProviderIDPrefix = "hcloud://"
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
	template := []byte(fmt.Sprintf(`{"schema":1,"mode":"native_k3s_worker_v1","source_commit":%q,"pool_id":"ci-native-worker","pool_uid":"","registry":{"kind":"","namespace":"","name":"","uid":""},"policy_id":"","policy_sha256":"","expected_pool_epoch":0,"intent_generation":0,"fencing_token":0,"reservation_id":"","intent_sha256":"","provider":{"kind":"hetzner","account_id":"","region":"eu-central","zone":"hel1","image_id":"123456","native_network_cidr":"10.90.0.0/24"},"floor":{"node_name":"ci-floor","node_uid":"33333333-3333-4333-8333-333333333333","provider_id":"hcloud://12345","cluster_uid":"44444444-4444-4444-8444-444444444444","api_endpoint":"https://10.80.0.2:6443","ca_sha256":%q,"node_network_cidr":"10.80.0.0/24"},"network":{"mode":"wireguard_routed_v1","transport_cidr":"10.81.0.0/24","worker_ipv4":"","floor_peer_ipv4":"10.81.0.2","floor_peer_endpoint":"203.0.113.2:51820","floor_peer_public_key":%q,"worker_public_key":"","pod_cidr":"10.82.0.0/16","service_cidr":"10.83.0.0/16"},"operator":{"source_commit":%q,"sha256":%q,"bytes":%d,"capability_ref":"native-private://operator-capability","expected_hostname":"ci-fixture.s3.us-east-1.amazonaws.com"},"reserve":{"kube_milli_cpu":100,"kube_memory_mib":128,"system_milli_cpu":100,"system_memory_mib":128,"eviction_memory_mib":128}}`, systemSource, hash(ca), base64.StdEncoding.EncodeToString(floorKey.PublicKey().Bytes()), systemSource, binarySHA, size))
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
	p.NativeWorkerLifecycleBinding.PhysicalObservers = []model.CapacityNativeWorkerPhysicalReadBinding{{Profile: execution.Profile, Provider: "hetzner", Region: "hel1", Adapter: physical, BindingName: "ci-physical", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("9", 64), Capability: capacity.ObserveNativeWorkerPhysical}}
	p.NativeWorkerLifecycleBinding.PhysicalObservers[0].HCloudScope = &model.CapacityNativeWorkerHCloudProjectScope{DeclaredProjectID: "ci-reviewed-project", ProofKind: "reviewed_token_and_network_anchor_v1", AnchorID: "10", AnchorCreated: time.Now().UTC().Add(-24 * time.Hour), AnchorOwnerLabelKey: "owner", AnchorOwnerLabelValue: "ci-native"}
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: "hcloud-runtime-composition"}, Spec: spec}, hash(spec))
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
	cfg := NativeWorkerConcreteRuntimeConfig{DB: f.db, Policy: policy, Factories: map[string]*capacity.NativeWorkerPrivateFactory{execution.Profile: factory}, PhaseRead: func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, string, string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		t.Fatal("constructor or pure Prepare performed a Kubernetes read")
		return model.CapacityNativeWorkerPhaseReadObservation{}, errNativeWorkerConcreteRuntime
	}, PhysicalRead: func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		t.Fatal("constructor or pure Prepare performed a provider read")
		return model.CapacityNativeWorkerPhysicalObservation{}, errNativeWorkerConcreteRuntime
	}}
	bad := cfg
	bad.Policy.Kind = "workflow"
	if _, err := newNativeWorkerConcreteRuntime(bad, p.NativeWorkerLifecycleBinding.SourceCommit); err == nil || !factory.MatchesExecution(execution) {
		t.Fatal("failed constructor stole or closed caller handle")
	}
	// HCloud has no AWS account-introspection fallback. Its independently
	// reviewed project/anchor scope is mandatory even before a CREATE exists.
	var withoutScope model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &withoutScope) != nil {
		t.Fatal("copy stored policy")
	}
	withoutScope.NativeWorkerLifecycleBinding.PhysicalObservers[0].HCloudScope = nil
	withoutScopeRaw, err := json.Marshal(withoutScope)
	if err != nil {
		t.Fatal(err)
	}
	missing := cfg
	missing.Policy.Spec, missing.Policy.Checksum = withoutScopeRaw, hash(withoutScopeRaw)
	if _, err := newNativeWorkerConcreteRuntime(missing, p.NativeWorkerLifecycleBinding.SourceCommit); err == nil || !factory.MatchesExecution(execution) {
		t.Fatal("missing independent HCloud scope was accepted or took factory ownership")
	}
	// Keep failure-only diagnostics at the same real constructor seams. These
	// assertions do not replace or bypass any constructor validation.
	if _, err := parseCapacityPolicy(policy); err != nil {
		t.Fatal("stored runtime policy fixture is not valid", err)
	}
	if !policy.Metadata.Active || !factory.MatchesExecution(execution) {
		t.Fatal("stored policy is inactive or original factory binding changed")
	}
	if _, err := capacity.NewNativeWorkerPhaseReader(p, cfg.PhaseRead, nil); err != nil {
		t.Fatal("protected phase-reader fixture is not valid", err)
	}
	if _, err := capacity.NewNativeWorkerACKQualifier(p, cfg.PhysicalRead); err != nil {
		t.Fatal("independent physical-reader fixture is not valid", err)
	}
	runtime, err := newNativeWorkerConcreteRuntime(cfg, p.NativeWorkerLifecycleBinding.SourceCommit)
	if err != nil {
		t.Fatal("actual factory-to-runtime composition refused", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	delete(cfg.Factories, execution.Profile)
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Namespace: policy.Metadata.Namespace, Domain: p.Domain, PoolUID: p.NativeWorkerPoolBinding.PoolUID, PoolEpoch: p.NativeWorkerPoolBinding.ExpectedPoolEpoch, Generation: 2, FencingToken: 3, Registry: p.NativeWorkerPoolBinding.RegistryRef, Profile: execution.Profile, Provider: "hetzner", Region: "hel1", ProviderIDPrefix: "hcloud://", SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, Execution: execution, OverlayIPv4: "10.81.0.7", IntentSHA256: strings.Repeat("c", 64), State: "reserved"}
	first, err := runtime.Prepare(a)
	if err != nil || capacity.ValidateNativeWorkerLaunch(a, first) != nil {
		t.Fatal("actual HCloud runtime factory preparation refused", err)
	}
	second, err := runtime.Prepare(a)
	if err != nil || !bytes.Equal(first.PublicJSON, second.PublicJSON) || credentials.Load() != 0 {
		t.Fatal("pure HCloud preparation changed identity or resolved credentials", err)
	}
	var launch struct {
		Provider struct {
			Kind      string `json:"kind"`
			AccountID string `json:"account_id"`
			Region    string `json:"region"`
			Zone      string `json:"zone"`
		} `json:"provider"`
	}
	if json.Unmarshal(first.PublicJSON, &launch) != nil || launch.Provider.Kind != "hetzner" || launch.Provider.AccountID != "" || launch.Provider.Region != "eu-central" || launch.Provider.Zone != "hel1" || a.Region != "hel1" || a.Physical != nil || a.HCloudWitness != nil {
		t.Fatal("pre-CREATE System geometry invented account, physical proof or changed market location")
	}
	for _, change := range []func(*model.CapacityNativeWorkerAttempt){func(a *model.CapacityNativeWorkerAttempt) { a.Provider = "hcloud" }, func(a *model.CapacityNativeWorkerAttempt) { a.Provider = "aws" }, func(a *model.CapacityNativeWorkerAttempt) { a.Region = "eu-central" }, func(a *model.CapacityNativeWorkerAttempt) { a.Execution.ScopeSHA256 = strings.Repeat("0", 64) }} {
		bad := a
		change(&bad)
		if _, err := runtime.Prepare(bad); err == nil || credentials.Load() != 0 {
			t.Fatal("known-provider substitution, alias, zone or scope escaped frozen factory profile")
		}
	}
	// Preparation is not provider acceptance: the real paired qualifier still
	// requires immutable DB original/launch custody and a full typed witness.
	if _, err := runtime.Qualify(t.Context(), a, model.CapacityNativeWorkerOriginalReturn{}); err == nil || a.HCloudWitness != nil {
		t.Fatal("pure preparation became a qualified empty-account HCloud birth")
	}
	copy := *runtime
	if err := copy.Close(); err != nil || factory.MatchesExecution(execution) || runtime.SourceCommit() != "" {
		t.Fatal("successful HCloud runtime did not share handle ownership/Close", err)
	}
	if _, err := runtime.Prepare(a); err == nil {
		t.Fatal("closed HCloud runtime prepared another launch")
	}
}
