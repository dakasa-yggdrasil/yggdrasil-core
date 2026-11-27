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

func TestNativeConcreteRuntimePublishedFactoryHandlePrepareAndOwnership(t *testing.T) {
	systemSource, binary, binarySHA := os.Getenv("NATIVE_FACTORY_SYSTEM_SOURCE"), os.Getenv("NATIVE_FACTORY_SYSTEM_CLI"), os.Getenv("NATIVE_FACTORY_SYSTEM_SHA256")
	size, err := strconv.ParseInt(os.Getenv("NATIVE_FACTORY_SYSTEM_BYTES"), 10, 64)
	if len(systemSource) != 40 || !filepath.IsAbs(binary) || len(binarySHA) != 64 || err != nil || size < 1 {
		t.Fatal("actual published System factory artifact required; no skip or replacement")
	}
	f, _, _, _ := nativeAttemptFixture(t)
	p := f.p
	for i := range p.Profiles {
		p.Profiles[i].Provider, p.Profiles[i].Region = "aws", "us-east-1"
	}
	for i := range p.MarketBinding.Profiles {
		p.MarketBinding.Profiles[i].Provider, p.MarketBinding.Profiles[i].Region = "aws", "us-east-1"
	}
	for i := range p.NativeWorkerPoolBinding.Profiles {
		p.NativeWorkerPoolBinding.Profiles[i].Provider = "aws"
		p.NativeWorkerPoolBinding.Profiles[i].ProviderIDPrefix = "aws:///us-east-1a/"
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
	var phaseObservation *model.CapacityNativeWorkerPhaseReadObservation
	phaseReads := 0
	cfg := NativeWorkerConcreteRuntimeConfig{DB: f.db, Policy: policy, Factories: map[string]*capacity.NativeWorkerPrivateFactory{execution.Profile: factory}, PhaseRead: func(_ context.Context, b model.CapacityNativeWorkerPhaseReadBinding, providerID, birth string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		if phaseObservation == nil {
			t.Fatal("constructor/Prepare performed a Kubernetes read")
		}
		if b != *p.NativeWorkerLifecycleBinding.PhaseObserver || providerID != phaseObservation.RequestedProviderID || birth != phaseObservation.RequestedCreationProofSHA256 {
			t.Fatal("phase forwarding changed its protected binding or stored birth selector")
		}
		phaseReads++
		return *phaseObservation, nil
	}, PhysicalRead: func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		t.Fatal("constructor/Prepare performed a provider read")
		return model.CapacityNativeWorkerPhysicalObservation{}, errNativeWorkerConcreteRuntime
	}}
	bad := cfg
	bad.Policy.Kind = "workflow"
	if _, err := newNativeWorkerConcreteRuntime(bad, p.NativeWorkerLifecycleBinding.SourceCommit); err == nil || !factory.MatchesExecution(execution) {
		t.Fatal("failed constructor stole or closed caller handle")
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
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Namespace: policy.Metadata.Namespace, Domain: p.Domain, PoolUID: p.NativeWorkerPoolBinding.PoolUID, PoolEpoch: p.NativeWorkerPoolBinding.ExpectedPoolEpoch, Generation: 2, FencingToken: 3, Registry: p.NativeWorkerPoolBinding.RegistryRef, Profile: execution.Profile, Provider: "aws", Region: "us-east-1", SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, Execution: execution, OverlayIPv4: "10.81.0.7", IntentSHA256: strings.Repeat("c", 64), State: "reserved"}
	first, err := runtime.Prepare(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.Prepare(a)
	if err != nil || !bytes.Equal(first.PublicJSON, second.PublicJSON) || credentials.Load() != 0 {
		t.Fatal("concrete preparation selected changed map/material or performed WAN", err)
	}
	// The same constructed handle must implement the third, real phase port.
	// This fixture's Node/registry data are CI inputs to the original reader;
	// no provider ACK, network warmup or admission permission is synthesized.
	now := time.Now().UTC()
	pool := p.NativeWorkerPoolBinding
	profile := pool.Profiles[0]
	a.State, a.CreatedAt = "acknowledged", now.Add(-20*time.Second)
	a.ProviderIDPrefix = profile.ProviderIDPrefix
	a.PhysicalSpecSHA256, a.BirthSHA256, a.LaunchSHA256 = profile.PhysicalSpecSHA256, strings.Repeat("6", 64), hash(first.PublicJSON)
	a.Physical = &model.CapacityNativeWorkerPhysical{ResourceID: "i-11111111111111111", ProviderID: profile.ProviderIDPrefix + "i-11111111111111111", AccountID: "153828470928", InstanceType: "m7i.large", NetworkID: "subnet-11111111111111111", CreatedAt: now.Add(-10 * time.Second), ImageID: "ami-11111111111111111", Region: a.Region, Zone: "us-east-1a", NativeIPv4: "10.90.0.7", MACAddress: "02:00:00:00:00:07", PhysicalSpecSHA256: a.PhysicalSpecSHA256, PhysicalBindingSHA256: strings.Repeat("5", 64), LaunchSHA256: a.LaunchSHA256}
	node := model.CapacityNativeWorkerPhaseCandidate{NodeName: "ci-worker", NodeUID: uuid.NewString(), NodeResourceVersion: "31", ProviderID: a.Physical.ProviderID, Addresses: []model.CapacityNativeWorkerPhaseAddress{{Type: "InternalIP", Address: a.OverlayIPv4}}, PoolUIDLabel: pool.PoolUID, Taints: []model.CapacityNativeWorkerPhaseTaint{{Key: p.NativeWorkerLifecycleBinding.PhaseObserver.QuarantineTaintKey, Value: pool.PoolUID, Effect: "NoSchedule"}}}
	b := p.NativeWorkerLifecycleBinding.PhaseObserver
	phaseObservation = &model.CapacityNativeWorkerPhaseReadObservation{Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.Name, BindingScopeSHA256: b.ScopeSHA256, RequestedProviderID: a.Physical.ProviderID, RequestedCreationProofSHA256: a.BirthSHA256, ObservedAt: now, Complete: true, FullCollectionComplete: true, CollectionResourceVersion: "100", CandidateSelected: true, EvidenceSHA256: strings.Repeat("4", 64), Registry: model.CapacityNativeWorkerPhaseRegistry{Ref: pool.RegistryRef, RealmNamespace: b.RealmNamespace, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: p.Owner, Epoch: pool.ExpectedPoolEpoch, CurrentProfile: a.Profile, ResourceVersion: "20", AnnotationSHA256: strings.Repeat("3", 64)}, RegistryRegistrationsComplete: true, Candidates: []model.CapacityNativeWorkerPhaseCandidate{node}}
	var phases NativeWorkerPhaseRuntime = runtime
	prepared, err := phases.PreparePhase(t.Context(), a, "register")
	if err != nil || phaseReads != 1 || prepared.Context.Node.UID != node.NodeUID || prepared.NodeReady || prepared.NetworkVerified || prepared.WarmupVerified || prepared.PhysicalQualified {
		t.Fatal("constructed runtime lost real phase forwarding or fabricated readiness", err)
	}
	permit := prepared.Context
	w := p.NativeWorkerLifecycleBinding.RegistryWriter
	permit.PolicyID, permit.BindingName, permit.WriterScopeSHA256, permit.Operation = policy.ID, w.BindingName, w.ScopeSHA256, w.Capability
	permit.PoolUID, permit.Owner, permit.Epoch = pool.PoolUID, p.Owner, pool.ExpectedPoolEpoch
	permit.ExpiresAt = now.Add(-time.Hour) // Historical receiving remains GET-only.
	entry := model.CapacityNativeWorkerRegistryEntry{NodeUID: node.NodeUID, ProviderID: node.ProviderID, Profile: a.Profile, PhysicalSpecSHA256: a.PhysicalSpecSHA256, RegistrationBindingSHA256: profile.RegistrationBindingSHA, CapacityPolicyID: policy.ID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, CreationProofSHA256: a.BirthSHA256, Admission: model.CapacityNativeWorkerRegistryAdmission{State: "quarantined"}}
	phaseObservation.Registrations = []model.CapacityNativeWorkerRegistryEntry{entry}
	phaseObservation.Candidates[0].Registrations = []model.CapacityNativeWorkerRegistryEntry{entry}
	observed, err := phases.ObservePhase(t.Context(), permit)
	if err != nil || phaseReads != 2 || !observed.Applied || observed.NodeUID != node.NodeUID || observed.QuarantineAbsent || observed.Ready {
		t.Fatal("late phase GET lost registration truth or invented admitted capacity", err)
	}
	a.State, a.NodeUID = "registered", node.NodeUID
	for _, action := range []string{"admit_registry", "release_quarantine"} {
		if _, err := phases.PreparePhase(t.Context(), a, action); err == nil {
			t.Fatal("composition supplied missing independent network/warmup evidence", action)
		}
	}
	beforeRefusal := phaseReads
	for _, change := range []func(*model.CapacityNativeWorkerAttempt){func(a *model.CapacityNativeWorkerAttempt) { a.PolicyChecksum = "other" }, func(a *model.CapacityNativeWorkerAttempt) { a.PoolEpoch++ }, func(a *model.CapacityNativeWorkerAttempt) { a.Execution.ScopeSHA256 = strings.Repeat("0", 64) }} {
		bad := a
		change(&bad)
		if _, err := phases.PreparePhase(t.Context(), bad, "register"); err == nil || phaseReads != beforeRefusal {
			t.Fatal("substituted phase attempt reached the independent reader")
		}
	}
	for _, change := range []func(*model.CapacityNativeWorkerPhasePermit){func(c *model.CapacityNativeWorkerPhasePermit) { c.WriterScopeSHA256 = strings.Repeat("0", 64) }, func(c *model.CapacityNativeWorkerPhasePermit) { c.Epoch++ }, func(c *model.CapacityNativeWorkerPhasePermit) { c.BindingName = "other" }} {
		bad := permit
		change(&bad)
		if _, err := phases.ObservePhase(t.Context(), bad); err == nil || phaseReads != beforeRefusal {
			t.Fatal("substituted phase permission reached the independent reader")
		}
	}
	copy := *runtime
	if err := copy.Close(); err != nil || factory.MatchesExecution(execution) || runtime.SourceCommit() != "" {
		t.Fatal("successful composition did not own the shared factory Close", err)
	}
	if _, err := runtime.Prepare(a); err == nil {
		t.Fatal("closed runtime prepared another launch")
	}
	if _, err := phases.ObservePhase(t.Context(), permit); err == nil || phaseReads != beforeRefusal {
		t.Fatal("closed shared handle retained an independent phase port")
	}
}
