//go:build linux && nativefactoryqualification

package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Construct the actual private TLS handle without dialing it. Only provider
// and Kubernetes facts are synthetic Go ports; floor TLS, the published CLI
// factory, database, immutable archive and abort/network stores are products.
func nativeAbortRuntimeReadClient(t *testing.T, adapter model.CapacityMarketAdapterBinding, profile, binding, source, scope, capability string) *capacity.NativeWorkerRPCClient {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI-only-abort-read"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CI-only-Core-read"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, clientPub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	c, err := capacity.NewNativeWorkerRPCClient(capacity.NativeWorkerRPCConfig{Adapter: adapter, Profile: profile, BindingName: binding, SDKSourceCommit: source, ScopeSHA256: scope, BaseURL: "https://127.0.0.1:9446", HealthURL: "http://127.0.0.1:8080/healthz", ServerCAFile: write("ca.pem", caPEM), ServerCASHA256: fmt.Sprintf("%x", sha256.Sum256(caPEM)), ServerCertificateSHA256: strings.Repeat("a", 64), ClientCertificateFile: write("client.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), ClientKeyFile: write("client-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), AllowedCapabilities: []string{capability}})
	if err != nil {
		t.Fatal("real private read handle", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type nativeAbortRuntimeFixture struct {
	x              *nativeNetworkRuntimeFixture
	runtime        *NativeWorkerConcreteAbortRuntime
	config         NativeWorkerConcreteAbortRuntimeConfig
	gone           atomic.Bool
	retainVolume   atomic.Bool
	providerReads  atomic.Int32
	inventoryReads atomic.Int32
	sourceDrift    atomic.Bool
}

func newNativeAbortRuntimeFixture(t *testing.T) *nativeAbortRuntimeFixture {
	t.Helper()
	x := newNativeNetworkRuntimeFixtureWithPolicy(t, func(p *model.CapacityPolicySpec) {
		b := *p.NativeWorkerLifecycleBinding.PhaseObserver
		b.Name, b.ScopeSHA256, b.Adapter.ManifestID = "ci-abort-inventory", strings.Repeat("6", 64), uuid.NewString()
		p.NativeWorkerLifecycleBinding.AbortInventoryObserver = &b
	})
	f := &nativeAbortRuntimeFixture{x: x}
	p := x.f.p
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	ib := p.NativeWorkerLifecycleBinding.AbortInventoryObserver
	provider := nativeAbortRuntimeReadClient(t, b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup)
	inventory := nativeAbortRuntimeReadClient(t, ib.Adapter, ib.Name, ib.Name, ib.SourceCommit, ib.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory)
	cleanup := func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, in model.CapacityNativeWorkerCleanupRequest) (model.CapacityNativeWorkerCleanupObservation, error) {
		f.providerReads.Add(1)
		now := time.Now().UTC()
		fp := in.Footprint
		mode := "closure"
		if fp == nil {
			mode = "snapshot"
			v := x.observation
			q := v.Physical
			fp = &model.CapacityNativeWorkerResourceFootprint{Schema: "native_worker_resource_footprint_v1", Provider: "aws", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: v.Requested, ActualPoolUID: v.ActualTags.PoolUID, ObservedAt: now, Physical: model.CapacityNativeWorkerCleanupPhysical{ResourceID: q.ResourceID, ProviderID: q.ProviderID, AccountID: q.AccountID, InstanceType: q.InstanceType, NetworkID: q.NetworkID, NativeNetworkCIDR: q.NativeNetworkCIDR, CreatedAt: q.CreatedAt, ImageID: q.ImageID, Region: q.Region, Zone: q.Zone, NativeIPv4: q.NativeIPv4, MACAddress: q.MACAddress, PhysicalSpecSHA256: q.PhysicalSpecSHA256, LaunchSHA256: q.LaunchSHA256}, AWS: &model.CapacityNativeWorkerAWSResourceFootprint{RootVolume: model.CapacityNativeWorkerCleanupVolume(v.RootVolume), PrimaryInterface: model.CapacityNativeWorkerCleanupInterface(v.PrimaryInterface), InstanceState: "running", PublicIPv4Kind: "none"}}
			fp.EvidenceSHA256 = capacity.NativeWorkerResourceFootprintSHA256(*fp)
		}
		o := model.CapacityNativeWorkerCleanupObservation{Schema: "native_worker_cleanup_observation_v1", Provider: "aws", Mode: mode, SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: fp.Requested, StartedAt: now, ObservedAt: now, Complete: true, Footprint: fp, Resources: []model.CapacityNativeWorkerCleanupResource{{Kind: "instance", ResourceID: in.ResourceID, Outcome: "present", NativeState: "running"}, {Kind: "volume", ResourceID: fp.AWS.RootVolume.ResourceID, Outcome: "present", NativeState: "in-use", AttachedInstanceID: in.ResourceID}, {Kind: "network_interface", ResourceID: fp.AWS.PrimaryInterface.ResourceID, Outcome: "present", NativeState: "in-use", AttachedInstanceID: in.ResourceID}}}
		for _, pair := range [][2]string{{"GetCallerIdentity", "caller"}, {"DescribeSubnets", "network"}, {"DescribeInstances", "before"}, {"DescribeVolumes", "root_volume"}, {"DescribeNetworkInterfaces", "primary_interface"}, {"DescribeInstances", "after"}} {
			o.AWSReads = append(o.AWSReads, model.CapacityNativeWorkerCleanupAWSRead{Operation: pair[0], Role: pair[1], RequestID: "ci-synthetic-" + pair[1], ObservedAt: now})
		}
		if f.gone.Load() {
			if in.Footprint == nil {
				return model.CapacityNativeWorkerCleanupObservation{}, fmt.Errorf("snapshot has no present resource")
			}
			for i, code := range []string{"InvalidInstanceID.NotFound", "InvalidVolume.NotFound", "InvalidNetworkInterfaceID.NotFound"} {
				o.Resources[i].Outcome, o.Resources[i].NotFoundCode, o.Resources[i].NativeState, o.Resources[i].AttachedInstanceID = "not_found", code, "", ""
			}
			if f.retainVolume.Load() {
				o.Resources[1].Outcome, o.Resources[1].NotFoundCode, o.Resources[1].NativeState = "present", "", "available"
			}
		}
		if f.sourceDrift.Load() {
			o.SourceCommit = strings.Repeat("0", 40)
		}
		raw, _ := json.Marshal(o)
		o.EvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
		return o, nil
	}
	readInventory := func(_ context.Context, b model.CapacityNativeWorkerPhaseReadBinding, in model.CapacityNativeWorkerAbortInventoryRequest) (model.CapacityNativeWorkerAbortInventoryObservation, error) {
		f.inventoryReads.Add(1)
		phase := phaseAuthorityTestHeader(p)
		phase.SourceCommit, phase.Adapter, phase.BindingName, phase.BindingScopeSHA256 = b.SourceCommit, b.Adapter, b.Name, b.ScopeSHA256
		phase.Registrations[0].ProviderID = "aws:///us-east-1a/i-22222222222222222"
		phase.CandidateSelected, phase.CandidateAbsenceProven = true, true
		phase.RequestedProviderID, phase.RequestedCreationProofSHA256 = in.ProviderID, in.CreationProofSHA256
		return model.CapacityNativeWorkerAbortInventoryObservation{Schema: "native_worker_abort_inventory_v1", SourceCommit: b.SourceCommit, BindingScopeSHA256: b.ScopeSHA256, Adapter: b.Adapter, BindingName: b.Name, Requested: in, ObservedAt: time.Now().UTC(), Phase: phase, BeforePhaseEvidence: strings.Repeat("1", 64), Complete: true, PodsComplete: true, PodsAllNamespaces: true, PodCollectionVersion: "ci-all-namespace-pods", TargetPodEvidenceSHA256: strings.Repeat("2", 64), EvidenceSHA256: strings.Repeat("3", 64)}, nil
	}
	f.config = NativeWorkerConcreteAbortRuntimeConfig{DB: x.f.db, Policy: x.f.policy, Network: x.runtime, CleanupRead: cleanup, InventoryRead: readInventory, RPCClients: []*capacity.NativeWorkerRPCClient{provider, inventory}}
	r, err := newNativeWorkerConcreteAbortRuntime(f.config, x.workers.SourceCommit())
	if err != nil {
		t.Fatal("actual abort composition", err)
	}
	f.runtime = r
	t.Cleanup(func() { _ = r.Close() })
	return f
}

func TestNativeAbortRuntimePublishedFactoryAndImmutableFootprintBeforeOneSend(t *testing.T) {
	f := newNativeAbortRuntimeFixture(t)
	x := f.x
	a := x.child(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if f.runtime.SourceCommit() != x.workers.SourceCommit() || !f.runtime.BoundToDatabase(x.f.db) || f.providerReads.Load() != 0 {
		t.Fatal("constructor performed WAN or lost identity")
	}
	store := CapacityNativeWorkerAbortStore{Workers: x.store, Runtime: f.runtime, RecoveryWorkflowID: x.recovery, Enabled: true}
	permit, err := store.Begin(ctx, x.f.policy, a.ID)
	if err != nil {
		t.Fatal("real Begin", err)
	}
	retained := abortPGStored(t, x.f, permit.PermitID)
	if retained.Observation == nil || retained.Observation.ResourceFootprint == nil || retained.TokenSHA256 != "" {
		t.Fatal("snapshot was not retained before any send right")
	}
	origin, _ := json.Marshal(retained.Observation.ResourceFootprint)
	caller := abortPGCaller(a)
	send, err := store.Redeem(ctx, x.f.policy, permit.PermitID, caller)
	if err != nil || !send.MutationPermitted || send.SettlementToken == "" {
		t.Fatal("real one-send permission", err)
	}
	if _, err = store.Redeem(ctx, x.f.policy, permit.PermitID, caller); err == nil {
		t.Fatal("second delete right exposed")
	}
	f.gone.Store(true)
	f.retainVolume.Store(true)
	result, err := store.Reconcile(ctx, x.f.policy, permit.PermitID, caller)
	if err != nil || result.State == "observed" {
		t.Fatal("retained EBS became complete absence", result.State, err)
	}
	abortPGState(t, x.f, store, a.ID, "aborting")
	f.retainVolume.Store(false)
	result, err = store.Reconcile(ctx, x.f.policy, permit.PermitID, caller)
	if err != nil || result.State != "observed" || result.MutationPermitted {
		t.Fatal("all independent closure refused", result.State, err)
	}
	abortPGState(t, x.f, store, a.ID, "absent")
	var archived []byte
	if err = x.f.db.QueryRowContext(ctx, `SELECT record#>'{observation,resource_footprint}' FROM public.capacity_native_worker_abort_events WHERE permit_id=$1 AND revision=1`, permit.PermitID).Scan(&archived); err != nil {
		t.Fatal(err)
	}
	var fp model.CapacityNativeWorkerResourceFootprint
	if json.Unmarshal(archived, &fp) != nil {
		t.Fatal("original immutable footprint lost")
	}
	actual, _ := json.Marshal(fp)
	if !bytes.Equal(origin, actual) {
		t.Fatal("later reconciliation rewrote immutable resource origin")
	}
	if x.writerCalls.Load() != 0 || x.credentials.Load() != 0 {
		t.Fatal("read-only cleanup rendered, hydrated or mutated provider/floor")
	}
}

func TestNativeAbortRuntimeRefusesCopiedOwnershipScopeAndMissingArchive(t *testing.T) {
	f := newNativeAbortRuntimeFixture(t)
	x := f.x
	a := x.child(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	config := f.config
	copyClient := *config.RPCClients[0]
	x.workers.mu.Lock()
	x.workers.clients = append(x.workers.clients, config.RPCClients[0])
	x.workers.mu.Unlock()
	config.RPCClients = append([]*capacity.NativeWorkerRPCClient(nil), config.RPCClients...)
	config.RPCClients[0] = &copyClient
	if _, err := newNativeWorkerConcreteAbortRuntime(config, x.workers.SourceCommit()); err == nil {
		t.Fatal("copied borrowed client acquired Close ownership")
	}
	x.workers.mu.Lock()
	x.workers.clients = nil
	x.workers.mu.Unlock()
	b := x.f.p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	if !copyClient.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
		t.Fatal("failed constructor closed caller-owned handle")
	}
	changed := x.f.policy
	changed.Spec = bytes.Clone(changed.Spec)
	changed.Spec[0] ^= 1
	if _, err := f.runtime.ObserveAbort(ctx, changed, a); err == nil || f.providerReads.Load() != 0 || f.inventoryReads.Load() != 0 {
		t.Fatal("wrong policy reached remote read")
	}
	f.sourceDrift.Store(true)
	if _, err := f.runtime.ObserveAbort(ctx, x.f.policy, a); err == nil || f.inventoryReads.Load() != 0 {
		t.Fatal("changed provider Source reached Kubernetes")
	}
	f.sourceDrift.Store(false)
	if err := x.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	before := f.providerReads.Load()
	if _, err := f.runtime.ObserveAbort(ctx, x.f.policy, a); err == nil || f.providerReads.Load() != before {
		t.Fatal("unreadable original archive acquired a remote read")
	}
	if err := f.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if f.runtime.SourceCommit() != "" || !x.runtime.BoundToDatabase(x.f.db) || x.workers.SourceCommit() == "" {
		t.Fatal("Close did not fence copies or closed borrowed composition")
	}
}
