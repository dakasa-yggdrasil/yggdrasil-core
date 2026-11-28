package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// Synthetic protected GET-only readers, never a provider/System/Kubernetes
// client. DB attempts/births, permission, original custody and DDL are real.
type networkPGRuntime struct {
	*abortPGRuntime
	networkMu              sync.Mutex
	installed, basePresent bool
}

func (r *networkPGRuntime) ObservePhaseAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	header := phaseAuthorityTestHeader(r.p)
	return &header, nil // Explicit complete nonempty quarantined registry, no useful-pool synthesis.
}
func networkPGWorkerKey(id uuid.UUID) string {
	sum := sha256.Sum256([]byte("CI synthetic public key " + id.String()))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (r *networkPGRuntime) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	b := r.p.NativeWorkerLifecycleBinding.Network
	// A complete public launch precedes Reserve commit. No private key or
	// qualified System factory is fabricated by this CI-only fixture.
	v := map[string]any{"schema": 1, "mode": "native_k3s_worker_v1", "source_commit": a.Execution.BootstrapSourceCommit, "pool_id": "ci-workers", "pool_uid": a.PoolUID, "registry": a.Registry, "policy_id": a.PolicyID.String(), "policy_sha256": strings.TrimPrefix(a.PolicyChecksum, "sha256:"), "expected_pool_epoch": a.PoolEpoch, "intent_generation": a.Generation, "fencing_token": a.FencingToken, "reservation_id": a.ID.String(), "intent_sha256": a.IntentSHA256,
		"provider": map[string]any{"kind": "hetzner", "account_id": "", "region": "eu-central", "zone": "hel1", "image_id": "76543", "native_network_cidr": "10.90.0.0/24"},
		"floor":    map[string]any{"node_name": b.Floor.NodeName, "node_uid": b.Floor.NodeUID, "provider_id": b.Floor.ProviderID, "cluster_uid": b.Floor.ClusterUID, "api_endpoint": "https://" + b.Floor.NativeIPv4 + ":6443", "ca_sha256": b.Floor.CASHA256, "node_network_cidr": "10.70.0.0/16"},
		"network":  map[string]any{"mode": "wireguard_routed_v1", "transport_cidr": b.Template.TransportCIDR, "worker_ipv4": a.OverlayIPv4, "floor_peer_ipv4": b.Template.FloorPeerIPv4, "floor_peer_endpoint": "203.0.113.2:51820", "floor_peer_public_key": b.Template.FloorPublicKey, "worker_public_key": networkPGWorkerKey(a.ID), "pod_cidr": b.Template.PodCIDR, "service_cidr": b.Template.ServiceCIDR},
		"operator": map[string]any{"source_commit": a.Execution.BootstrapSourceCommit, "sha256": strings.Repeat("b", 64), "bytes": 12345, "capability_ref": "native-private://ci-operator", "expected_hostname": "ci-fixture.s3.us-east-1.amazonaws.com"},
		"reserve":  map[string]any{"kube_milli_cpu": 100, "kube_memory_mib": 128, "system_milli_cpu": 100, "system_memory_mib": 128, "eviction_memory_mib": 128}}
	raw, e := json.Marshal(v)
	return model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: a.Execution.LaunchTemplateSHA256, PublicJSON: raw}, e
}

func (r *networkPGRuntime) floor(a model.CapacityNativeWorkerAttempt) model.CapacityNativeWorkerNetworkObservation {
	r.networkMu.Lock()
	defer r.networkMu.Unlock()
	b := r.p.NativeWorkerLifecycleBinding.Network
	o := model.CapacityNativeWorkerNetworkObservation{Schema: model.CapacityNativeWorkerNetworkObservationSchema, BindingName: b.Reader.BindingName, AdapterSourceCommit: b.Reader.SystemSourceCommit, ReaderScopeSHA256: b.Reader.ScopeSHA256, Requested: model.CapacityNativeWorkerNetworkObserveInput{BindingName: b.Reader.BindingName, AttemptID: a.ID.String(), LaunchSHA256: a.LaunchSHA256, WorkerPublicKey: networkPGWorkerKey(a.ID), WorkerIPv4: a.OverlayIPv4}, ObservedAt: time.Now().UTC(), Floor: model.CapacityNativeWorkerNetworkFloorFacts{Bound: b.Floor, Observed: model.CapacityNativeWorkerNetworkHostIdentity{Hostname: b.Floor.NodeName, CASHA256: b.Floor.CASHA256, CAOrigin: "source_bound_local_certificate", NativeInterfaceIndex: 2, NativeInterfaceUp: true, NativeIPv4Present: true}}, NetworkTemplateSHA256: b.TemplateSHA256, MTU: 1380, Interface: model.CapacityNativeWorkerNetworkInterfaceFacts{Name: b.Template.Interface, Addresses: []string{}}, Peers: []model.CapacityNativeWorkerNetworkPeerFacts{}, Routes: []model.CapacityNativeWorkerNetworkRouteFacts{}, Firewall: model.CapacityNativeWorkerNetworkFirewallFacts{Chain: "inet/dakasa_native/DAKASA_NATIVE", Rules: []string{}, Complete: true}, KernelSettings: model.CapacityNativeWorkerNetworkKernelSettings{IPForward: 1, AllRPFilter: 2, NativeRPFilter: 2}, KernelInventoryComplete: true}
	if r.basePresent || r.installed {
		o.Interface = model.CapacityNativeWorkerNetworkInterfaceFacts{Present: true, Name: b.Template.Interface, IfIndex: 20, MTU: 1380, Up: true, Addresses: []string{b.Template.FloorPeerIPv4 + "/32"}, PublicKey: b.Template.FloorPublicKey, ListenPort: b.Template.ListenPort}
		o.Firewall.Rules = []string{"dakasa-native:drop"}
		o.KernelSettings.WireGuardRPFilter = 2
		o.KernelSettings.WireGuardRPFilterObserved = true
	}
	if r.installed {
		o.Peers = []model.CapacityNativeWorkerNetworkPeerFacts{{PublicKey: networkPGWorkerKey(a.ID), AllowedIPs: []string{a.OverlayIPv4 + "/32"}, Endpoint: "198.51.100.12:52345", LastHandshakeUnix: time.Now().Unix()}}
		o.Routes = []model.CapacityNativeWorkerNetworkRouteFacts{{Destination: a.OverlayIPv4 + "/32", Device: b.Template.Interface, PreferredSource: b.Floor.NativeIPv4}}
		o.Firewall.Rules = []string{"dakasa-native:" + a.ID.String() + "|198.51.100.12", "dakasa-native:drop"}
	}
	o.Firewall.RulesSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(o.Firewall.Rules, "\n")+"\n")))
	return o
}
func (r *networkPGRuntime) PrepareNetwork(_ context.Context, _ model.Manifest, a model.CapacityNativeWorkerAttempt, action string) (capacity.NativeWorkerNetworkPreparation, error) {
	if a.Physical == nil {
		return capacity.NativeWorkerNetworkPreparation{}, ErrCapacityConflict
	}
	b := r.p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	if action == "remove" {
		// Provider may already be gone. These are only sealed target fields,
		// not a fabricated fresh provider GET. The deliberately different runtime
		// endpoint must be replaced by the immutable original install endpoint.
		return capacity.NativeWorkerNetworkPreparation{Floor: r.floor(a), Physical: *a.Physical, TransportEndpointIPv4: "203.0.113.99"}, nil
	}
	return capacity.NativeWorkerNetworkPreparation{Floor: r.floor(a), Physical: *a.Physical, PhysicalObservedAt: time.Now().UTC(), PhysicalEvidenceSHA256: strings.Repeat("7", 64), PhysicalSourceCommit: b.SourceCommit, PhysicalScopeSHA256: b.ScopeSHA256, TransportEndpointIPv4: "198.51.100.12"}, nil
}
func (r *networkPGRuntime) ObserveNetwork(_ context.Context, _ model.Manifest, a model.CapacityNativeWorkerAttempt, _ model.CapacityNativeWorkerNetworkGrant) (model.CapacityNativeWorkerNetworkObservation, error) {
	return r.floor(a), nil
}

func networkPGFixture(t *testing.T) (marketRepositoryFixture, CapacityNativeWorkerNetworkStore, *networkPGRuntime, model.CapacityNativeWorkerAuthority) {
	t.Helper()
	f, w, provider, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) {
		phaseAuthorityTestBinding(p)
		life, pool := p.NativeWorkerLifecycleBinding, p.NativeWorkerPoolBinding
		life.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: p.Workflow.Namespace, Name: "cleanup-network-workers"}, MaxPermitSeconds: 30}
		adapter := life.Profiles[0].Adapter
		adapter.ManifestID = uuid.NewString()
		life.PhysicalObservers = []model.CapacityNativeWorkerPhysicalReadBinding{{Profile: p.Profiles[0].Name, Provider: p.Profiles[0].Provider, Region: p.Profiles[0].Region, Adapter: adapter, BindingName: "ci-independent-physical", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("8", 64), Capability: capacity.ObserveNativeWorkerPhysical}}
		floor := model.CapacityNativeWorkerNetworkFloorIdentity{NodeName: "ci-floor", NodeUID: uuid.NewString(), ProviderID: "hcloud://10000", ClusterUID: pool.RealmUID, CASHA256: strings.Repeat("9", 64), NativeIPv4: "10.70.1.2", NativeInterface: "enp7s0"}
		pool.ProtectedNodes = append(pool.ProtectedNodes, model.CapacityNativeProtectedNode{NodeUID: floor.NodeUID, ProviderID: floor.ProviderID})
		n := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: life.Profiles[0].BootstrapSourceCommit, Interface: "wg-dakasa", MTU: 1380, TransportCIDR: life.Profiles[0].OverlayCIDR, FloorPeerIPv4: life.Profiles[0].ExcludedIPv4[0], FloorPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("f", 32))), ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: "172.29.0.0/16", ServiceCIDR: "172.30.0.0/16", ClusterDNSIPv4: "172.30.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
		life.Network = &model.CapacityNativeWorkerNetworkBinding{Mode: capacity.NativeWorkerNetworkMode, Writer: model.CapacityNativeWorkerNetworkWriterBinding{AdapterID: uuid.NewString(), PrincipalID: "ci-floor-writer", BindingName: "ci-floor-writer", SystemSourceCommit: n.GuestSystemSourceCommit, ScopeSHA256: strings.Repeat("1", 64)}, Reader: model.CapacityNativeWorkerNetworkReaderBinding{AdapterID: uuid.NewString(), BindingName: "ci-floor-reader", SystemSourceCommit: n.GuestSystemSourceCommit, ScopeSHA256: strings.Repeat("2", 64)}, Floor: floor, Template: n, TemplateSHA256: capacity.NativeWorkerNetworkTemplateSHA256(n), MaxPermitSeconds: 30}
	})
	raw := json.RawMessage(`{"authorization":{}}`)
	recovery, e := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: "cleanup-network-workers"}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if e != nil {
		t.Fatal(e)
	}
	r := &networkPGRuntime{abortPGRuntime: &abortPGRuntime{nativeAttemptRuntime: provider, p: f.p}}
	w.Runtime = r
	return f, CapacityNativeWorkerNetworkStore{Workers: w, Runtime: r, AbortRuntime: r, RecoveryWorkflowID: recovery.ID, Enabled: true}, r, authority
}

func networkPGChild(t *testing.T, f marketRepositoryFixture, s CapacityNativeWorkerNetworkStore, auth model.CapacityNativeWorkerAuthority) model.CapacityNativeWorkerAttempt {
	t.Helper()
	a, e := s.Workers.Reserve(t.Context(), f.policy, auth)
	if e != nil {
		t.Fatal("network-bound actual Reserve failed", e)
	}
	if _, e = s.Workers.Redeem(t.Context(), f.policy, auth, a.ID); e != nil {
		t.Fatal(e)
	}
	a, e = s.Workers.Record(t.Context(), f.policy, auth, a.ID)
	if e != nil || a.State != "acknowledged" || a.Physical == nil || a.Physical.AccountID == "" {
		t.Fatal("actual sealed child required", e)
	}
	return a
}
func networkPGCaller(p model.CapacityPolicySpec, action string) CapacityNativeWorkerNetworkCaller {
	w := p.NativeWorkerLifecycleBinding.Network.Writer
	capability := capacity.NativeWorkerNetworkInstall
	if action == "remove" {
		capability = capacity.NativeWorkerNetworkRemove
	}
	return CapacityNativeWorkerNetworkCaller{PrincipalID: w.PrincipalID, InstanceID: w.AdapterID, SystemSourceCommit: w.SystemSourceCommit, BindingName: w.BindingName, Capability: capability}
}
func networkPGOriginal(g model.CapacityNativeWorkerNetworkGrant, closed bool) model.CapacityNativeWorkerNetworkOriginalReturn {
	now := time.Now().UTC()
	start := now.Add(-time.Second)
	body := map[string]any{"schema": "native_worker_network_original_batch_v1", "permit_id": g.PermitID, "attempt_id": g.AttemptID, "action": g.Action, "started_at": start, "returned_at": now, "execution_complete": false, "steps": []any{map[string]any{"step": "ci-original-host-step", "started_at": start, "returned_at": now, "process_started": true, "wait_returned": closed, "exit_code": 1, "capture_complete": false, "stdout": []byte("ci-private-original-prefix"), "stderr": []byte("ci-private-close-error")}}}
	raw, _ := json.Marshal(body)
	return model.CapacityNativeWorkerNetworkOriginalReturn{Schema: "native_worker_network_receive_v1", PermitID: g.PermitID, BindingName: g.BindingName, OriginalReturn: raw, CaptureComplete: false, ErrorClass: "CI_ORIGINAL_TRANSPORT_UNCERTAIN"}
}

func TestNativeWorkerNetworkPostgresOneSendAndLatePrivateCustody(t *testing.T) {
	f, s, _, auth := networkPGFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	a := networkPGChild(t, f, s, auth)
	caller := networkPGCaller(f.p, "install")
	g, e := s.Begin(ctx, f.policy, a.ID, "install")
	if e != nil {
		t.Fatal("network Begin failed", e)
	}
	id := uuid.MustParse(g.PermitID)
	read, e := s.Read(ctx, f.policy, id, caller)
	if e != nil || !read.Redeemable || read.MutationPermitted {
		t.Fatal("read did not preserve separate send right", e)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.Redeem(ctx, f.policy, id, caller)
			if e == nil {
				if !v.MutationPermitted || v.Redeemable || v.State != "redeemed" {
					t.Error("successful redemption lost one-use grant")
				}
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal("network command was replayed or never consumed", won.Load())
	}
	if _, e = s.Redeem(ctx, f.policy, id, caller); e == nil {
		t.Fatal("retry returned second permission")
	}
	disabled := s
	disabled.Enabled = false
	disabled.Workers.Enabled = false
	disabled.Workers.Capacity.ExecutionEnabled = false
	if _, e = f.db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, f.policy.ID); e != nil {
		t.Fatal(e)
	}
	v := networkPGOriginal(g, false)
	if e = disabled.Receive(ctx, f.policy, caller, v); e != nil {
		t.Fatal("historical original lost after gates/policy closed", e)
	}
	stored, e := s.load(ctx, f.policy, id)
	if e != nil || stored.Original == nil || stored.OriginalCallerClosed || stored.Context.State != "unknown" || string(stored.Original.OriginalReturn) != string(v.OriginalReturn) {
		t.Fatal("unknown original lost custody or claimed quiescence", e)
	}
	read, e = disabled.Read(ctx, f.policy, id, caller)
	if e != nil || read.MutationPermitted || read.Redeemable {
		t.Fatal("historical read reauthorized send", e)
	}
	wire, _ := json.Marshal(read)
	for _, private := range []string{"ci-private-original-prefix", "ci-private-close-error", stored.ExecutorID, "original_return", "original_caller_closed"} {
		if strings.Contains(string(wire), private) {
			t.Fatal("private network history escaped public context")
		}
	}
	var revisions int
	if e = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_network_events WHERE permit_id=$1`, id).Scan(&revisions); e != nil || revisions != 3 {
		t.Fatal("every actual revision must have DB event", revisions, e)
	}
	if e = disabled.Receive(ctx, f.policy, caller, v); e != nil {
		t.Fatal("exact original duplicate was not idempotent", e)
	}
	v.OriginalReturn = []byte("replacement original")
	if e = disabled.Receive(ctx, f.policy, caller, v); e == nil {
		t.Fatal("different original overwrote custody")
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_worker_network_permits SET revision=revision+1,record=jsonb_set(jsonb_set(record,'{original,error_class}','"rewritten"'::jsonb),'{revision}',to_jsonb(revision+1)) WHERE id=$1`,
		`UPDATE public.capacity_native_worker_network_events SET record=record||'{"forged":true}'::jsonb WHERE permit_id=$1`,
		`DELETE FROM public.capacity_native_worker_network_events WHERE permit_id=$1`,
		`DELETE FROM public.capacity_native_worker_network_permits WHERE id=$1`,
	} {
		if _, e = f.db.ExecContext(ctx, query, id); e == nil {
			t.Fatal("retained network origin/event was mutable")
		}
	}
	if e = goose.DownTo(f.db, "../db/migrations", 116); e == nil {
		t.Fatal("Down erased retained network commands")
	}
	version, e := goose.GetDBVersion(f.db)
	if e != nil || version != 117 {
		t.Fatal("failed Down changed schema boundary", version, e)
	}
	current, e := s.Workers.Read(ctx, f.policy, a.ID)
	if e != nil || current.State != "acknowledged" {
		t.Fatal("unknown host send released child/IP accounting", e)
	}
}

func TestNativeWorkerNetworkPostgresCleanupRequiresClosedProducerAndCompensatingRemoval(t *testing.T) {
	f, s, r, auth := networkPGFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	a := networkPGChild(t, f, s, auth)
	var launch []byte
	if e := f.db.QueryRowContext(ctx, `SELECT launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1`, a.ID).Scan(&launch); e != nil {
		t.Fatal(e)
	}
	prepared, e := r.PrepareNetwork(ctx, f.policy, a, "install")
	if e != nil || !capacity.NativeWorkerNetworkPreparationValidForAction(f.p, a, json.RawMessage(launch), prepared, "install", time.Now().UTC()) {
		t.Fatal("coherent baseline preparation refused", e)
	}
	policyJSON, e := json.Marshal(f.p)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"pod_cidr", "service_cidr"} {
		t.Run("coherent_new_"+field+"_cannot_rewrite_original_launch", func(t *testing.T) {
			var bad model.CapacityPolicySpec
			if e := json.Unmarshal(policyJSON, &bad); e != nil {
				t.Fatal(e)
			}
			b := bad.NativeWorkerLifecycleBinding.Network
			if field == "pod_cidr" {
				b.Template.PodCIDR = "172.28.0.0/16"
			} else {
				b.Template.ServiceCIDR = "172.31.0.0/16"
				b.Template.ClusterDNSIPv4 = "172.31.0.10"
			}
			b.TemplateSHA256 = capacity.NativeWorkerNetworkTemplateSHA256(b.Template)
			coherent := prepared
			coherent.Floor.NetworkTemplateSHA256 = b.TemplateSHA256
			if e := capacity.ValidateNativeWorkerNetworkBinding(bad); e != nil {
				t.Fatal("negative is structurally invalid instead of a coherent substitution", e)
			}
			if capacity.NativeWorkerNetworkPreparationValidForAction(bad, a, json.RawMessage(launch), coherent, "install", time.Now().UTC()) {
				t.Fatal("new coherent template/observation rewrote original launch", field)
			}
		})
	}
	installCaller := networkPGCaller(f.p, "install")
	g, e := s.Begin(ctx, f.policy, a.ID, "install")
	if e != nil {
		t.Fatal(e)
	}
	id := uuid.MustParse(g.PermitID)
	if _, e = s.Redeem(ctx, f.policy, id, installCaller); e != nil {
		t.Fatal(e)
	}
	cleanup := CapacityNativeWorkerAbortStore{Workers: s.Workers, Runtime: r, RecoveryWorkflowID: s.RecoveryWorkflowID, Enabled: true}
	if _, e = cleanup.Begin(ctx, f.policy, a.ID); e == nil {
		t.Fatal("cleanup overtook an exposed network writer")
	}
	// A current absent peer alone says nothing about a still-running sender.
	read, e := s.Reconcile(ctx, f.policy, id, installCaller)
	if e != nil || read.State != "unknown" {
		t.Fatal("absent peer was mistaken for producer closure", read.State, e)
	}
	if _, e = cleanup.Begin(ctx, f.policy, a.ID); e == nil {
		t.Fatal("momentary absence released the writer fence")
	}
	r.networkMu.Lock()
	r.installed, r.basePresent = true, true
	r.networkMu.Unlock()
	if e = s.Receive(ctx, f.policy, installCaller, networkPGOriginal(g, true)); e != nil {
		t.Fatal("closed failed caller could not preserve original", e)
	}
	stored, e := s.load(ctx, f.policy, id)
	if e != nil || !stored.OriginalCallerClosed || stored.Original == nil || stored.Original.CaptureComplete || stored.Context.State != "unknown" {
		t.Fatal("caller closure was confused with capture/success", e)
	}
	installed, e := s.Reconcile(ctx, f.policy, id, installCaller)
	if e != nil || installed.State != "observed" || installed.MutationPermitted || installed.Redeemable {
		t.Fatal("independent exact native-source route/peer/ACL readback failed", e)
	}
	historical, e := s.Begin(ctx, f.policy, a.ID, "install")
	if e != nil || historical.PermitID != g.PermitID || historical.State != "observed" || historical.Redeemable || historical.MutationPermitted {
		t.Fatal("second Begin after observed minted new install authority", e)
	}
	var installs int
	if e = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_network_permits WHERE attempt_id=$1 AND action='install'`, a.ID).Scan(&installs); e != nil || installs != 1 {
		t.Fatal("observed install was duplicated", installs, e)
	}
	abort, e := cleanup.Begin(ctx, f.policy, a.ID)
	if e != nil {
		t.Fatal("closed original did not permit scoped cleanup", e)
	}
	providerCaller := abortPGCaller(a)
	providerGrant, e := cleanup.Redeem(ctx, f.policy, abort.PermitID, providerCaller)
	if e != nil {
		t.Fatal(e)
	}
	if e = cleanup.Receive(ctx, f.policy, providerCaller, model.CapacityNativeWorkerAbortReceive{PermitID: abort.PermitID, BindingName: providerCaller.BindingName, SettlementToken: providerGrant.SettlementToken, OriginalReturn: []byte(`{"ci":"original-delete-return"}`), CaptureComplete: true}); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	r.settled = true
	r.keepNetwork = false
	r.mu.Unlock()
	r.networkMu.Lock()
	r.installed = false // Explicit separate CI floor read, never inferred from provider deletion.
	r.networkMu.Unlock()
	// Provider, registry, peer and charge readers now all explicitly report
	// absence. SQL still retains the address until the exposed install has a
	// separately consumed/closed/observed compensating removal.
	if _, e = cleanup.Reconcile(ctx, f.policy, abort.PermitID, providerCaller); e == nil {
		t.Fatal("all-zero component snapshot bypassed required network removal")
	}
	current, e := s.Workers.Read(ctx, f.policy, a.ID)
	if e != nil || current.State != "aborting" {
		t.Fatal("failed settlement released the child", e)
	}
	second, e := s.Workers.Reserve(ctx, f.policy, auth)
	if e != nil || second.OverlayIPv4 == a.OverlayIPv4 {
		t.Fatal("still-held network/IP reservation was reused", e)
	}
	removeCaller := networkPGCaller(f.p, "remove")
	remove, e := s.Begin(ctx, f.policy, a.ID, "remove")
	if e != nil {
		t.Fatal("sealed-target remove-after-provider-delete refused", e)
	}
	if remove.Peer.TransportEndpointIPv4 != g.Peer.TransportEndpointIPv4 || remove.Peer.TransportEndpointIPv4 == "203.0.113.99" {
		t.Fatal("cleanup endpoint came from runtime instead of original install")
	}
	removeID := uuid.MustParse(remove.PermitID)
	if _, e = s.Redeem(ctx, f.policy, removeID, removeCaller); e != nil {
		t.Fatal(e)
	}
	if e = s.Receive(ctx, f.policy, removeCaller, networkPGOriginal(remove, true)); e != nil {
		t.Fatal(e)
	}
	removed, e := s.Reconcile(ctx, f.policy, removeID, removeCaller)
	if e != nil || removed.State != "observed" || removed.MutationPermitted || removed.Redeemable {
		t.Fatal("independent complete removal was not GET-only settled", e)
	}
	if _, e = s.Redeem(ctx, f.policy, removeID, removeCaller); e == nil {
		t.Fatal("observed removal reauthorized another send")
	}
	settled, e := cleanup.Reconcile(ctx, f.policy, abort.PermitID, providerCaller)
	if e != nil || settled.State != "observed" {
		t.Fatal("all real DB component gates could not settle", e)
	}
	current, e = s.Workers.Read(ctx, f.policy, a.ID)
	if e != nil || current.State != "absent" {
		t.Fatal("full settlement did not release exact child", e)
	}
	reused, e := s.Workers.Reserve(ctx, f.policy, auth)
	if e != nil || reused.ID == a.ID || reused.OverlayIPv4 != a.OverlayIPv4 {
		t.Fatal("closed IP was not reusable under a NEW UUID/reservation", e)
	}
}
