package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var errNativeWorkerConcreteAbort = errors.New("HOLD: independent Native abort evidence is unavailable")

// Private installed Go composition. Network and its Workers/database are
// borrowed; successful construction owns only these separate read clients.
// A failed constructor takes no ownership. There is no mutation callback.
type NativeWorkerConcreteAbortRuntimeConfig struct {
	DB            *sql.DB
	Policy        model.Manifest
	Network       *NativeWorkerConcreteNetworkRuntime
	CleanupRead   capacity.NativeWorkerCleanupReadFunc
	InventoryRead capacity.NativeWorkerAbortInventoryReadFunc
	RPCClients    []*capacity.NativeWorkerRPCClient
}

type NativeWorkerConcreteAbortRuntime struct {
	*nativeWorkerConcreteAbortState
}
type nativeWorkerConcreteAbortState struct {
	mu        sync.RWMutex
	closed    bool
	db        *sql.DB
	policy    model.Manifest
	spec      model.CapacityPolicySpec
	source    string
	network   *NativeWorkerConcreteNetworkRuntime
	cleanup   capacity.NativeWorkerCleanupReadFunc
	inventory capacity.NativeWorkerAbortInventoryReadFunc
	clients   []*capacity.NativeWorkerRPCClient
}

func (NativeWorkerConcreteAbortRuntime) String() string     { return "[private Native abort runtime]" }
func (r NativeWorkerConcreteAbortRuntime) GoString() string { return r.String() }
func (NativeWorkerConcreteAbortRuntime) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_abort_runtime":"redacted"}`), nil
}

func NewNativeWorkerConcreteAbortRuntime(c NativeWorkerConcreteAbortRuntimeConfig) (*NativeWorkerConcreteAbortRuntime, error) {
	return newNativeWorkerConcreteAbortRuntime(c, capacity.CurrentGuestCoreSource())
}

func newNativeWorkerConcreteAbortRuntime(c NativeWorkerConcreteAbortRuntimeConfig, source string) (*NativeWorkerConcreteAbortRuntime, error) {
	if c.DB == nil || c.Network == nil || c.Network.nativeWorkerConcreteNetworkState == nil || c.Network.workers == nil || c.Network.workers.nativeWorkerConcreteRuntimeState == nil || c.CleanupRead == nil || c.InventoryRead == nil || !nativeNetworkCoreSource(source) {
		return nil, errNativeWorkerConcreteAbort
	}
	n := c.Network
	n.mu.RLock()
	defer n.mu.RUnlock()
	n.workers.mu.RLock()
	defer n.workers.mu.RUnlock()
	p, err := parseCapacityPolicy(c.Policy)
	if err != nil || !n.boundLocked(c.Policy) || n.db != c.DB || n.source != source || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.SourceCommit != source || p.NativeWorkerLifecycleBinding.PreAdmissionAbort == nil ||
		capacity.ValidateNativeWorkerAbortBinding(p) != nil {
		return nil, errNativeWorkerConcreteAbort
	}
	bound, err := capacity.NativeWorkerAbortInventoryPolicy(p)
	if err != nil || len(c.RPCClients) != len(p.NativeWorkerLifecycleBinding.PhysicalObservers)+1 {
		return nil, errNativeWorkerConcreteAbort
	}
	clients := append([]*capacity.NativeWorkerRPCClient(nil), c.RPCClients...)
	seen := map[*capacity.NativeWorkerRPCClient]bool{}
	for _, client := range clients {
		if client == nil || seen[client] {
			return nil, errNativeWorkerConcreteAbort
		}
		seen[client] = true
		for prior := range seen {
			if prior != client && client.SharesState(prior) {
				return nil, errNativeWorkerConcreteAbort
			}
		}
		for _, borrowed := range n.workers.clients {
			if client.SharesState(borrowed) {
				return nil, errNativeWorkerConcreteAbort
			}
		}
	}
	matched := map[*capacity.NativeWorkerRPCClient]bool{}
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		count := 0
		for _, client := range clients {
			if client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
				count++
				matched[client] = true
			}
		}
		if count != 1 {
			return nil, errNativeWorkerConcreteAbort
		}
	}
	b := bound.NativeWorkerLifecycleBinding.PhaseObserver
	count := 0
	for _, client := range clients {
		if client.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory) {
			count++
			matched[client] = true
		}
	}
	if count != 1 || len(matched) != len(clients) {
		return nil, errNativeWorkerConcreteAbort
	}
	raw, err := json.Marshal(c.Policy)
	var own model.Manifest
	if err != nil || json.Unmarshal(raw, &own) != nil {
		return nil, errNativeWorkerConcreteAbort
	}
	own.Spec = append(json.RawMessage(nil), c.Policy.Spec...)
	var spec model.CapacityPolicySpec
	if json.Unmarshal(own.Spec, &spec) != nil {
		return nil, errNativeWorkerConcreteAbort
	}
	return &NativeWorkerConcreteAbortRuntime{&nativeWorkerConcreteAbortState{db: c.DB, policy: own, spec: spec, source: source, network: n, cleanup: c.CleanupRead, inventory: c.InventoryRead, clients: clients}}, nil
}

// Lock order is Abort -> Network -> Workers -> RPC. No mutable database
// transaction is held across provider, Kubernetes or floor reads.
func (r *NativeWorkerConcreteAbortRuntime) SourceCommit() string {
	if r == nil || r.nativeWorkerConcreteAbortState == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.network == nil {
		return ""
	}
	if r.network.SourceCommit() != r.source {
		return ""
	}
	if !r.readClientsBound() {
		return ""
	}
	return r.source
}

func (r *NativeWorkerConcreteAbortRuntime) BoundToDatabase(db *sql.DB) bool {
	if r == nil || r.nativeWorkerConcreteAbortState == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.closed && db != nil && r.db == db && r.network.BoundToDatabase(db)
}

func (r *NativeWorkerConcreteAbortRuntime) ObserveAbort(ctx context.Context, policy model.Manifest, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAbortObservation, error) {
	zero := model.CapacityNativeWorkerAbortObservation{}
	if r == nil || r.nativeWorkerConcreteAbortState == nil || ctx == nil || ctx.Err() != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.network == nil {
		return zero, errNativeWorkerConcreteAbort
	}
	n := r.network
	n.mu.RLock()
	defer n.mu.RUnlock()
	n.workers.mu.RLock()
	defer n.workers.mu.RUnlock()
	if !n.boundLocked(policy) || !n.workers.policyMatches(r.policy) || !n.attemptBoundLocked(a) ||
		a.State != "acknowledged" && a.State != "registered" && a.State != "aborting" || a.Physical == nil || !capacity.ValidDigest(a.BirthSHA256) {
		return zero, errNativeWorkerConcreteAbort
	}
	if !r.readClientsBound() {
		return zero, errNativeWorkerConcreteAbort
	}
	launch, original, selector, err := n.targetLocked(ctx, a)
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	defer clear(original.Wire)
	historical, err := nativeAbortCommittedResourceFootprint(ctx, r.db, r.policy, a, r.source)
	if err != nil || historical != nil && !capacity.NativeWorkerResourceFootprintValid(r.spec, a, launch, historical, time.Now().UTC(), false) {
		return zero, errNativeWorkerConcreteAbort
	}
	var provider *model.CapacityNativeWorkerPhysicalReadBinding
	for i := range r.spec.NativeWorkerLifecycleBinding.PhysicalObservers {
		b := &r.spec.NativeWorkerLifecycleBinding.PhysicalObservers[i]
		if b.Profile == a.Profile && b.Provider == a.Provider && b.Region == a.Region {
			if provider != nil {
				return zero, errNativeWorkerConcreteAbort
			}
			provider = b
		}
	}
	if provider == nil {
		return zero, errNativeWorkerConcreteAbort
	}
	cleanup, err := r.cleanup(ctx, *provider, model.CapacityNativeWorkerCleanupRequest{BindingName: provider.BindingName, AttemptID: a.ID.String(), ResourceID: a.Physical.ResourceID, LaunchSHA256: a.LaunchSHA256, Footprint: historical})
	if err != nil || ctx.Err() != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	outcome, charges, err := capacity.NativeWorkerCleanupOutcome(r.spec, a, launch, historical, cleanup, time.Now().UTC())
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	name, err := capacity.NativeWorkerBootstrapNodeName(a)
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	b := r.spec.NativeWorkerLifecycleBinding.AbortInventoryObserver
	inventory, err := r.inventory(ctx, *b, model.CapacityNativeWorkerAbortInventoryRequest{BindingName: b.Name, ProviderID: a.Physical.ProviderID, CreationProofSHA256: a.BirthSHA256, NodeName: name})
	if err != nil || ctx.Err() != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	o := model.CapacityNativeWorkerAbortObservation{ResourceFootprint: cleanup.Footprint, ProviderOutcome: outcome, ProviderEvidenceSHA256: cleanup.EvidenceSHA256, AncillaryChargesClosed: charges, ChargeEvidenceSHA256: cleanup.EvidenceSHA256}
	o, err = capacity.NativeWorkerApplyAbortInventory(r.spec, a, inventory, o, time.Now().UTC())
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	floor, err := n.reader.Observe(ctx, selector)
	if err != nil || ctx.Err() != nil || !capacity.NativeWorkerNetworkObservationValid(r.spec, a, launch, floor, time.Now().UTC()) {
		return zero, errNativeWorkerConcreteAbort
	}
	// This no-send comparison checks the actual peer, address route and owned
	// firewall projection. It is never passed to a writer as a fabricated grant.
	remove := model.CapacityNativeWorkerNetworkGrant{Action: "remove", AttemptID: a.ID.String(), NetworkTemplateSHA256: r.spec.NativeWorkerLifecycleBinding.Network.TemplateSHA256, Peer: model.CapacityNativeWorkerNetworkPeer{WorkerPublicKey: selector.WorkerPublicKey, WorkerIPv4: selector.WorkerIPv4}}
	absent := capacity.NativeWorkerNetworkDesired(*r.spec.NativeWorkerLifecycleBinding.Network, remove, floor)
	closed, err := nativeAbortNetworkProducersClosed(ctx, r.db, r.policy, a, r.source)
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	o.NetworkPeerAbsent = absent && closed
	// The internal Attempt/IP cost reservation is intentionally still held.
	// IPAMEntryAbsent refers only to external use of its allocated address:
	// complete owned peer/route/firewall inventory plus settled producers.
	// The Store releases the internal reservation atomically at state absent.
	o.IPAMEntryAbsent = o.NetworkPeerAbsent
	o.NetworkEvidenceSHA256, err = floor.PreimageSHA256()
	if err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	now := time.Now().UTC()
	o.ObservedAt = now
	// The complete observation must still be fresh after the final read.
	if ctx.Err() != nil || !capacity.NativeWorkerResourceFootprintValid(r.spec, a, launch, cleanup.Footprint, now, historical == nil) ||
		!capacity.NativeWorkerNetworkObservationValid(r.spec, a, launch, floor, now) || !capacity.NativeWorkerAbortObservationValid(r.spec, a, o, now) {
		return zero, errNativeWorkerConcreteAbort
	}
	if _, _, err = capacity.NativeWorkerCleanupOutcome(r.spec, a, launch, historical, cleanup, now); err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	if _, err = capacity.NativeWorkerApplyAbortInventory(r.spec, a, inventory, o, now); err != nil {
		return zero, errNativeWorkerConcreteAbort
	}
	return o, nil
}

func nativeAbortNetworkProducersClosed(ctx context.Context, db *sql.DB, policy model.Manifest, a model.CapacityNativeWorkerAttempt, source string) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE attempt_id=$1 AND policy_id=$2 AND namespace=$3 ORDER BY id LIMIT 129`, a.ID, policy.ID, a.Namespace)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	count, installed, removed := 0, false, false
	for rows.Next() {
		count++
		var raw []byte
		var record nativeWorkerNetworkRecord
		if count > 128 || rows.Scan(&raw) != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &record) != nil || record.Attempt.ID != a.ID || record.Attempt.BirthSHA256 != a.BirthSHA256 || record.SourceCommit != source || record.Attempt.PolicyID != policy.ID || record.Attempt.Namespace != a.Namespace {
			return false, errNativeWorkerConcreteAbort
		}
		g := record.Context
		if g.Action != "install" && g.Action != "remove" {
			return false, errNativeWorkerConcreteAbort
		}
		if g.State == "issued" {
			return false, nil
		}
		if g.State != "observed" && g.State != "no_effect" && g.State != "redeemed" && g.State != "received" && g.State != "unknown" {
			return false, errNativeWorkerConcreteAbort
		}
		if g.State != "no_effect" && (!record.OriginalCallerClosed || record.Original == nil) {
			return false, nil
		}
		// A partial original can honestly close its caller without proving the
		// install desired state. Its observed compensation is still mandatory.
		if g.Action == "install" && g.State != "no_effect" {
			installed = true
		}
		if g.Action == "remove" && g.State == "observed" {
			removed = true
		}
	}
	if err = rows.Err(); err != nil || ctx.Err() != nil {
		return false, errNativeWorkerConcreteAbort
	}
	return !installed || removed, nil
}

func (r *NativeWorkerConcreteAbortRuntime) readClientsBound() bool {
	for _, b := range r.spec.NativeWorkerLifecycleBinding.PhysicalObservers {
		count := 0
		for _, client := range r.clients {
			if client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	b := r.spec.NativeWorkerLifecycleBinding.AbortInventoryObserver
	if b == nil {
		return false
	}
	count := 0
	for _, client := range r.clients {
		if client.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory) {
			count++
		}
	}
	return count == 1
}

func (r *NativeWorkerConcreteAbortRuntime) Close() error {
	if r == nil || r.nativeWorkerConcreteAbortState == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	for _, client := range r.clients {
		errs = append(errs, client.Close())
	}
	r.clients, r.cleanup, r.inventory = nil, nil, nil
	return errors.Join(errs...)
}
