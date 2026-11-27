package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only CI installs this synthetic read-only witness. It performs no provider or
// Kubernetes call; the store, shared admission arbiter and Goose DDL are real.
type abortPGRuntime struct {
	*nativeAttemptRuntime
	p           model.CapacityPolicySpec
	mu          sync.Mutex
	node        string
	settled     bool
	keepNetwork bool
}

func (r *abortPGRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, raw model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	o, e := r.nativeAttemptRuntime.Qualify(ctx, a, raw)
	if e == nil {
		o.OriginalAcceptance.AccountID = "ci-owned-account"
		o.IndependentCurrent.AccountID = "ci-owned-account"
	}
	return o, e
}
func (r *abortPGRuntime) ObserveAbort(_ context.Context, _ model.Manifest, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAbortObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.p.NativeWorkerPoolBinding
	o := model.CapacityNativeWorkerAbortObservation{ObservedAt: time.Now().UTC(), RealmUID: b.RealmUID, PoolUID: b.PoolUID, Owner: b.Owner, Epoch: r.pool.OwnerEpoch, Registry: b.RegistryRef, RegistryResourceVersion: "ci-current", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ProviderOutcome: "present", ProviderEvidenceSHA256: strings.Repeat("1", 64), NodeState: "none_confirmed", NodesComplete: true, PodsComplete: true, NodeEvidenceSHA256: strings.Repeat("2", 64)}
	if a.Physical != nil {
		o.Physical = *a.Physical
	}
	if a.NodeUID != "" {
		o.NodeState = "quarantined"
		o.NodeUID = a.NodeUID
		o.NodeProviderID = a.Physical.ProviderID
		o.NodeResourceVersion = "ci-node-rv"
		o.QuarantinePresent = true
		o.Unschedulable = true
	}
	if r.node == "unknown" {
		o.NodeState = "unknown"
		o.NodesComplete = false
		o.PodsComplete = false
	}
	if r.settled {
		o.ProviderOutcome = "not_found"
		o.NodeState = "none_confirmed"
		o.NodeUID = ""
		o.NodeProviderID = ""
		o.RegistryEntryAbsent = true
		o.RegistryEvidenceSHA256 = strings.Repeat("3", 64)
		o.NetworkPeerAbsent = !r.keepNetwork
		o.IPAMEntryAbsent = !r.keepNetwork
		o.NetworkEvidenceSHA256 = strings.Repeat("4", 64)
		o.AncillaryChargesClosed = true
		o.ChargeEvidenceSHA256 = strings.Repeat("5", 64)
	}
	return o, nil
}
func nativeWorkerAbortPGFixture(t *testing.T, ttl int) (marketRepositoryFixture, CapacityNativeWorkerAbortStore, *abortPGRuntime, model.CapacityNativeWorkerAuthority, CapacityNativeWorkerPhaseStore, model.CapacityNativeWorkerPhaseCaller) {
	t.Helper()
	f, w, provider, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) {
		p.NativeWorkerLifecycleBinding.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: model.ManifestSelector{Namespace: p.Workflow.Namespace, Name: "cleanup-workers"}, MaxPermitSeconds: ttl}
		p.NativeWorkerLifecycleBinding.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: p.NativeWorkerLifecycleBinding.Profiles[0].Adapter, BindingName: "ci-registry-writer", PrincipalID: "ci-registry-principal", SourceCommit: strings.Repeat("a", 40), ScopeSHA256: strings.Repeat("e", 64), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 30}
	})
	raw := json.RawMessage(`{"authorization":{}}`)
	workflow, e := CreateManifestVersion(t.Context(), f.db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "workflow", Metadata: model.ManifestMetadataInput{Namespace: f.p.NativeWorkerLifecycleBinding.PreAdmissionAbort.Workflow.Namespace, Name: "cleanup-workers"}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if e != nil {
		t.Fatal(e)
	}
	runtime := &abortPGRuntime{nativeAttemptRuntime: provider, p: f.p}
	w.Runtime = runtime
	s := CapacityNativeWorkerAbortStore{Workers: w, Runtime: runtime, RecoveryWorkflowID: workflow.ID, Enabled: true}
	phaseRuntime := &phasePermitRuntime{p: f.p, nodes: map[uuid.UUID]string{}, observeApplied: true}
	phase := CapacityNativeWorkerPhaseStore{Workers: w, Runtime: phaseRuntime, Enabled: true}
	writer := f.p.NativeWorkerLifecycleBinding.RegistryWriter
	caller := model.CapacityNativeWorkerPhaseCaller{Adapter: writer.Adapter, BindingName: writer.BindingName, PrincipalID: writer.PrincipalID, SourceCommit: writer.SourceCommit}
	return f, s, runtime, authority, phase, caller
}
func abortPGChild(t *testing.T, f marketRepositoryFixture, s CapacityNativeWorkerAbortStore, authority model.CapacityNativeWorkerAuthority) model.CapacityNativeWorkerAttempt {
	t.Helper()
	ctx := t.Context()
	a, e := s.Workers.Reserve(ctx, f.policy, authority)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Workers.Redeem(ctx, f.policy, authority, a.ID); e != nil {
		t.Fatal(e)
	}
	a, e = s.Workers.Record(ctx, f.policy, authority, a.ID)
	if e != nil || a.State != "acknowledged" {
		t.Fatal("actual child acceptance failed", e)
	}
	return a
}
func abortPGCaller(a model.CapacityNativeWorkerAttempt) model.CapacityNativeWorkerCommandCaller {
	return model.CapacityNativeWorkerCommandCaller{BindingName: a.Execution.BindingName, InstanceID: a.Execution.Adapter.ManifestID, SDKSourceCommit: a.Execution.SDKSourceCommit, Capability: a.Execution.DestroyCapability}
}
func abortPGStored(t *testing.T, f marketRepositoryFixture, id uuid.UUID) nativeWorkerAbortRecord {
	t.Helper()
	var raw []byte
	var r nativeWorkerAbortRecord
	if e := f.db.QueryRow(`SELECT record FROM public.capacity_native_worker_abort_permits WHERE id=$1`, id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func abortPGState(t *testing.T, f marketRepositoryFixture, s CapacityNativeWorkerAbortStore, id uuid.UUID, state string) {
	t.Helper()
	a, e := s.Workers.Read(t.Context(), f.policy, id)
	if e != nil || a.State != state {
		t.Fatal("unexpected physical accounting state", a.State, e)
	}
	var held int
	if e = f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_worker_attempts WHERE id=$1 AND state<>'absent'`, id).Scan(&held); e != nil {
		t.Fatal(e)
	}
	if (state == "absent") != (held == 0) {
		t.Fatal("charged child/IP reservation released before full absence", state, held)
	}
}

func TestNativeWorkerAbortPostgresOneSendAndUnknownNodeCannotBecomeZero(t *testing.T) {
	f, s, r, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	ctx := t.Context()
	a := abortPGChild(t, f, s, authority)
	caller := abortPGCaller(a)
	r.node = "unknown"
	p, e := s.Begin(ctx, f.policy, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	abortPGState(t, f, s, a.ID, "aborting")
	read, e := s.Read(ctx, f.policy, p.PermitID, caller)
	if e != nil || read.Redeemable || read.MutationPermitted {
		t.Fatal("unknown Node became a destructive right", e)
	}
	if _, e = s.Redeem(ctx, f.policy, p.PermitID, caller); e == nil {
		t.Fatal("unknown Node redeemed destroy")
	}
	if abortPGStored(t, f, p.PermitID).TokenSHA256 != "" {
		t.Fatal("failed destructive qualification consumed a send")
	}
	r.node = ""
	var won atomic.Int32
	var wg sync.WaitGroup
	tokens := make(chan model.CapacityNativeWorkerAbortPermit, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.Redeem(ctx, f.policy, p.PermitID, caller)
			if e == nil {
				won.Add(1)
				tokens <- v
			}
		}()
	}
	wg.Wait()
	close(tokens)
	if won.Load() != 1 {
		t.Fatal("not exactly one destructive permission", won.Load())
	}
	token := <-tokens
	if !token.MutationPermitted || token.SettlementToken == "" {
		t.Fatal("winning private redemption has no token")
	}
	// No creator/bootstrap right can be recovered from the same child afterward.
	creator := caller
	creator.Capability = a.Execution.EnsureCapability
	command, e := (CapacityNativeWorkerCommandStore{Workers: s.Workers}).Read(ctx, f.policy, a.ID, creator)
	if e != nil || command.Redeemable || command.MutationPermitted || len(command.PublicLaunchJSON) != 0 {
		t.Fatal("aborting child re-opened creation/bootstrap", e)
	}
	if _, e = s.Workers.Redeem(ctx, f.policy, authority, a.ID); e == nil {
		t.Fatal("aborting child re-opened creator")
	}
}

func TestNativeWorkerAbortPostgresLateCustodyAndEveryComponentSettlement(t *testing.T) {
	f, s, r, authority, _, _ := nativeWorkerAbortPGFixture(t, 1)
	ctx := t.Context()
	a := abortPGChild(t, f, s, authority)
	caller := abortPGCaller(a)
	p, e := s.Begin(ctx, f.policy, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	granted, e := s.Redeem(ctx, f.policy, p.PermitID, caller)
	if e != nil {
		t.Fatal(e)
	}
	r.settled = true
	r.keepNetwork = true
	out, e := s.Reconcile(ctx, f.policy, p.PermitID, caller)
	if e != nil || out.State != "unknown" {
		t.Fatal("partial closure failed to preserve uncertainty", out.State, e)
	}
	abortPGState(t, f, s, a.ID, "aborting")
	if _, e = s.Begin(ctx, f.policy, a.ID); e != nil {
		t.Fatal("historical read lost existing abort", e)
	}
	if _, e = s.Redeem(ctx, f.policy, p.PermitID, caller); e == nil {
		t.Fatal("uncertain delete was resent")
	}
	time.Sleep(1100 * time.Millisecond) // CI only: exercise the actual database deadline.
	r.keepNetwork = false
	out, e = s.Reconcile(ctx, f.policy, p.PermitID, caller)
	if e != nil || out.State != "observed" {
		t.Fatal("late GET-only full closure rejected", out.State, e)
	}
	abortPGState(t, f, s, a.ID, "absent")
	raw := []byte(`{"opaque_original":"ci-private-delete-return"}`)
	received := model.CapacityNativeWorkerAbortReceive{PermitID: p.PermitID, BindingName: caller.BindingName, SettlementToken: granted.SettlementToken, OriginalReturn: raw, CaptureComplete: false, ErrorClass: "ORIGINAL_TRANSPORT_UNCERTAIN"}
	if e = s.Receive(ctx, f.policy, caller, received); e != nil {
		t.Fatal("late original custody rejected", e)
	}
	stored := abortPGStored(t, f, p.PermitID)
	if stored.Context.State != "observed" || stored.Original == nil || string(stored.Original.OriginalReturn) != string(raw) || stored.Original.SettlementToken != "" {
		t.Fatal("late original erased truth or retained plaintext token")
	}
	for _, secret := range []string{granted.SettlementToken, string(raw), stored.TokenSHA256, "ci-private-delete-return"} {
		wire, _ := json.Marshal(abortContext(stored))
		if strings.Contains(string(wire), secret) {
			t.Fatal("private original/bearer escaped in read")
		}
	}
	if e = s.Receive(ctx, f.policy, caller, received); e != nil {
		t.Fatal("exact duplicate original is not idempotent", e)
	}
	received.OriginalReturn = []byte("different")
	if e = s.Receive(ctx, f.policy, caller, received); e == nil {
		t.Fatal("different late original overwrote custody")
	}
}

func TestNativeWorkerAbortPostgresAdmissionArbiterAndExposedRelease(t *testing.T) {
	f, s, _, authority, phase, phaseCaller := nativeWorkerAbortPGFixture(t, 30)
	ctx := t.Context()
	a := abortPGChild(t, f, s, authority)
	// Register through the existing independent observation path, not a SQL state edit.
	var e error
	a, e = s.Workers.Record(ctx, f.policy, authority, a.ID)
	if e != nil || a.State != "registered" {
		t.Fatal("real registered child fixture failed", e)
	}
	admit, e := phase.Issue(ctx, f.policy, authority, a.ID, "admit_registry")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = phase.Redeem(ctx, f.policy, admit.PermitID, phaseCaller); e != nil {
		t.Fatal(e)
	}
	if _, e = phase.Reconcile(ctx, f.policy, admit.PermitID, phaseCaller); e != nil {
		t.Fatal(e)
	}
	release, e := phase.Issue(ctx, f.policy, authority, a.ID, "release_quarantine")
	if e != nil {
		t.Fatal(e)
	}
	var abortWon, releaseWon atomic.Int32
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, e := s.Begin(ctx, f.policy, a.ID); e == nil {
			abortWon.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		if _, e := phase.Redeem(ctx, f.policy, release.PermitID, phaseCaller); e == nil {
			releaseWon.Add(1)
		}
	}()
	wg.Wait()
	if abortWon.Load()+releaseWon.Load() != 1 {
		t.Fatal("admission and cleanup did not share a single arbiter", abortWon.Load(), releaseWon.Load())
	}
	if releaseWon.Load() == 1 {
		if _, e = s.Begin(ctx, f.policy, a.ID); e == nil {
			t.Fatal("exposed release_quarantine permitted pre-admission abort")
		}
	} else {
		abortPGState(t, f, s, a.ID, "aborting")
		if _, e = phase.Redeem(ctx, f.policy, release.PermitID, phaseCaller); e == nil {
			t.Fatal("fenced unredeemed admission token re-opened")
		}
	}
	t.Run("unknown_release_receive_cannot_race_into_cleanup", func(t *testing.T) {
		f, s, _, authority, phase, caller := nativeWorkerAbortPGFixture(t, 30)
		a := abortPGChild(t, f, s, authority)
		a, err := s.Workers.Record(t.Context(), f.policy, authority, a.ID)
		if err != nil || a.State != "registered" {
			t.Fatal("registered child fixture failed", err)
		}
		admit, err := phase.Issue(t.Context(), f.policy, authority, a.ID, "admit_registry")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = phase.Redeem(t.Context(), f.policy, admit.PermitID, caller); err != nil {
			t.Fatal(err)
		}
		if _, err = phase.Reconcile(t.Context(), f.policy, admit.PermitID, caller); err != nil {
			t.Fatal(err)
		}
		release, err := phase.Issue(t.Context(), f.policy, authority, a.ID, "release_quarantine")
		if err != nil {
			t.Fatal(err)
		}
		grant, err := phase.Redeem(t.Context(), f.policy, release.PermitID, caller)
		if err != nil {
			t.Fatal(err)
		}
		var captured, wronglyAborted atomic.Int32
		var race sync.WaitGroup
		race.Add(2)
		go func() {
			defer race.Done()
			_, err := phase.Receive(t.Context(), f.policy, caller, model.CapacityNativeWorkerPhaseReceive{PermitID: release.PermitID, BindingName: caller.BindingName, SettlementToken: grant.SettlementToken, HTTPStatus: 0, TransportCompleted: false, OriginalReturn: []byte("ci-partial-unknown-quarantine-return")})
			if err == nil {
				captured.Add(1)
			}
		}()
		go func() {
			defer race.Done()
			if _, err := s.Begin(t.Context(), f.policy, a.ID); err == nil {
				wronglyAborted.Add(1)
			}
		}()
		race.Wait()
		if captured.Load() != 1 || wronglyAborted.Load() != 0 || nativePhaseStored(t, f, release.PermitID).Context.PhaseState != "unknown" {
			t.Fatal("uncertain release custody became cleanup permission", captured.Load(), wronglyAborted.Load())
		}
		abortPGState(t, f, s, a.ID, "registered")
	})
}

func TestNativeWorkerAbortPostgresUnknownCreationRemainsCharged(t *testing.T) {
	f, s, r, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	a, err := s.Workers.Reserve(t.Context(), f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Workers.Redeem(t.Context(), f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	r.failSDK.Store(true)
	a, err = s.Workers.Record(t.Context(), f.policy, authority, a.ID)
	if err != nil || a.State != "unknown" || a.Physical != nil {
		t.Fatal("actual unknown creation fixture failed", err)
	}
	if _, err = s.Begin(t.Context(), f.policy, a.ID); err == nil {
		t.Fatal("missing original physical birth became a guessed abort target")
	}
	abortPGState(t, f, s, a.ID, "unknown")
}

func TestNativeWorkerAbortPostgresScopeDefaultOffAndWorkflowRevocation(t *testing.T) {
	f, s, _, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	ctx := t.Context()
	a := abortPGChild(t, f, s, authority)
	caller := abortPGCaller(a)
	off := s
	off.Enabled = false
	if _, e := off.Begin(ctx, f.policy, a.ID); e == nil {
		t.Fatal("default-off cleanup issued permission")
	}
	p, e := s.Begin(ctx, f.policy, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	wrong := caller
	wrong.SDKSourceCommit = strings.Repeat("f", 40)
	if _, e = s.Redeem(ctx, f.policy, p.PermitID, wrong); e == nil {
		t.Fatal("foreign SDK source redeemed")
	}
	changed := s
	changed.Workers.Capacity.ExecutorID = uuid.NewString()
	if _, e = changed.Redeem(ctx, f.policy, p.PermitID, caller); e == nil {
		t.Fatal("different private executor inherited permission")
	}
	if _, e = f.db.Exec(`UPDATE public.manifests SET active=false WHERE id=$1`, s.RecoveryWorkflowID); e != nil {
		t.Fatal(e)
	}
	read, e := s.Read(ctx, f.policy, p.PermitID, caller)
	if e != nil || read.Redeemable {
		t.Fatal("revoked recovery workflow remains redeemable", e)
	}
	if _, e = s.Redeem(ctx, f.policy, p.PermitID, caller); e == nil {
		t.Fatal("revoked workflow redeemed destroy")
	}
	if abortPGStored(t, f, p.PermitID).TokenSHA256 != "" {
		t.Fatal("refused authority minted a token")
	}
}
