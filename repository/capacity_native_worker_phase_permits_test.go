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

func TestNativeWorkerPhaseNoEffectRequiresAnUnambiguousNativeStatus(t *testing.T) {
	conflict := `{"apiVersion":"v1","kind":"Status","metadata":{},"status":"Failure","message":"the object has been modified","reason":"Conflict","details":{"kind":"leases","name":"ci-pool","causes":[{"reason":"FieldValueInvalid","message":"resourceVersion"}]},"code":409}`
	invalid := `{"apiVersion":"v1","kind":"Status","metadata":{},"status":"Failure","message":"JSON patch test failed","reason":"Invalid","details":{"kind":"nodes","name":"ci-worker"},"code":422}`
	for _, tc := range []struct {
		name string
		code int
		raw  string
		want bool
	}{
		{"nativeConflictCamelCase", 409, conflict, true},
		{"nativeAtomicPatchTestInvalid", 422, invalid, true},
		{"mismatchedHTTPCode", 422, conflict, false},
		{"nonConflict", 409, strings.Replace(conflict, `"reason":"Conflict"`, `"reason":"Forbidden"`, 1), false},
		{"wrongVersion", 409, strings.Replace(conflict, `"apiVersion":"v1"`, `"apiVersion":"other/v1"`, 1), false},
		{"missingVersion", 409, strings.Replace(conflict, `"apiVersion":"v1",`, "", 1), false},
		{"versionCaseAlias", 409, strings.Replace(conflict, `"apiVersion"`, `"APIVersion"`, 1), false},
		{"duplicateReason", 409, strings.Replace(conflict, `"reason":"Conflict"`, `"reason":"Forbidden","reason":"Conflict"`, 1), false},
		{"nestedDuplicate", 409, strings.Replace(conflict, `"kind":"leases"`, `"kind":"nodes","kind":"leases"`, 1), false},
		{"unknownEnvelopeField", 409, strings.Replace(conflict, `"code":409`, `"code":409,"extra":true`, 1), false},
		{"wrongKind", 409, strings.Replace(conflict, `"kind":"Status"`, `"kind":"Lease"`, 1), false},
		{"successBody", 409, strings.Replace(conflict, `"status":"Failure"`, `"status":"Success"`, 1), false},
		{"missingMetadata", 409, strings.Replace(conflict, `"metadata":{},`, "", 1), false},
		{"scalarMetadata", 409, strings.Replace(conflict, `"metadata":{}`, `"metadata":1`, 1), false},
		{"arrayDetails", 409, strings.Replace(conflict, `"details":{"kind":"leases","name":"ci-pool","causes":[{"reason":"FieldValueInvalid","message":"resourceVersion"}]}`, `"details":[]`, 1), false},
		{"stringCode", 409, strings.Replace(conflict, `"code":409`, `"code":"409"`, 1), false},
		{"truncated", 409, conflict[:len(conflict)-1], false},
		{"trailing", 409, conflict + ` {}`, false},
		{"timeoutOrProxy", 504, conflict, false},
		{"arrayEnvelope", 409, `[]`, false},
		{"nullEnvelope", 409, `null`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativePhaseDefinitiveNoEffect(tc.code, []byte(tc.raw)); got != tc.want {
				t.Fatalf("definitive native no-effect=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestNativeWorkerPhasePublicContextCannotExposePrivateReturnOrBearer(t *testing.T) {
	secret := "ci-one-send-settlement-secret"
	raw := "ci-private-native-return"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(secret)))
	r := nativeWorkerPhaseRecord{Context: model.CapacityNativeWorkerPhasePermit{PermitID: uuid.New(), PhaseState: "observed", MutationPermitted: true, Redeemable: true, SettlementToken: secret}, ExecutorID: uuid.NewString(), SettlementTokenSHA256: digest, Original: &model.CapacityNativeWorkerPhaseReceive{SettlementToken: secret, OriginalReturn: []byte(raw)}}
	out := phaseContext(r)
	if out.MutationPermitted || out.Redeemable || out.SettlementToken != "" || out.PhaseState != "observed" {
		t.Fatal("historical read minted a send right or lost observed truth")
	}
	wire, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{secret, raw, digest, r.ExecutorID, "original_return", "settlement_token_sha256"} {
		if strings.Contains(string(wire), v) {
			t.Fatalf("private phase material entered public context: %s", v)
		}
	}
	if r.Context.SettlementToken != secret || r.Original.SettlementToken != secret {
		t.Fatal("sanitizing public view altered private original custody")
	}
}

func TestNativeWorkerPhaseWriterScopePinsTheWholeReviewedInventory(t *testing.T) {
	file := []byte("{\"schema\":\"native_worker_pool_writer_bindings_v1\",\"bindings\":[]}\n")
	want := fmt.Sprintf("%x", sha256.Sum256(file))
	r := nativeWorkerPhaseRecord{Context: model.CapacityNativeWorkerPhasePermit{PermitID: uuid.New(), WriterScopeSHA256: want}, Writer: model.CapacityNativeWorkerRegistryWriterBinding{ScopeSHA256: want, PrincipalID: "ci-writer", BindingName: "ci-pool", SourceCommit: strings.Repeat("a", 40)}}
	caller := model.CapacityNativeWorkerPhaseCaller{Adapter: r.Writer.Adapter, PrincipalID: r.Writer.PrincipalID, BindingName: r.Writer.BindingName, SourceCommit: r.Writer.SourceCommit}
	if !phaseCaller(r, caller) {
		t.Fatal("identical policy and inventory scope was refused")
	}
	wire, err := json.Marshal(phaseContext(r))
	var roundtrip model.CapacityNativeWorkerPhasePermit
	if err != nil || json.Unmarshal(wire, &roundtrip) != nil || roundtrip.WriterScopeSHA256 != want || !strings.Contains(string(wire), `"writer_scope_sha256":"`+want+`"`) {
		t.Fatal("public read lost the exact reviewed writer inventory pin")
	}
	// Whitespace changes the actual file hash even when parsed bindings would
	// be identical. Re-encoding only the selected binding cannot satisfy it.
	changed := fmt.Sprintf("%x", sha256.Sum256(append(append([]byte{}, file...), '\n')))
	for _, scope := range []string{"", strings.ToUpper(want), changed} {
		bad := r
		bad.Context.WriterScopeSHA256 = scope
		if phaseCaller(bad, caller) {
			t.Fatal("mismatched inventory context could reach redemption")
		}
		// Both persistence boundaries must refuse before accessing any Tx.
		if err := nativePhaseInsertTx(t.Context(), nil, bad, "ci", time.Now()); err == nil {
			t.Fatal("mismatched pin was persisted as a new permission")
		}
		if err := nativePhaseWriteTx(t.Context(), nil, bad, time.Now()); err == nil {
			t.Fatal("mismatched pin was persisted during redemption or receiving")
		}
	}
	bad := r
	bad.Writer.ScopeSHA256, bad.Context.WriterScopeSHA256 = "", ""
	if phaseCaller(bad, caller) {
		t.Fatal("two absent pins became authority")
	}
}

func nativePhasePreparedFixture() (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerPhasePreparation, time.Time) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	hash := func(s string) string { return strings.Repeat(s, 64) }
	id := uuid.New()
	node := uuid.NewString()
	registry := model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "infra", Name: "ci-pool", UID: uuid.NewString()}
	p := model.CapacityPolicySpec{NativeWorkerPoolBinding: &model.CapacityNativeWorkerPoolBinding{RealmUID: uuid.NewString(), Profiles: []model.CapacityNativeWorkerProfileBinding{{Profile: "ci", RegistrationBindingSHA: hash("b")}}}, NativeWorkerLifecycleBinding: &model.CapacityNativeWorkerLifecycleBinding{MaxReadAgeSeconds: 60}}
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New(), PolicyID: id, Generation: 2, FencingToken: 3, State: "registered", Registry: registry, NodeUID: node, Profile: "ci", PhysicalSpecSHA256: hash("a"), BirthSHA256: hash("c"), NetworkBindingSHA256: hash("d"), QualificationEvidenceSHA256: hash("e"), QualificationValidUntil: now.Add(time.Minute), Physical: &model.CapacityNativeWorkerPhysical{ProviderID: "hcloud://12345"}}
	v := model.CapacityNativeWorkerPhasePreparation{Context: model.CapacityNativeWorkerPhasePermit{Action: "admit_registry", RealmNamespace: "dakasa", RealmUID: p.NativeWorkerPoolBinding.RealmUID, Registry: registry, ExpectedRegistryResourceVersion: "10", ExpectedRegistrySHA256: hash("f"), Node: model.CapacityNativeWorkerPhaseNode{Name: "ci-worker", UID: node, ResourceVersion: "12", ProviderID: a.Physical.ProviderID, Profile: a.Profile, PhysicalSpecSHA256: a.PhysicalSpecSHA256, RegistrationBindingSHA256: hash("b"), CapacityPolicyID: id.String(), IntentGeneration: 2, FencingToken: 3, CreationProofSHA256: a.BirthSHA256}, Admission: model.CapacityNativeWorkerPhaseAdmission{NetworkBindingSHA256: a.NetworkBindingSHA256, WarmupEvidenceSHA256: hash("a"), PhysicalQualificationSHA256: a.QualificationEvidenceSHA256}}, ObservedAt: now, ReadinessValidUntil: now.Add(time.Minute), NodeReady: true, NetworkVerified: true, WarmupVerified: true, PhysicalQualified: true}
	return p, a, v, now
}

func TestNativeWorkerPhasePreparationBindsBirthAndIndependentAdmissionFacts(t *testing.T) {
	p, a, v, now := nativePhasePreparedFixture()
	if !phasePrepared(p, a, "admit_registry", v, now) {
		t.Fatal("qualified baseline refused")
	}
	wire, err := json.Marshal(v)
	if err != nil || strings.Contains(string(wire), "ReadinessValidUntil") || strings.Contains(string(wire), "readiness_valid_until") {
		t.Fatal("private callback validity entered a JSON preparation")
	}
	for _, tc := range []struct {
		name  string
		alter func(*model.CapacityPolicySpec, *model.CapacityNativeWorkerAttempt, *model.CapacityNativeWorkerPhasePreparation)
	}{
		{"notReady", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.NodeReady = false
		}},
		{"networkNotVerified", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.NetworkVerified = false
		}},
		{"warmupNotVerified", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.WarmupVerified = false
		}},
		{"physicalNotQualified", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.PhysicalQualified = false
		}},
		{"staleRead", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.ObservedAt = now.Add(-61 * time.Second)
		}},
		{"futureRead", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.ObservedAt = now.Add(time.Second)
		}},
		{"expiredQualification", func(_ *model.CapacityPolicySpec, a *model.CapacityNativeWorkerAttempt, _ *model.CapacityNativeWorkerPhasePreparation) {
			a.QualificationValidUntil = now
		}},
		{"missingReadinessValidity", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.ReadinessValidUntil = time.Time{}
		}},
		{"expiredReadiness", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.ReadinessValidUntil = now.Add(-time.Nanosecond)
		}},
		{"readinessAtBoundary", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.ReadinessValidUntil = now
		}},
		{"endedAttempt", func(_ *model.CapacityPolicySpec, a *model.CapacityNativeWorkerAttempt, _ *model.CapacityNativeWorkerPhasePreparation) {
			a.State = "absent"
		}},
		{"differentNode", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.Context.Node.UID = uuid.NewString()
		}},
		{"wrongBirth", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.Context.Node.CreationProofSHA256 = strings.Repeat("f", 64)
		}},
		{"wrongFence", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.Context.Node.FencingToken++
		}},
		{"wrongPolicy", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.Context.Node.CapacityPolicyID = uuid.NewString()
		}},
		{"registrySubstitution", func(_ *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			v.Context.Registry.UID = uuid.NewString()
		}},
		{"protectedNode", func(p *model.CapacityPolicySpec, _ *model.CapacityNativeWorkerAttempt, v *model.CapacityNativeWorkerPhasePreparation) {
			p.NativeWorkerPoolBinding.ProtectedNodes = []model.CapacityNativeProtectedNode{{NodeUID: v.Context.Node.UID}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, a, v, _ := nativePhasePreparedFixture()
			tc.alter(&p, &a, &v)
			for _, action := range []string{"admit_registry", "release_quarantine"} {
				if phasePrepared(p, a, action, v, now) {
					t.Fatal("unqualified or substituted phase became a mutation right", action)
				}
			}
		})
	}
	p, a, v, now = nativePhasePreparedFixture()
	a.State = "acknowledged"
	a.NodeUID = ""
	v.ReadinessValidUntil = time.Time{}
	if !phasePrepared(p, a, "register", v, now) {
		t.Fatal("first independently observed Node UID cannot be bound at registration")
	}
	a.NodeUID = uuid.NewString()
	if phasePrepared(p, a, "register", v, now) {
		t.Fatal("a bound Node UID was replaced")
	}
}

// A source-installed synthetic GET-only callback. It never sends Kubernetes or
// provider traffic; PostgreSQL tests below exercise the actual store and DDL.
type phasePermitRuntime struct {
	p                 model.CapacityPolicySpec
	mu                sync.Mutex
	nodes             map[uuid.UUID]string
	observeWrongEpoch bool
	observeApplied    bool
}

func (r *phasePermitRuntime) PreparePhase(_ context.Context, a model.CapacityNativeWorkerAttempt, action string) (model.CapacityNativeWorkerPhasePreparation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node := a.NodeUID
	if node == "" {
		node = r.nodes[a.ID]
		if node == "" {
			node = uuid.NewString()
			r.nodes[a.ID] = node
		}
	}
	c := model.CapacityNativeWorkerPhasePermit{Action: action, RealmNamespace: r.p.NativeWorkerPoolBinding.RegistryRef.Namespace, RealmUID: r.p.NativeWorkerPoolBinding.RealmUID, Registry: a.Registry, ExpectedRegistryResourceVersion: "10", ExpectedRegistrySHA256: strings.Repeat("a", 64), Node: model.CapacityNativeWorkerPhaseNode{Name: "ci-worker-" + a.ID.String(), UID: node, ResourceVersion: "11", ProviderID: a.Physical.ProviderID, Profile: a.Profile, PhysicalSpecSHA256: a.PhysicalSpecSHA256, RegistrationBindingSHA256: r.p.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA, CapacityPolicyID: a.PolicyID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, CreationProofSHA256: a.BirthSHA256}, Admission: model.CapacityNativeWorkerPhaseAdmission{NetworkBindingSHA256: a.NetworkBindingSHA256, WarmupEvidenceSHA256: strings.Repeat("b", 64), PhysicalQualificationSHA256: a.QualificationEvidenceSHA256}}
	return model.CapacityNativeWorkerPhasePreparation{Context: c, ObservedAt: time.Now().UTC(), ReadinessValidUntil: a.QualificationValidUntil, NodeReady: true, NetworkVerified: true, WarmupVerified: true, PhysicalQualified: true}, nil
}
func (r *phasePermitRuntime) ObservePhase(_ context.Context, c model.CapacityNativeWorkerPhasePermit) (model.CapacityNativeWorkerPhaseObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	epoch := c.Epoch
	if r.observeWrongEpoch {
		epoch++
	}
	return model.CapacityNativeWorkerPhaseObservation{RealmUID: c.RealmUID, PoolUID: c.PoolUID, Owner: c.Owner, Epoch: epoch, ObservedAt: time.Now().UTC(), Applied: r.observeApplied, NodeUID: c.Node.UID, RegistryUID: c.Registry.UID, RegistryResourceVersion: "20", RegistrySHA256: strings.Repeat("c", 64), ProviderID: c.Node.ProviderID, AdmissionReceiptSHA256: c.Admission.ReceiptSHA256, QuarantineAbsent: true, Ready: true}, nil
}

func nativePhasePGFixture(t *testing.T, maxPermitSeconds int, configure ...func(*model.CapacityPolicySpec)) (marketRepositoryFixture, CapacityNativeWorkerPhaseStore, *nativeAttemptRuntime, *phasePermitRuntime, model.CapacityNativeWorkerAuthority, model.CapacityNativeWorkerPhaseCaller) {
	t.Helper()
	f, workers, provider, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) {
		p.NativeWorkerLifecycleBinding.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: p.NativeWorkerLifecycleBinding.Profiles[0].Adapter, BindingName: "ci-registry-writer", PrincipalID: "ci-registry-writer-principal", SourceCommit: strings.Repeat("a", 40), ScopeSHA256: strings.Repeat("e", 64), Capability: "ensure_native_worker_pool", MaxPermitSeconds: maxPermitSeconds}
		for _, apply := range configure {
			apply(p)
		}
	})
	runtime := &phasePermitRuntime{p: f.p, nodes: map[uuid.UUID]string{}, observeApplied: true}
	store := CapacityNativeWorkerPhaseStore{Workers: workers, Runtime: runtime, Enabled: true}
	w := f.p.NativeWorkerLifecycleBinding.RegistryWriter
	caller := model.CapacityNativeWorkerPhaseCaller{Adapter: w.Adapter, PrincipalID: w.PrincipalID, BindingName: w.BindingName, SourceCommit: w.SourceCommit}
	return f, store, provider, runtime, authority, caller
}
func nativePhaseAcknowledged(t *testing.T, f marketRepositoryFixture, s CapacityNativeWorkerPhaseStore, a model.CapacityNativeWorkerAuthority) model.CapacityNativeWorkerAttempt {
	t.Helper()
	ctx := t.Context()
	child, err := s.Workers.Reserve(ctx, f.policy, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Workers.Redeem(ctx, f.policy, a, child.ID); err != nil {
		t.Fatal(err)
	}
	child, err = s.Workers.Record(ctx, f.policy, a, child.ID)
	if err != nil || child.State != "acknowledged" {
		t.Fatal("real child ledger did not retain original acceptance", err)
	}
	return child
}
func nativePhaseStored(t *testing.T, f marketRepositoryFixture, id uuid.UUID) nativeWorkerPhaseRecord {
	t.Helper()
	var raw []byte
	if err := f.db.QueryRow(`SELECT record FROM public.capacity_native_worker_phase_permits WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var r nativeWorkerPhaseRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func nativePhaseIssue(t *testing.T, f marketRepositoryFixture, s CapacityNativeWorkerPhaseStore, a model.CapacityNativeWorkerAuthority, child model.CapacityNativeWorkerAttempt) model.CapacityNativeWorkerPhasePermit {
	t.Helper()
	p, err := s.Issue(t.Context(), f.policy, a, child.ID, "register")
	if err != nil {
		t.Fatal(err)
	}
	if p.MutationPermitted || p.SettlementToken != "" || p.PhaseState != "issued" {
		t.Fatal("Issue returned a send bearer before durable Redeem")
	}
	if p.WriterScopeSHA256 != f.p.NativeWorkerLifecycleBinding.RegistryWriter.ScopeSHA256 {
		t.Fatal("Issue did not overwrite preparation with the exact policy writer scope")
	}
	return p
}

func TestNativeWorkerPhasePermitPostgresOneSendCustodyAndScope(t *testing.T) {
	f, s, provider, runtime, authority, caller := nativePhasePGFixture(t, 30)
	ctx := t.Context()
	t.Run("atomic_redeem_private_token_and_no_successor", func(t *testing.T) {
		child := nativePhaseAcknowledged(t, f, s, authority)
		p := nativePhaseIssue(t, f, s, authority, child)
		if _, err := s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
			t.Fatal("second issued phase bypassed per-attempt/action fence")
		}
		var won atomic.Int32
		var wg sync.WaitGroup
		tokens := make(chan model.CapacityNativeWorkerPhasePermit, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
				if err == nil {
					won.Add(1)
					tokens <- out
				} else if out.MutationPermitted || out.SettlementToken != "" {
					t.Error("failed/unknown redeem exposed a possible one-send bearer")
				}
			}()
		}
		wg.Wait()
		close(tokens)
		if won.Load() != 1 {
			t.Fatalf("want exactly one durable Redeem, got%d", won.Load())
		}
		permit := <-tokens
		if !permit.MutationPermitted || len(permit.SettlementToken) < 32 {
			t.Fatal("original successful Redeem lost its private mutation bearer")
		}
		if permit.WriterScopeSHA256 != p.WriterScopeSHA256 {
			t.Fatal("Redeem changed the reviewed writer inventory pin")
		}
		if _, err := s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
			t.Fatal("new phase bypassed redeemed/possibly-sent predecessor")
		}
		read, err := s.Read(ctx, f.policy, p.PermitID, caller)
		if err != nil || read.Redeemable || read.MutationPermitted || read.SettlementToken != "" {
			t.Fatal("historical read reopened a consumed right", err)
		}
		private := nativePhaseStored(t, f, p.PermitID)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(permit.SettlementToken)))
		if private.SettlementTokenSHA256 != hash || private.Context.SettlementToken != "" || private.Context.MutationPermitted {
			t.Fatal("bearer persisted in place of private digest")
		}
		var events string
		if err = f.db.QueryRow(`SELECT string_agg(record::text,'') FROM public.capacity_native_worker_phase_permit_events WHERE permit_id=$1`, p.PermitID).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(events, permit.SettlementToken) {
			t.Fatal("plaintext bearer entered durable event stream")
		}
		before := private.Revision
		receive := model.CapacityNativeWorkerPhaseReceive{PermitID: p.PermitID, BindingName: caller.BindingName, SettlementToken: "forged-token", HTTPStatus: 201, TransportCompleted: true, OriginalReturn: []byte(`{"private":"first-native-return"}`), CompletedAt: time.Now().UTC()}
		if _, err = s.Receive(ctx, f.policy, caller, receive); err == nil {
			t.Fatal("forged bearer archived a return")
		}
		if nativePhaseStored(t, f, p.PermitID).Revision != before {
			t.Fatal("unauthorized receive changed history")
		}
		receive.SettlementToken = permit.SettlementToken
		receive.TransportCompleted = false
		receive.HTTPStatus = 0
		got, err := s.Receive(ctx, f.policy, caller, receive)
		if err != nil || got.PhaseState != "unknown" {
			t.Fatal("uncertain original was mislabeled no-effect", err)
		}
		if _, err = s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
			t.Fatal("new phase bypassed unknown original")
		}
		runtime.mu.Lock()
		runtime.observeApplied = false
		runtime.mu.Unlock()
		if _, err = s.Reconcile(ctx, f.policy, p.PermitID, caller); err == nil {
			t.Fatal("failed fresh read silently reopened unknown phase")
		}
		runtime.mu.Lock()
		runtime.observeApplied = true
		runtime.mu.Unlock()
	})
	t.Run("received_success_and_ambiguous_refusal_never_allow_successor", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			code  int
			raw   string
			state string
		}{
			{"received", 201, `{"kind":"Lease","private":"ci-original-accepted"}`, "received"},
			{"ambiguous409", 409, `{"apiVersion":"v1","kind":"Status","metadata":{},"status":"Failure","reason":"Other","reason":"Conflict","code":409}`, "unknown"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				child := nativePhaseAcknowledged(t, f, s, authority)
				p := nativePhaseIssue(t, f, s, authority, child)
				one, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.Receive(ctx, f.policy, caller, model.CapacityNativeWorkerPhaseReceive{PermitID: p.PermitID, BindingName: caller.BindingName, SettlementToken: one.SettlementToken, HTTPStatus: tc.code, TransportCompleted: true, OriginalReturn: []byte(tc.raw), CompletedAt: time.Now().UTC()})
				if err != nil || got.PhaseState != tc.state {
					t.Fatal("original return classification lost custody or claimed false no-effect", got.PhaseState, err)
				}
				if _, err = s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
					t.Fatal("received/ambiguous original minted a second one-send permit")
				}
			})
		}
	})

	t.Run("only_definitive_no_effect_allows_successor", func(t *testing.T) {
		child := nativePhaseAcknowledged(t, f, s, authority)
		p := nativePhaseIssue(t, f, s, authority, child)
		one, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte(`{"apiVersion":"v1","kind":"Status","metadata":{},"status":"Failure","reason":"Conflict","code":409}`)
		got, err := s.Receive(ctx, f.policy, caller, model.CapacityNativeWorkerPhaseReceive{PermitID: p.PermitID, BindingName: caller.BindingName, SettlementToken: one.SettlementToken, HTTPStatus: 409, TransportCompleted: true, OriginalReturn: raw, CompletedAt: time.Now().UTC()})
		if err != nil || got.PhaseState != "no_effect" {
			t.Fatal("native atomic CAS refusal lost no-effect classification", err)
		}
		next, err := s.Issue(ctx, f.policy, authority, child.ID, "register")
		if err != nil || next.PermitID == p.PermitID || next.MutationPermitted {
			t.Fatal("definitive refusal cannot be followed by a distinct issued permit", err)
		}
		old := nativePhaseStored(t, f, p.PermitID)
		if old.Original == nil || string(old.Original.OriginalReturn) != string(raw) || old.Context.PhaseState != "no_effect" {
			t.Fatal("successor overwrote the original refusal")
		}
	})
	t.Run("current_attempt_progress_revokes_old_register_permit", func(t *testing.T) {
		child := nativePhaseAcknowledged(t, f, s, authority)
		p := nativePhaseIssue(t, f, s, authority, child)
		registered, err := s.Workers.Record(ctx, f.policy, authority, child.ID)
		if err != nil || registered.State != "registered" {
			t.Fatal("genuine child registry observation failed", err)
		}
		out, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
		if err == nil || out.MutationPermitted || out.SettlementToken != "" {
			t.Fatal("stale issued phase ignored advanced attempt state/Node binding")
		}
	})
	t.Run("fresh_registry_epoch_revocation_preserves_read_not_redeem", func(t *testing.T) {
		child := nativePhaseAcknowledged(t, f, s, authority)
		p := nativePhaseIssue(t, f, s, authority, child)
		provider.pool.OwnerEpoch++
		read, err := s.Read(ctx, f.policy, p.PermitID, caller)
		if err != nil || read.Redeemable || read.MutationPermitted || read.SettlementToken != "" {
			t.Fatal("historical read either disappeared or retained stale epoch authority", err)
		}
		out, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
		if err == nil || out.MutationPermitted || out.SettlementToken != "" {
			t.Fatal("fresh epoch change did not revoke one-send authority")
		}
		provider.pool.OwnerEpoch--
		bad := caller
		bad.SourceCommit = strings.Repeat("b", 40)
		if _, err = s.Read(ctx, f.policy, p.PermitID, bad); err == nil {
			t.Fatal("different source identity read protected context")
		}
	})
}

func TestNativeWorkerPhasePermitPostgresLateObservedOriginalAfterExpiry(t *testing.T) {
	f, s, _, runtime, authority, caller := nativePhasePGFixture(t, 2)
	ctx := t.Context()
	child := nativePhaseAcknowledged(t, f, s, authority)
	p := nativePhaseIssue(t, f, s, authority, child)
	one, err := s.Redeem(ctx, f.policy, p.PermitID, caller)
	if err != nil {
		t.Fatal(err)
	}
	// This timer runs only in the guarded disposable GitHub PostgreSQL fixture.
	// It expires the real two-second permit; no database history is rewritten.
	if delay := time.Until(p.ExpiresAt) + 25*time.Millisecond; delay > 0 {
		if delay > 3*time.Second {
			t.Fatal("unexpected permit lifetime")
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	runtime.mu.Lock()
	runtime.observeWrongEpoch = true
	runtime.mu.Unlock()
	if _, err = s.Reconcile(ctx, f.policy, p.PermitID, caller); err == nil {
		t.Fatal("readback from another registry epoch became observed")
	}
	runtime.mu.Lock()
	runtime.observeWrongEpoch = false
	runtime.mu.Unlock()
	got, err := s.Reconcile(ctx, f.policy, p.PermitID, caller)
	if err != nil || got.PhaseState != "observed" || got.MutationPermitted || got.Redeemable {
		t.Fatal("late GET-only truth required new mutation authority", err)
	}
	if _, err = s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
		t.Fatal("observed predecessor was reopened after its permit expired")
	}
	raw := []byte(`{"private_native_return":"ci-late-secret","partial_original":true}`)
	receive := model.CapacityNativeWorkerPhaseReceive{PermitID: p.PermitID, BindingName: caller.BindingName, SettlementToken: one.SettlementToken, HTTPStatus: 0, TransportCompleted: false, OriginalReturn: raw, CompletedAt: time.Now().UTC()}
	got, err = s.Receive(ctx, f.policy, caller, receive)
	if err != nil || got.PhaseState != "observed" || got.MutationPermitted || got.Redeemable || got.SettlementToken != "" {
		t.Fatal("late uncertain original either disappeared or reopened an observed phase", err)
	}
	first := nativePhaseStored(t, f, p.PermitID)
	if first.Original == nil || first.ReceivedAt == nil || string(first.Original.OriginalReturn) != string(raw) || first.Original.TransportCompleted || first.Original.SettlementToken != "" || first.Observed == nil {
		t.Fatal("original late uncertainty/observation was not privately preserved")
	}
	if _, err = s.Receive(ctx, f.policy, caller, receive); err != nil {
		t.Fatal("exact duplicate late custody is not idempotent", err)
	}
	if later := nativePhaseStored(t, f, p.PermitID); later.Revision != first.Revision || !later.ReceivedAt.Equal(*first.ReceivedAt) {
		t.Fatal("duplicate original rewrote its first custody revision or clock")
	}
	receive.OriginalReturn = append(append([]byte{}, raw...), byte(' '))
	if _, err = s.Receive(ctx, f.policy, caller, receive); err == nil {
		t.Fatal("different original bytes replaced immutable first custody")
	}
	again, err := s.Reconcile(ctx, f.policy, p.PermitID, caller)
	if err != nil || again.PhaseState != "observed" || again.MutationPermitted {
		t.Fatal("idempotent GET-only reconciliation changed terminal truth", err)
	}
	wire, _ := json.Marshal(again)
	for _, v := range []string{"ci-late-secret", one.SettlementToken, first.SettlementTokenSHA256, fmt.Sprintf("%x", sha256.Sum256(raw))} {
		if strings.Contains(string(wire), v) {
			t.Fatal("private original or its hash entered public late read")
		}
	}
}

func TestNativeWorkerPhasePermitPostgresExpiredNeverRedeemedCanBeReissued(t *testing.T) {
	f, s, _, _, authority, caller := nativePhasePGFixture(t, 1)
	ctx := t.Context()
	child := nativePhaseAcknowledged(t, f, s, authority)
	first := nativePhaseIssue(t, f, s, authority, child)
	if delay := time.Until(first.ExpiresAt) + 25*time.Millisecond; delay > 0 {
		if delay > 2*time.Second {
			t.Fatal("unexpected fixture deadline")
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// No Redeem took place and there is no original to conceal. Only this
	// never-authorized predecessor may be closed without a native Status.
	next, err := s.Issue(ctx, f.policy, authority, child.ID, "register")
	if err != nil || next.PermitID == first.PermitID || next.MutationPermitted {
		t.Fatal("expired never-redeemed permit deadlocked safe issuance", err)
	}
	old := nativePhaseStored(t, f, first.PermitID)
	if old.Context.PhaseState != "no_effect" || old.SettlementTokenSHA256 != "" || old.Original != nil {
		t.Fatal("expiry manufactured an original or erased a possible send")
	}
	var events int
	if err = f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_worker_phase_permit_events WHERE permit_id=$1`, first.PermitID).Scan(&events); err != nil || events != 2 {
		t.Fatal("safe expiry did not preserve issue plus terminal history", events, err)
	}
	if out, err := s.Redeem(ctx, f.policy, first.PermitID, caller); err == nil || out.MutationPermitted || out.SettlementToken != "" {
		t.Fatal("closed expired permit became redeemable")
	}
	if _, err = s.Issue(ctx, f.policy, authority, child.ID, "register"); err == nil {
		t.Fatal("fresh issued successor lost at-most-one active permit fence")
	}
}

// The protected runtime supplies a fixed evidence expiry, not a fresh TTL
// every time a caller asks to redeem a previously issued permission.
type phaseReadinessExpiryRuntime struct {
	*phasePermitRuntime
	validUntil time.Time
	prepares   int
}

func (r *phaseReadinessExpiryRuntime) PreparePhase(ctx context.Context, a model.CapacityNativeWorkerAttempt, action string) (model.CapacityNativeWorkerPhasePreparation, error) {
	v, err := r.phasePermitRuntime.PreparePhase(ctx, a, action)
	r.prepares++
	v.ReadinessValidUntil = r.validUntil
	return v, err
}

func TestNativeWorkerPhasePermitPostgresReadinessExpiryCannotBecomeSendAuthority(t *testing.T) {
	f, s, _, runtime, authority, caller := nativePhasePGFixture(t, 30, func(p *model.CapacityPolicySpec) {
		p.LeaseSeconds = 20
	})
	ctx := t.Context()
	r := &phaseReadinessExpiryRuntime{phasePermitRuntime: runtime}
	s.Runtime = r
	registered := func() model.CapacityNativeWorkerAttempt {
		t.Helper()
		a := nativePhaseAcknowledged(t, f, s, authority)
		a, err := s.Workers.Record(ctx, f.policy, authority, a.ID)
		if err != nil || a.State != "registered" || a.NodeUID == "" {
			t.Fatal("original child birth/registration required", err)
		}
		return a
	}

	child := registered()
	r.validUntil = time.Now().UTC().Add(2 * time.Second)
	p, err := s.Issue(ctx, f.policy, authority, child.ID, "admit_registry")
	if err != nil || !p.ExpiresAt.Equal(r.validUntil) || p.MutationPermitted || p.SettlementToken != "" {
		t.Fatal("shorter readiness evidence did not bound the actual issued permit", err)
	}
	if read, err := s.Read(ctx, f.policy, p.PermitID, caller); err != nil || !read.Redeemable {
		t.Fatal("fresh evidence did not retain normal redeemability", err)
	}
	// CI only: let the real DB clock cross the actual stored evidence limit.
	// Do not rewrite an immutable record or substitute a fake clock.
	timer := time.NewTimer(time.Until(p.ExpiresAt) + 25*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if out, err := s.Redeem(ctx, f.policy, p.PermitID, caller); err == nil || out.MutationPermitted || out.SettlementToken != "" {
		t.Fatal("expired readiness between Issue and Redeem minted a send bearer")
	}
	if read, err := s.Read(ctx, f.policy, p.PermitID, caller); err != nil || read.Redeemable || read.MutationPermitted {
		t.Fatal("expired evidence hid history or refreshed its authority", err)
	}
	stored := nativePhaseStored(t, f, p.PermitID)
	if stored.Revision != 1 || stored.Context.PhaseState != "issued" || stored.SettlementTokenSHA256 != "" || stored.Original != nil || !stored.Context.ExpiresAt.Equal(r.validUntil) || r.prepares != 1 {
		t.Fatal("refused redemption renewed evidence, consumed a permit or rewrote original custody")
	}

	// The evidence cap must never extend a still-shorter real parent lease.
	child = registered()
	var parent model.CapacityIntent
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil || parent.LeaseExpiresAt == nil {
		t.Fatal("real parent progress lease required", err)
	}
	r.validUntil = time.Now().UTC().Add(time.Minute)
	if !parent.LeaseExpiresAt.Before(r.validUntil) {
		t.Fatal("fixture does not establish the shorter parent lease")
	}
	p, err = s.Issue(ctx, f.policy, authority, child.ID, "admit_registry")
	if err != nil || !p.ExpiresAt.Equal(*parent.LeaseExpiresAt) {
		t.Fatal("longer evidence extended the original parent lease", err)
	}
	if out, err := s.Redeem(ctx, f.policy, p.PermitID, caller); err != nil || !out.MutationPermitted || out.SettlementToken == "" {
		t.Fatal("fresh genuinely bounded permit was refused", err)
	}

	child = registered()
	for _, until := range []time.Time{{}, time.Now().UTC().Add(-time.Second)} {
		r.validUntil = until
		if out, err := s.Issue(ctx, f.policy, authority, child.ID, "admit_registry"); err == nil || out.MutationPermitted || out.SettlementToken != "" {
			t.Fatal("missing/expired private readiness was issued as a new permission")
		}
	}
	var rows int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1`, child.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("refused readiness created phase history", rows, err)
	}
}
