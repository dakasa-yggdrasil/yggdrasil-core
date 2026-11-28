package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Real PostgreSQL, parent/command/Attempt and member Store custody; provider,
// allocator canaries and SDK are explicitly synthetic. The TLS wrapper below
// installs a fixed Go caller and calls Receive itself. It is not the production
// MemberListener/MemberOwner, an installer, a Node or an absence qualification.
func TestNativeMemberReceivingPostgresLateTLSOriginalSurvivesCallerCancellation(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(map[bool]string{true: "complete", false: "incomplete"}[complete], func(t *testing.T) {
			f := nativeMemberReceivingPGFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			var r nativeMemberRecord
			var token string
			core := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost || req.URL.Path != "/private-member-original" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				raw, readErr := io.ReadAll(io.LimitReader(req.Body, model.CapacityNativeWorkerMemberMaxReceiveBytes+1))
				closeErr := req.Body.Close()
				defer clear(raw)
				var original model.CapacityNativeWorkerMemberReceive
				if readErr != nil || closeErr != nil || req.Context().Err() != nil || len(raw) > model.CapacityNativeWorkerMemberMaxReceiveBytes || capacity.DecodeNativeCapacity(json.RawMessage(raw), &original) != nil || f.store.Receive(req.Context(), original, f.writer()) != nil {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(core.Close)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			captured := make(chan model.CapacityNativeWorkerMemberReceive, 1)
			posted := make(chan error, 1)
			var sdkCalls atomic.Int32
			body := []byte(`{"fixture":"private-member-http-original","private_value":"ci-only-never-public"}`)
			sdk := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if sdkCalls.Add(1) != 1 || req.Method != http.MethodPost || req.URL.Path != "/one-sdk-call" {
					w.WriteHeader(http.StatusConflict)
					return
				}
				original := model.CapacityNativeWorkerMemberReceive{Schema: model.CapacityNativeWorkerMemberReceiveSchema, BindingName: r.Context.Actor.BindingName, PermitID: r.Context.PermitID, SettlementToken: token, HTTPStatus: 200, CompletedAt: time.Now().UTC(), TransportCompleted: true, CaptureComplete: complete, OriginalReturn: bytes.Clone(body)}
				captured <- original
				// Intentionally independent of this canceled HTTP caller: the SDK
				// has not joined its original until its separate private POST ends.
				<-release
				tail, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				raw, err := original.PrivateJSON()
				defer clear(raw)
				if err != nil {
					posted <- err
					return
				}
				post, err := http.NewRequestWithContext(tail, http.MethodPost, core.URL+"/private-member-original", bytes.NewReader(raw))
				if err == nil {
					var response *http.Response
					response, err = core.Client().Do(post)
					if err == nil {
						_, readErr := io.Copy(io.Discard, response.Body)
						closeErr := response.Body.Close()
						if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent {
							err = errNativeMember
						}
					}
				}
				posted <- err
			}))
			t.Cleanup(sdk.Close)
			t.Cleanup(unblock)
			// The original completes while the permit is still live. Only its
			// custody POST occurs after expiry and local caller cancellation.
			r, token = f.row(t, "cordon", true, time.Now().UTC().Add(3*time.Second))
			callerCtx, callerCancel := context.WithCancel(ctx)
			defer callerCancel()
			request, err := http.NewRequestWithContext(callerCtx, http.MethodPost, sdk.URL+"/one-sdk-call", nil)
			if err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			go func() {
				response, err := sdk.Client().Do(request)
				if response != nil {
					_ = response.Body.Close()
				}
				returned <- err
			}()
			var original model.CapacityNativeWorkerMemberReceive
			select {
			case original = <-captured:
			case <-ctx.Done():
				t.Fatal("synthetic SDK did not enter", ctx.Err())
			}
			if !original.CompletedAt.Before(r.Context.NotAfter) || original.CompletedAt.Before(*r.RedeemedAt) {
				t.Fatal("fixture did not capture an original within its original permit")
			}
			callerCancel()
			select {
			case err = <-returned:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("original SDK caller did not cancel locally", err)
				}
			case <-ctx.Done():
				t.Fatal("local SDK caller failed to return", ctx.Err())
			}
			f.store.Seal()
			f.pending(t, ctx)
			untilExpired := time.NewTimer(time.Until(r.Context.NotAfter) + time.Millisecond)
			defer untilExpired.Stop()
			select {
			case <-untilExpired.C:
			case <-ctx.Done():
				t.Fatal("fixture expiry wait", ctx.Err())
			}
			unblock()
			select {
			case err = <-posted:
				if err != nil {
					t.Fatal("actual Store did not retain late private TLS original", err)
				}
			case <-ctx.Done():
				t.Fatal("late original did not return", ctx.Err())
			}
			if sdkCalls.Load() != 1 {
				t.Fatal("the SDK operation was repeated")
			}
			var raw []byte
			var stored nativeMemberRecord
			if err = f.f.db.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_member_permits WHERE id=$1`, r.Context.PermitID).Scan(&raw); err != nil || nativeMemberDecode(raw, &stored) != nil || stored.State != "received" || stored.Original == nil || capacity.NativeWorkerMemberContextSHA(stored.Context) != capacity.NativeWorkerMemberContextSHA(r.Context) {
				t.Fatal("private original custody changed the original context/state", err)
			}
			if bytes.Contains(raw, body) || bytes.Contains(raw, []byte(token)) {
				t.Fatal("raw private body or token was stored in clear")
			}
			decoded, err := f.store.state.original(stored)
			if err != nil || !bytes.Equal(decoded.OriginalReturn, body) || decoded.SettlementToken != token || !decoded.CompletedAt.Equal(original.CompletedAt) {
				t.Fatal("encrypted original lost exact bytes or completion time", err)
			}
			if complete {
				if err = f.store.ReceivingOriginalsJoined(ctx); err != nil {
					t.Fatal("complete late original did not join", err)
				}
			} else {
				f.pending(t, ctx)
			}
			f.keyRetained(t)
		})
	}
}

func TestNativeMemberReceivingPostgresReadKindsAndFailuresPreserveCustody(t *testing.T) {
	for _, kind := range []string{"member_inventory", "kubelet_configz"} {
		t.Run(kind, func(t *testing.T) {
			f := nativeMemberReceivingPGFixture(t)
			action := "cordon"
			if kind == "member_inventory" {
				action = "delete_node"
			}
			r, _ := f.row(t, action, false, time.Now().UTC().Add(-time.Second))
			in := model.CapacityNativeWorkerMemberSelectors{BindingName: r.Context.Observer.BindingName, PermitID: r.Context.PermitID}
			reader := NativeWorkerMemberCaller{Role: NativeMemberReaderRole, Binding: f.f.p.NativeWorkerLifecycleBinding.Members.Reader}
			out, err := f.store.Read(t.Context(), in, reader)
			if err != nil || out.ReadID == "" || out.Redeemable || out.MutationPermitted || out.State != "preparing" {
				t.Fatal("actual historical Store.Read did not issue a private durable context", err)
			}
			var raw []byte
			var rr nativeMemberReadRecord
			var state, endpoint string
			if err = f.f.db.QueryRowContext(t.Context(), `SELECT state,endpoint_kind,record FROM public.capacity_native_worker_member_reads WHERE id=$1`, out.ReadID).Scan(&state, &endpoint, &raw); err != nil || nativeMemberDecode(raw, &rr) != nil || state != "issued" || endpoint != kind || rr.Kind != kind || rr.ReadID.String() != out.ReadID || rr.ContextSHA256 != capacity.NativeWorkerMemberContextSHA(r.Context) || rr.SubjectNodeUID != f.a.NodeUID || rr.SDKSourceCommit != reader.Binding.SourceCommit || rr.ScopeSHA256 != reader.Binding.ScopeSHA256 || rr.PrivateOriginal != nil {
				t.Fatal("read context did not preserve its permit/Node/Source/scope/purpose", err)
			}
			original := model.CapacityNativeWorkerMemberReadOriginal{Schema: model.CapacityNativeWorkerMemberReadOriginalSchema, BindingName: in.BindingName, PermitID: in.PermitID, ReadID: out.ReadID, Kind: kind, HTTPStatus: 200, CompletedAt: time.Now().UTC(), CaptureComplete: true, TransportCompleted: true, OriginalReturn: []byte(`{"fixture_private_configz":"not-an-effective-kubelet-qualification"}`)}
			f.store.Seal()
			if _, err = f.store.Read(t.Context(), in, reader); !errors.Is(err, ErrCapacityDisabled) {
				t.Fatal("Seal allowed another read context", err)
			}
			if kind == "member_inventory" {
				if err = f.store.ReceiveRead(t.Context(), original, reader); err == nil {
					t.Fatal("metadata-only inventory accepted a configz original")
				}
				original.Kind = "kubelet_configz"
				if err = f.store.ReceiveRead(t.Context(), original, reader); err == nil {
					t.Fatal("changing the claimed purpose adopted the inventory read context")
				}
				_, err = f.f.db.ExecContext(t.Context(), `UPDATE public.capacity_native_worker_member_reads SET state='captured',record=record||jsonb_build_object('private_original',jsonb_build_object('nonce','YQ==','ciphertext','Yg==')),updated_at=clock_timestamp() WHERE id=$1`, out.ReadID)
				nativeMemberDDLCode(t, err, "P0001")
				if err = f.store.ReceivingOriginalsJoined(t.Context()); err != nil {
					t.Fatal("metadata-only durable read incorrectly waited for a configz body", err)
				}
				if err = f.f.db.Close(); err != nil {
					t.Fatal(err)
				}
				f.pending(t, t.Context())
			} else {
				f.pending(t, t.Context())
				for _, changed := range []string{"source", "scope", "read_id", "permit_id"} {
					bad, caller := original, reader
					switch changed {
					case "source":
						caller.Binding.SourceCommit = strings.Repeat("0", 40)
					case "scope":
						caller.Binding.ScopeSHA256 = strings.Repeat("0", 64)
					case "read_id":
						bad.ReadID = uuid.NewString()
					case "permit_id":
						bad.PermitID = uuid.NewString()
					}
					if err = f.store.ReceiveRead(t.Context(), bad, caller); err == nil {
						t.Fatal("read original adopted another Source/scope/read/permit", changed)
					}
				}
				if err = f.store.ReceiveRead(t.Context(), original, reader); err != nil {
					t.Fatal("sealed owner lost an original read already issued", err)
				}
				if err = f.store.ReceivingOriginalsJoined(t.Context()); err != nil {
					t.Fatal("complete captured configz transport did not join", err)
				}
			}
			f.keyRetained(t)
		})
	}
}

type nativeMemberReceivingPG struct {
	f     marketRepositoryFixture
	a     model.CapacityNativeWorkerAttempt
	store *CapacityNativeWorkerMemberStore
	key   []byte
}

func nativeMemberReceivingPGFixture(t *testing.T) nativeMemberReceivingPG {
	t.Helper()
	var store *CapacityNativeWorkerMemberStore
	key := bytes.Repeat([]byte{47}, 32)
	f, a, _, _ := nativeReadinessComposedFixture(t, nativeReadinessComposedOptions{NoOpen: true,
		ConfigurePolicy: func(t *testing.T, p *model.CapacityPolicySpec) {
			life := p.NativeWorkerLifecycleBinding
			binding := func(name, pin string) model.CapacityNativeWorkerProbeResourceBinding {
				b := life.ReadinessProducer.ResourceReader
				b.Name, b.ScopeSHA256 = name, strings.Repeat(pin, 64)
				b.Adapter.ManifestID, b.Adapter.IntegrationTypeID = uuid.NewString(), uuid.NewString()
				return b
			}
			writer := binding("ci-tail-writer", "a")
			writer.PrincipalID = "ci-tail-writer"
			life.PreAdmissionAbort = &model.CapacityNativeWorkerAbortBinding{Mode: model.CapacityNativeWorkerAbortSchema, Workflow: p.Workflow, MaxPermitSeconds: 30}
			life.Members = &model.CapacityNativeWorkerMemberBinding{Mode: capacity.NativeWorkerMemberMode, Name: "ci-tail-members", Writer: writer, Reader: binding("ci-tail-reader", "b"), AllocatorFenceReader: binding("ci-tail-fence", "c"), BootstrapPolicySHA256: strings.Repeat("d", 64), MaxPermitSeconds: 30, MaxReadAgeSeconds: 30}
		},
		BeforeRedeem: func(t *testing.T, f marketRepositoryFixture, workers *CapacityNativeWorkerStore, a model.CapacityNativeWorkerAttempt) {
			now := time.Now().UTC()
			authority := capacity.NativeWorkerMemberAuthority{FenceObjects: []model.CapacityNativeWorkerFenceObject{{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass", Name: "dakasa-native-placement-workloads", UID: uuid.NewString(), ResourceVersion: "ci-synthetic-1", PublicContentSHA256: strings.Repeat("e", 64)}}, LegacyControllers: []model.CapacityNativeWorkerLegacyController{}}
			for _, operation := range []string{"bind", "node_assignment", "pod_delete", "eviction"} {
				authority.Enforcement = append(authority.Enforcement, model.CapacityNativeWorkerFenceEnforcement{APIServerID: "ci-synthetic-api", PolicyUID: uuid.NewString(), Operation: operation, ObservedAt: now, HTTPStatus: 403, Reason: "explicit synthetic fixture, not a live VAP canary"})
			}
			runtime := &nativeMemberReceivingRuntime{db: f.db, policy: f.policy, spec: f.p, authority: authority}
			var err error
			store, err = newCapacityNativeWorkerMemberStore(NativeWorkerMemberStoreConfig{Workers: *workers, Policy: f.policy, Runtime: runtime, Authority: authority, Key: key, Enabled: true, ScopeSHA256: strings.Repeat("f", 64)}, f.p.NativeWorkerLifecycleBinding.SourceCommit)
			if err != nil {
				t.Fatal("CI-only explicit Source fixture could not install member custody", err)
			}
			workers.Members = store
		},
	})
	if store == nil || a.State != "registered" || a.Physical == nil || a.NodeUID == "" {
		t.Fatal("real Claim/Reserve/Redeem/ACK/registration ledger prerequisite missing")
	}
	t.Cleanup(func() { _ = store.Close(); clear(key) })
	return nativeMemberReceivingPG{f: f, a: a, store: store, key: key}
}

func (f nativeMemberReceivingPG) writer() NativeWorkerMemberCaller {
	return NativeWorkerMemberCaller{Role: NativeMemberWriterRole, Binding: f.f.p.NativeWorkerLifecycleBinding.Members.Writer}
}
func (f nativeMemberReceivingPG) keyRetained(t *testing.T) {
	t.Helper()
	if f.store.state.closed || !bytes.Equal(f.store.state.key, f.key) {
		t.Fatal("unjoined custody wiped the owner's key")
	}
}
func (f nativeMemberReceivingPG) pending(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.store.ReceivingOriginalsJoined(ctx); !errors.Is(err, ErrCapacityNativeReturnPending) {
		t.Fatal("uncertain original/DB failure did not keep receiving pending", err)
	}
	f.keyRetained(t)
}

// SQL-only member history on actual FKs: this does not call or qualify member
// Issue/Redeem, Node mutations, provider sends or the VAP installation. Identity
// is copied from the actual retained Attempt; private transport is tested below.
func (f nativeMemberReceivingPG) row(t *testing.T, action string, exposed bool, end time.Time) (nativeMemberRecord, string) {
	t.Helper()
	a, p := f.a, f.f.p
	pool, b := p.NativeWorkerPoolBinding, p.NativeWorkerLifecycleBinding.Members
	name, err := capacity.NativeWorkerBootstrapNodeName(a)
	if err != nil {
		t.Fatal(err)
	}
	now, planID := time.Now().UTC(), uuid.New()
	identity := nativeMemberPlanIdentity{Schema: "native_worker_member_plan_v1", PlanID: planID, AttemptID: a.ID, PolicyID: a.PolicyID, PolicyChecksum: a.PolicyChecksum, Namespace: a.Namespace, Kind: "retirement", Mode: "never_admitted", SubjectUID: uuid.MustParse(a.NodeUID), SourceCommit: a.SourceCommit, BirthSHA256: a.BirthSHA256, Generation: a.Generation, Fence: a.FencingToken, ParentKind: "recovery_workflow_v1", RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Epoch: pool.ExpectedPoolEpoch, ExecutorID: f.f.store.ExecutorID, WorkflowID: f.f.store.WorkflowID}
	plan := nativeMemberPlanRecord{Identity: identity, State: "active", Revision: 1}
	_, err = f.f.db.ExecContext(t.Context(), `INSERT INTO public.capacity_native_worker_member_plans(id,attempt_id,policy_id,namespace,kind,mode,subject_uid,state,revision,identity,record,created_at,updated_at) VALUES($1,$2,$3,$4,'retirement','never_admitted',$5,'active',1,$6,$7,$8,$8)`, planID, a.ID, a.PolicyID, a.Namespace, a.NodeUID, nativeMemberDDLJSON(t, identity), nativeMemberDDLJSON(t, plan), now)
	if err != nil {
		t.Fatal("SQL-only member plan fixture", err)
	}
	c := model.CapacityNativeWorkerMemberContext{Schema: model.CapacityNativeWorkerMemberContextSchema, PlanID: planID.String(), PermitID: uuid.NewString(), AttemptID: a.ID.String(), CoreSourceCommit: a.SourceCommit, Mode: "never_admitted", Action: action, Actor: capacity.NativeWorkerMemberEndpoint(b.Writer, capacity.NativeWorkerMemberCapability(action, "retirement")), Observer: capacity.NativeWorkerMemberEndpoint(b.Reader, capacity.NativeWorkerMemberReadCapability(action)), PolicyID: a.PolicyID.String(), PolicyChecksum: a.PolicyChecksum, IntentGeneration: a.Generation, FencingToken: a.FencingToken, RealmNamespace: pool.RegistryRef.Namespace, RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch, Profile: a.Profile, BirthSHA256: a.BirthSHA256, Physical: *a.Physical, OverlayIPv4: a.OverlayIPv4, Node: &model.CapacityNativeWorkerMemberNode{Name: name, UID: a.NodeUID, ResourceVersion: "ci-synthetic-node-rv", ProviderID: a.Physical.ProviderID}, Registry: a.Registry, BootstrapPolicySHA256: b.BootstrapPolicySHA256, PlacementFenceSHA256: strings.Repeat("e", 64), NotAfter: end}
	if action == "delete_node" {
		c.PhysicalAbsenceEvidenceSHA256 = strings.Repeat("d", 64)
	}
	if err = capacity.NativeWorkerMemberContextValid(p, a, c, now, false); err != nil {
		t.Fatal("synthetic context lost the actual retained identity", err)
	}
	r := nativeMemberRecord{Context: c, State: "preparing", Revision: 1}
	if exposed {
		r.State = "issued"
	}
	_, err = f.f.db.ExecContext(t.Context(), `INSERT INTO public.capacity_native_worker_member_permits(id,plan_id,attempt_id,policy_id,namespace,action,capability,subject_uid,state,revision,context,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$12)`, c.PermitID, planID, a.ID, a.PolicyID, a.Namespace, action, c.Actor.Capability, a.NodeUID, r.State, nativeMemberDDLJSON(t, c), nativeMemberDDLJSON(t, r), now)
	if err != nil {
		t.Fatal("SQL-only member permit fixture", err)
	}
	if !exposed {
		return r, ""
	}
	dispatch, redeemed := time.Now().UTC(), time.Now().UTC()
	if err = nativeMemberDDLUpdate(t.Context(), f.f.db, uuid.MustParse(c.PermitID), "issued", map[string]any{"dispatch_started_at": dispatch}); err != nil {
		t.Fatal("SQL-only dispatch fixture", err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{59}, 32))
	hash, ok := nativeReadinessTokenSHA(token)
	if !ok {
		t.Fatal("synthetic canonical token")
	}
	if err = nativeMemberDDLUpdate(t.Context(), f.f.db, uuid.MustParse(c.PermitID), "redeemed", map[string]any{"settlement_token_sha256": hash, "redeemed_at": redeemed}); err != nil {
		t.Fatal("SQL-only exposed custody fixture", err)
	}
	r.State, r.Revision, r.DispatchStartedAt, r.RedeemedAt, r.SettlementTokenSHA256 = "redeemed", 3, &dispatch, &redeemed, hash
	return r, token
}

type nativeMemberReceivingRuntime struct {
	db        *sql.DB
	policy    model.Manifest
	spec      model.CapacityPolicySpec
	authority capacity.NativeWorkerMemberAuthority
}

func (s *nativeMemberReceivingRuntime) SourceCommit() string {
	return s.spec.NativeWorkerLifecycleBinding.SourceCommit
}
func (s *nativeMemberReceivingRuntime) AllocatorFence(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAllocatorFenceContext, model.CapacityNativeWorkerAllocatorFenceObservation, error) {
	c, err := nativeMemberFenceContext(ctx, s.db, s.policy, s.spec, a)
	if err != nil {
		return c, model.CapacityNativeWorkerAllocatorFenceObservation{}, err
	}
	o := model.CapacityNativeWorkerAllocatorFenceObservation{Schema: model.CapacityNativeWorkerAllocatorFenceObservationSchema, BindingName: c.Observer.BindingName, CreatorPermitID: c.CreatorPermitID, SourceCommit: c.Observer.SourceCommit, ScopeSHA256: c.Observer.ScopeSHA256, Adapter: c.Observer.Adapter, ContextSHA256: nativeMemberDigest(c), ObservedAt: time.Now().UTC(), Objects: s.authority.FenceObjects, Enforcement: s.authority.Enforcement, LegacyControllers: s.authority.LegacyControllers, ProducerInventoryComplete: true, Complete: true}
	return c, o, nil
}
func (*nativeMemberReceivingRuntime) Target(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhaseReadObservation, error) {
	return model.CapacityNativeWorkerPhaseReadObservation{}, errNativeMember
}
func (*nativeMemberReceivingRuntime) Facts(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerMemberContext) (capacity.NativeWorkerMemberFacts, error) {
	return capacity.NativeWorkerMemberFacts{}, errNativeMember
}
func (*nativeMemberReceivingRuntime) Observe(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerMemberContext) (model.CapacityNativeWorkerMemberObservation, error) {
	return model.CapacityNativeWorkerMemberObservation{}, errNativeMember
}
func (*nativeMemberReceivingRuntime) Send(context.Context, model.CapacityNativeWorkerMemberContext) error {
	return errNativeMember
}
