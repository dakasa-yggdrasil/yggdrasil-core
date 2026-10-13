package httpapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type originalNotifyDispatchFixture struct {
	dispatchHTTPFixture
	owner context.Context
	job   repository.CapacityDispatchJob
	// Private expected claim copy captured by the actual dispatch guard. The
	// immutable started database row remains the original independent source.
	dispatchClaim *repository.CapacityDispatchJob
	store         repository.CapacityStore
	intent        model.CapacityIntent
	scope         messagecontroller.OriginalNotifyWindowScope
	factory       messagecontroller.OriginalNotifyAuthorityFactory
	marker        model.CapacityOriginalNotifyWindowMarker
	tls           *httptest.Server
}

// The PG records/real Core guards are native; the unexecuted participant roster
// below is a DECLARED protocol fixture. It proves no live Notify/Pod/capacity.
func originalNotifyDispatchPostgresFixture(t *testing.T) *originalNotifyDispatchFixture {
	t.Helper()
	base := dispatchHTTPPostgresFixture(t)
	owner, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	server := httptest.NewTLSServer(http.HandlerFunc(base.server.serveOriginalCanaryAuthority))
	t.Cleanup(server.Close)
	p := base.spec
	p.Domain = "app-notify"
	p.NativeNotifyWindowBinding = &model.CapacityNativeNotifyWindowBinding{Mode: "core_original_bound_machine", Name: "original", SourceCommit: strings.Repeat("1", 40), QuerySHA256: "cb805c604ceeffb265368719082a2f9203dabb60fc0406e1378e64e6ba0180f1", CoreAuthorityURL: server.URL + capacityOriginalCanaryAuthorityPath, Adapter: p.AssessmentBinding.Snapshot.Adapter, NativeNamespace: p.AssessmentBinding.Snapshot.Namespace, NativeBindingName: p.HPAExecutionBinding.PodTerminationBinding, PrivateBindingName: "notify-private", ControlKeyRef: "secret://" + p.Workflow.Namespace + "/control#value", ReadKeyRef: "secret://" + p.Workflow.Namespace + "/read#value", ProbeCount: 1, Participants: []model.CapacityNativeNotifyParticipant{{PodName: "notify-a", Origin: "https://original-a.invalid", Role: "publisher_reader"}, {PodName: "notify-b", Origin: "https://original-b.invalid", Role: "consumer"}}}
	base.spec = p
	base.policy = base.create("capacity_policy", "pods", p)
	admissionWorkflow := base.create("workflow", "admit", model.WorkflowManifestSpec{Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: p.Workflow.Namespace, Name: "dispatch"}}, Steps: []model.WorkflowStepSpec{{ID: "native", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.admit_bound"}, With: map[string]any{"policy": map[string]any{"namespace": p.Workflow.Namespace, "name": "pods"}}}}})
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	queued := base.enqueue(t, base.prepare(t))
	job, err := repository.ClaimCapacityDispatch(owner, base.db, queued.Realm, queued.Environment, uuid.New(), 90*time.Second)
	if err != nil {
		t.Fatal("original dispatch claim unavailable", err)
	}
	job, err = repository.StartCapacityDispatch(owner, base.db, job)
	if err != nil {
		t.Fatal("original dispatch Start Commit ACK unavailable", err)
	}
	executor := uuid.NewString()
	admission := repository.CapacityStore{DB: base.db, ExecutionEnabled: true, AdmissionOnly: true, WorkflowID: admissionWorkflow.ID, ExecutorID: executor}
	b := p.AssessmentBinding.Snapshot
	hpa := model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: b.Namespace, HPAName: b.HPAName, HPAUID: b.HPAUID, ResourceVersion: "1", WorkloadName: b.WorkloadName, WorkloadUID: b.WorkloadUID, WorkloadResourceVersion: "1", Owner: b.Owner, EnvelopeGeneration: 1, IdempotencyKey: "native-protocol", MinReplicas: 2, MaxReplicas: p.Ceiling, ProtectedFloor: p.Floor, TrackedProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	intent, err := admission.AcquireNativeAdmissionExecution(owner, base.policy, hpa)
	if err != nil {
		t.Fatal("original native PG lease unavailable", err)
	}
	store := admission
	store.AdmissionOnly = false
	store.WorkflowID = base.workflow.ID
	guard := func(ctx context.Context) error {
		_, _, err := base.service.authorizeEnvelope(ctx, job.CapacityDispatchEnvelope)
		return errors.Join(err, repository.ValidateCapacityDispatchClaim(ctx, base.db, job, true), dispatchContext(ctx), dispatchContext(owner))
	}
	factory := base.service.originalNotifyFactory(job, owner, guard)
	a, buid := uuid.NewString(), uuid.NewString()
	roster := messagecontroller.OriginalNotifyNativeRoster{BindingName: p.NativeNotifyWindowBinding.NativeBindingName, PublisherUID: a, ReaderUID: a, ConsumerUIDs: []string{buid}, ManagedPods: []messagecontroller.OriginalNotifyNativeIdentity{{PodName: "notify-a", PodUID: a}, {PodName: "notify-b", PodUID: buid}}}
	scope, err := factory.PrepareScope(owner, base.policy, p, intent, roster)
	if err != nil {
		t.Fatal("actual private factory current guards refused", err)
	}
	scopeSHA, err := dispatchSHA(scope)
	if err != nil {
		t.Fatal(err)
	}
	rosterSHA, err := dispatchSHA(roster)
	if err != nil {
		t.Fatal(err)
	}
	marker := model.CapacityOriginalNotifyWindowMarker{Schema: "core_original_notify_window_marker_v1", State: "possible_start", WindowID: scope.WindowID, ScopeSHA256: scopeSHA, SourceCommit: p.NativeNotifyWindowBinding.SourceCommit, QuerySHA256: p.NativeNotifyWindowBinding.QuerySHA256, RosterSHA256: rosterSHA, PolicyID: scope.PolicyID, PolicyChecksum: scope.PolicyChecksum, WorkflowID: scope.WorkflowID, WorkflowChecksum: scope.CoreAuthority.WorkflowChecksum, DispatchJobID: scope.CoreAuthority.DispatchJobID, DispatchFence: scope.CoreAuthority.DispatchFence, IntentGeneration: scope.Generation, IntentFence: scope.FencingToken, LeaseOwner: scope.LeaseOwner, ExecutorID: scope.LeaseExecutorID, Deadline: scope.Deadline}
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM public.capacity_intent_events WHERE namespace=$1`, `DELETE FROM public.capacity_intents WHERE namespace=$1`} {
			if _, err := base.db.ExecContext(context.Background(), q, base.policy.Metadata.Namespace); err != nil {
				t.Error(err)
			}
		}
	})
	return &originalNotifyDispatchFixture{dispatchHTTPFixture: base, owner: owner, job: job, dispatchClaim: &job, store: store, intent: intent, scope: scope, factory: factory, marker: marker, tls: server}
}

func (f *originalNotifyDispatchFixture) begin(t *testing.T) {
	t.Helper()
	next, err := f.store.BeginOriginalNotifyWindow(f.owner, f.policy, f.intent, f.marker)
	if err != nil {
		t.Fatal("original marker Commit ACK refused", err)
	}
	f.intent = next
}

func (f *originalNotifyDispatchFixture) readIntent(t *testing.T) model.CapacityIntent {
	t.Helper()
	return nativeKindOriginalNotifyIntent(t, f.owner, f.db, f.policy, f.spec)
}

func TestCapacityOriginalNotifyWindowPostgres(t *testing.T) {
	t.Run("same_original_start_and_marker_ack_before_register", func(t *testing.T) {
		f := originalNotifyDispatchPostgresFixture(t)
		if token, revoke, _, err := f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope); err == nil || token.HeaderValue() != "" || revoke != nil {
			t.Fatal("fresh SQL/constructor replaced missing original ACK")
		}
		f.begin(t)
		token, revoke, current, err := f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope)
		if err != nil || revoke == nil || current == nil {
			t.Fatal("same original Start/marker guards did not register", err)
		}
		defer revoke()
		if err = current(f.owner); err != nil {
			t.Fatal("current original guards refused", err)
		}
		if _, _, _, err = f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope); err == nil {
			t.Fatal("same owner reconstructed/reminted token")
		}
		req, err := http.NewRequestWithContext(f.owner, http.MethodGet, f.tls.URL+capacityOriginalCanaryAuthorityPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(capacityOriginalCanaryAuthorityHeader, token.HeaderValue())
		req.Header.Set(capacityOriginalCanaryScopeHeader, f.marker.ScopeSHA256)
		response, err := f.tls.Client().Do(req)
		if err != nil {
			t.Fatal("actual original TLS permission GET refused", err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
		err = errors.Join(err, response.Body.Close())
		var reply capacity.OriginalCanaryAuthorityReply
		if err != nil || response.StatusCode != http.StatusOK || capacity.DecodeBusinessJSON(raw, &reply) != nil || !reply.OriginalLiveLeaseVerified || !reply.CurrentMachineRBACVerified || reply.HumanSessionVerified || reply.UsefulCapacityKnown || reply.FullTransitionQualified {
			t.Fatal("permission reply borrowed capacity/human authority")
		}
		if f.readIntent(t).LeaseExpiresAt == nil {
			t.Fatal("permission completed original lease")
		}
	})
	for _, mode := range []string{"dispatch_fence", "intent_fence", "intent_owner", "intent_executor", "policy", "rbac", "principal"} {
		t.Run("current_"+mode+"_refuses_registration", func(t *testing.T) {
			f := originalNotifyDispatchPostgresFixture(t)
			f.begin(t)
			intent := f.intent
			switch mode {
			case "dispatch_fence":
				// A started claim is durably immutable. Present a mismatched
				// expected copy to the SAME actual SQL guard, never rewrite it.
				wrong := *f.dispatchClaim
				wrong.FencingToken++
				*f.dispatchClaim = wrong
			case "intent_fence":
				intent.FencingToken++
			case "intent_owner":
				intent.LeaseOwner = uuid.NewString()
			case "intent_executor":
				intent.LeaseExecutorID = uuid.NewString()
			case "policy":
				p := f.spec
				p.NativeNotifyWindowBinding = nil
				f.create("capacity_policy", "pods", p)
			case "rbac":
				deny := f.allow
				deny.Roles = []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "deny", Resources: []string{"workflow:" + f.workflow.Metadata.Namespace + ":pressure"}, Actions: []string{"run"}}}}}
				f.create("rbac", "dispatch", deny)
			case "principal":
				f.server.workflowRunAuthConfig().principals[0].Status = "revoked"
			}
			token, revoke, _, err := f.factory.Register(f.owner, f.policy, f.spec, intent, f.scope)
			if err == nil || token.HeaderValue() != "" || revoke != nil {
				t.Fatal("stale current owner/source/authority admitted")
			}
			if mode == "dispatch_fence" && (!errors.Is(err, repository.ErrCapacityDispatchClaim) || repository.ValidateCapacityDispatchClaim(f.owner, f.db, f.job, true) != nil) {
				t.Fatal("actual mismatched dispatch guard did not refuse or original row changed")
			}
			if current := f.readIntent(t); current.OriginalNotifyWindow == nil || current.OriginalNotifyWindow.State != "possible_start" || current.LeaseExpiresAt == nil {
				t.Fatal("refusal released pending original")
			}
		})
	}
	t.Run("different_original_core_cannot_adopt_bearer", func(t *testing.T) {
		f := originalNotifyDispatchPostgresFixture(t)
		f.begin(t)
		token, revoke, _, err := f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer revoke()
		other := capacity.NewOriginalCanaryAuthorityRegistry()
		if _, err := other.Observe(f.owner, token.HeaderValue(), f.marker.ScopeSHA256); err == nil {
			t.Fatal("other Core registry copied original authority")
		}
		revoke()
		if _, err = f.server.originalCanaryAuthorities.Observe(f.owner, token.HeaderValue(), f.marker.ScopeSHA256); err == nil {
			t.Fatal("revoked original invocation adopted")
		}
	})
	t.Run("unknown_marker_survives_generation_and_binding_removal", func(t *testing.T) {
		f := originalNotifyDispatchPostgresFixture(t)
		f.begin(t)
		original := f.readIntent(t)
		// Fault setup changes ONLY this fixture's lease/phase, never foreign rows.
		// The subsequent ORIGINAL Assess constructs a new intent value and must
		// still carry its previous immutable possible-start marker.
		raw, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.ExecContext(f.owner, `UPDATE public.capacity_intents SET intent=jsonb_set(jsonb_set(jsonb_set(jsonb_set($2::jsonb,'{phase}','"hold"'),'{lease_owner}','""'),'{lease_executor_id}','""'),'{lease_expires_at}','null') WHERE namespace=$1`, f.policy.Metadata.Namespace, raw); err != nil {
			t.Fatal(err)
		}
		p := f.spec
		p.NativeNotifyWindowBinding = nil
		policy := f.create("capacity_policy", "pods", p)
		assessment := original.Assessment
		now := time.Now().UTC()
		assessment.Snapshot.ObservedAt = now
		v := 0.9
		assessment.Evidence = []model.CapacityEvidence{{Name: p.Signals[0].Name, SourceIdentity: p.Signals[0].SourceIdentity, Unit: p.Signals[0].Unit, RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Second), WindowEnd: now, Samples: 1, CoverageComplete: true, MaxGapSeconds: 1}}
		if _, err = f.store.Assess(f.owner, policy, assessment); err != nil {
			t.Fatal("original next-generation Assess refused", err)
		}
		current := nativeKindOriginalNotifyIntent(t, f.owner, f.db, policy, p)
		if current.Generation <= original.Generation || current.OriginalNotifyWindow == nil || current.OriginalNotifyWindow.ScopeSHA256 != f.marker.ScopeSHA256 || current.OriginalNotifyWindow.State != "possible_start" {
			t.Fatal("original marker erased by new value/binding removal")
		}
		encoded, _ := json.Marshal(current.OriginalNotifyWindow)
		if strings.Contains(string(encoded), "Bearer") || strings.Contains(string(encoded), "secret://") {
			t.Fatal("private credential entered durable marker")
		}
	})
	t.Run("final_original_return_commit_precedes_reservation_complete", func(t *testing.T) {
		f := originalNotifyDispatchPostgresFixture(t)
		f.begin(t)
		token, revoke, current, err := f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer revoke()
		digest := strings.Repeat("f", 64)
		if err = f.store.RecordOriginalNotifyWindowReturns(f.owner, f.policy, f.intent, f.marker.ScopeSHA256, digest, time.Now().UTC()); err != nil {
			t.Fatal("actual source observation Commit ACK refused", err)
		}
		native := f.readIntent(t)
		if native.LeaseExpiresAt == nil || native.OriginalNotifyWindow.State != "original_returns_observed" {
			t.Fatal("recording original returns cleared live lease")
		}
		if err = current(f.owner); err != nil {
			t.Fatal("same owner ended before original completion", err)
		}
		if err = f.store.CompleteNativeReservationDecision(f.owner, f.policy, f.intent); err != nil {
			t.Fatal("original reservation Complete refused", err)
		}
		if f.readIntent(t).LeaseExpiresAt != nil {
			t.Fatal("original Complete did not retire reservation lease")
		}
		if _, err = f.server.originalCanaryAuthorities.Observe(f.owner, token.HeaderValue(), f.marker.ScopeSHA256); err == nil {
			t.Fatal("postComplete permission remained live")
		}
	})
	for _, mode := range []string{"lost_ack", "late_actual_ack"} {
		t.Run(mode+"_original_marker_no_registration", func(t *testing.T) {
			f := originalNotifyDispatchPostgresFixture(t)
			connector, err := pq.NewConnector(os.Getenv("DB_URL"))
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &originalNotifyMarkerConnector{Connector: connector, mode: mode, cause: errors.New("private-original-marker-ack"), entered: make(chan struct{}), release: make(chan struct{})}
			db := sql.OpenDB(wrapped)
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error("original wrapped pool Close failed")
				}
			})
			store := f.store
			store.DB = db
			owner, cancel := context.WithCancelCause(f.owner)
			defer cancel(nil)
			var returned model.CapacityIntent
			var originalErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				returned, originalErr = store.BeginOriginalNotifyWindow(owner, f.policy, f.intent, f.marker)
			}()
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(wrapped.release) }); <-done })
			if mode == "late_actual_ack" {
				select {
				case <-wrapped.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("actual original marker Commit never returned")
				}
				cancel(wrapped.cause)
				select {
				case <-done:
					t.Fatal("deadline replaced actual original Commit return")
				default:
				}
				releaseOnce.Do(func() { close(wrapped.release) })
			}
			<-done
			if originalErr == nil || returned.OriginalNotifyWindow != nil || wrapped.markerCommits.Load() != 1 || wrapped.markerWrites.Load() != 1 {
				t.Fatal("original acknowledgment/census fabricated")
			}
			if mode == "lost_ack" && !errors.Is(originalErr, wrapped.cause) {
				t.Fatal("original ACK cause dropped")
			}
			if mode == "late_actual_ack" && !errors.Is(originalErr, wrapped.cause) {
				t.Fatal("original cancel cause dropped")
			}
			if token, revoke, _, err := f.factory.Register(f.owner, f.policy, f.spec, f.intent, f.scope); err == nil || token.HeaderValue() != "" || revoke != nil {
				t.Fatal("SQL presence replaced unknown original ACK")
			}
			current := f.readIntent(t)
			if current.OriginalNotifyWindow == nil || current.OriginalNotifyWindow.State != "possible_start" || current.LeaseExpiresAt == nil {
				t.Fatal("unknown original marker not durable")
			}
			if _, err = store.BeginOriginalNotifyWindow(f.owner, f.policy, f.intent, f.marker); err == nil || wrapped.markerCommits.Load() != 1 {
				t.Fatal("original unknown replayed")
			}
		})
	}
}

// Classify the actual accepted intent UPDATE in SAME original TX. Native
// authorization audits and read-only guard Commits cannot consume this fault.
type originalNotifyMarkerConnector struct {
	driver.Connector
	mode                        string
	cause                       error
	markerWrites, markerCommits atomic.Int64
	lost                        atomic.Bool
	entered, release            chan struct{}
}

func (c *originalNotifyMarkerConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	original, ok := conn.(demandOriginalConn)
	if !ok {
		return nil, errors.Join(errors.New("actual original pq interfaces required"), conn.Close())
	}
	return &originalNotifyMarkerConn{demandOriginalConn: original, owner: c}, nil
}

type originalNotifyMarkerConn struct {
	demandOriginalConn
	owner  *originalNotifyMarkerConnector
	active *originalNotifyMarkerTx
}

func (c *originalNotifyMarkerConn) wrap(tx driver.Tx, err error) (driver.Tx, error) {
	if err != nil {
		return nil, err
	}
	c.active = &originalNotifyMarkerTx{Tx: tx, conn: c}
	return c.active, nil
}
func (c *originalNotifyMarkerConn) Begin() (driver.Tx, error) {
	tx, err := c.demandOriginalConn.Begin()
	return c.wrap(tx, err)
}
func (c *originalNotifyMarkerConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.demandOriginalConn.BeginTx(ctx, opts)
	return c.wrap(tx, err)
}
func (c *originalNotifyMarkerConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.demandOriginalConn.ExecContext(ctx, query, args)
	if err == nil && result != nil && c.active != nil && strings.Contains(query, "UPDATE public.capacity_intents SET intent=$5") && len(args) >= 5 {
		count, e := result.RowsAffected()
		var raw []byte
		switch v := args[4].Value.(type) {
		case []byte:
			raw = v
		case string:
			raw = []byte(v)
		}
		var intent model.CapacityIntent
		if e == nil && count == 1 && capacity.DecodeNativeCapacity(json.RawMessage(raw), &intent) == nil && intent.OriginalNotifyWindow != nil && intent.OriginalNotifyWindow.State == "possible_start" {
			c.active.marker = true
			c.owner.markerWrites.Add(1)
		}
	}
	return result, err
}

type originalNotifyMarkerTx struct {
	driver.Tx
	conn   *originalNotifyMarkerConn
	marker bool
}

func (tx *originalNotifyMarkerTx) Commit() error {
	err := tx.Tx.Commit()
	tx.conn.active = nil
	if err == nil && tx.marker {
		tx.conn.owner.markerCommits.Add(1)
		if tx.conn.owner.lost.CompareAndSwap(false, true) {
			if tx.conn.owner.mode == "late_actual_ack" {
				close(tx.conn.owner.entered)
				<-tx.conn.owner.release
				return nil
			}
			return tx.conn.owner.cause
		}
	}
	return err
}
func (tx *originalNotifyMarkerTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.conn.active = nil
	return err
}
