//go:build linux

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativeMemberNetworkAuthenticationReached = errors.New("scripted network authentication reached")
var errNativeMemberNetworkUnexpectedOperation = errors.New("scripted unexpected network operation")

// The driver supplies SQL-only identity vectors, never a qualified provider,
// floor read, member plan, dispatch or absence proof. No database is contacted.
// Reaching the real authentication method in the legacy control is essential:
// a malformed selector/record must not make the Members negatives pass vacuously.
func TestNativeMemberNetworkRedeemRequiresRetirementBeforeAuthentication(t *testing.T) {
	for _, owner := range []string{"nil", "uninstalled", "no_retirement_history"} {
		t.Run(owner, func(t *testing.T) {
			f := newNativeMemberNetworkRedeemFixture(t, true, owner == "no_retirement_history")
			wantErr := ErrCapacityDisabled
			switch owner {
			case "uninstalled":
				f.store.Workers.Members = &CapacityNativeWorkerMemberStore{}
			case "no_retirement_history":
				// This private test state can read the scripted empty journal. It
				// deliberately has no plan/dispatch/facts and is not an installed
				// runtime or a bypass of the public constructor's Source checks.
				f.store.Workers.Members = &CapacityNativeWorkerMemberStore{state: &nativeMemberStoreState{
					workers: f.store.Workers, policy: f.policy, key: bytes.Repeat([]byte{71}, 32),
				}}
				t.Cleanup(func() {
					if err := f.store.Workers.Members.Close(); err != nil {
						t.Error("close synthetic member storage", err)
					}
				})
				wantErr = errNativeMember
			}
			// Intentionally call Redeem directly. A preceding Store.Read would
			// hide a gate installed in the wrong public method.
			got, err := f.store.Redeem(t.Context(), f.policy, f.permit, f.caller)
			if !errors.Is(err, wantErr) || got.MutationPermitted || got.Redeemable || got.PermitID != "" {
				t.Fatal("direct Redeem exposed a right or missed the Members fence", err)
			}
			if f.runtime.phaseReads != 0 || f.runtime.poolReads != 0 || f.runtime.networkPrepares != 0 || f.runtime.networkReads != 0 || f.runtime.otherCalls != 0 {
				t.Fatal("Members refusal occurred after external authentication/preparation")
			}
			f.script.requireCompleteReadOnly(t)
		})
	}
}

func TestNativeMemberNetworkRedeemLegacyControlReachesAuthentication(t *testing.T) {
	f := newNativeMemberNetworkRedeemFixture(t, false, false)
	got, err := f.store.Redeem(t.Context(), f.policy, f.permit, f.caller)
	if !errors.Is(err, errNativeMemberNetworkAuthenticationReached) || got.MutationPermitted || got.Redeemable || got.PermitID != "" {
		t.Fatal("nil-Members control failed to reach actual authentication", err)
	}
	if f.runtime.phaseReads != 1 || f.runtime.poolReads != 0 || f.runtime.networkPrepares != 0 || f.runtime.networkReads != 0 || f.runtime.otherCalls != 0 {
		t.Fatal("legacy control did not stop exactly at the phase authority sentinel")
	}
	f.script.requireCompleteReadOnly(t)
}

type nativeMemberNetworkRedeemFixture struct {
	store   CapacityNativeWorkerNetworkStore
	policy  model.Manifest
	permit  uuid.UUID
	caller  CapacityNativeWorkerNetworkCaller
	runtime *nativeMemberNetworkRedeemRuntime
	script  *nativeMemberNetworkReadScript
}

func newNativeMemberNetworkRedeemFixture(t *testing.T, members, emptyHistory bool) nativeMemberNetworkRedeemFixture {
	t.Helper()
	f := newMemberConfigFixture(t)
	if !members {
		f.base.p.NativeWorkerLifecycleBinding.Members = nil
		f.base.repinPolicy(t)
	}
	if err := capacity.ValidatePolicy(f.base.p); err != nil {
		t.Fatal("schema-only policy prerequisite", err)
	}
	p, policy := f.base.p, f.base.policy
	life, pool := p.NativeWorkerLifecycleBinding, p.NativeWorkerPoolBinding
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := model.CapacityNativeWorkerAttempt{
		ID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Namespace: policy.Metadata.Namespace,
		Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 1, FencingToken: 1,
		PoolUID: pool.PoolUID, PoolEpoch: pool.ExpectedPoolEpoch, Registry: pool.RegistryRef,
		Profile: p.Profiles[0].Name, Provider: p.Profiles[0].Provider, Region: p.Profiles[0].Region,
		ProviderIDPrefix: pool.Profiles[0].ProviderIDPrefix, SourceCommit: life.SourceCommit, Execution: life.Profiles[0],
		NetworkBindingSHA256: p.MarketBinding.Profiles[0].NetworkBindingSHA, PhysicalSpecSHA256: p.MarketBinding.Profiles[0].PhysicalSpecSHA256,
		LaunchSHA256: strings.Repeat("8", 64), BirthSHA256: strings.Repeat("9", 64), OverlayIPv4: "10.90.0.20",
		State: "aborting", Revision: 3, NodeUID: uuid.NewString(), CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
	a.Physical = &model.CapacityNativeWorkerPhysical{
		ResourceID: "i-0123456789abcdef0", ProviderID: "aws:///us-east-1a/i-0123456789abcdef0", AccountID: "123456789012",
		InstanceType: "m6a.large", NetworkID: "subnet-0123456789abcdef0", CreatedAt: a.CreatedAt.Add(time.Second),
		ImageID: "ami-0123456789abcdef0", Region: a.Region, Zone: "us-east-1a", NativeIPv4: "10.0.2.20", MACAddress: "02:00:00:00:00:20",
		PhysicalSpecSHA256: a.PhysicalSpecSHA256, PhysicalBindingSHA256: strings.Repeat("a", 64), LaunchSHA256: a.LaunchSHA256,
	}
	if !capacity.NativeWorkerPhysicalValid(a, *a.Physical) {
		t.Fatal("synthetic AWS identity lost its closed identity shape")
	}
	permit := uuid.New()
	b := *life.Network
	executor, workflow := uuid.NewString(), uuid.New()
	r := nativeWorkerNetworkRecord{Attempt: a, Binding: b, SourceCommit: life.SourceCommit, ExecutorID: executor, WorkflowID: workflow, RecoveryWorkflowID: workflow, Revision: 1}
	r.Context = model.CapacityNativeWorkerNetworkGrant{
		Schema: model.CapacityNativeWorkerNetworkPermitSchema, PermitID: permit.String(), AttemptID: a.ID.String(),
		BindingName: b.Writer.BindingName, Action: "remove", Capability: capacity.NativeWorkerNetworkRemove, State: "issued", ExpiresAt: now.Add(30 * time.Second),
		SystemSourceCommit: b.Writer.SystemSourceCommit, WriterScopeSHA256: b.Writer.ScopeSHA256, Owner: p.Owner,
		PolicyID: policy.ID.String(), PoolUID: a.PoolUID, RegistryUID: a.Registry.UID, PoolEpoch: a.PoolEpoch,
		IntentGeneration: a.Generation, FencingToken: a.FencingToken, LaunchSHA256: a.LaunchSHA256, CreationProofSHA256: a.BirthSHA256,
		NetworkTemplateSHA256: b.TemplateSHA256, FloorNodeUID: b.Floor.NodeUID, ExpectedPreimageSHA256: strings.Repeat("b", 64),
		Peer: model.CapacityNativeWorkerNetworkPeer{WorkerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)), WorkerIPv4: a.OverlayIPv4, TransportEndpointIPv4: "8.8.8.8"}, MTU: capacity.NativeWorkerNetworkMTU,
	}
	caller := CapacityNativeWorkerNetworkCaller{PrincipalID: b.Writer.PrincipalID, InstanceID: b.Writer.AdapterID, SystemSourceCommit: b.Writer.SystemSourceCommit, BindingName: b.Writer.BindingName, Capability: capacity.NativeWorkerNetworkRemove}
	if !nativeNetworkCaller(r, caller) || r.Attempt.PolicyChecksum != policy.Checksum || r.SourceCommit != life.SourceCommit || !nativeNetworkBindingEqual(r.Binding, *life.Network) {
		t.Fatal("private row/caller prerequisite differs from policy")
	}
	marshal := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal("synthetic private row serialization", err)
		}
		return raw
	}
	script := &nativeMemberNetworkReadScript{steps: []nativeMemberNetworkQuery{{
		query: `SELECT record FROM public.capacity_native_worker_network_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3`,
		args:  []driver.Value{permit.String(), policy.ID.String(), policy.Metadata.Namespace}, value: marshal(r),
	}}}
	if emptyHistory {
		script.steps = append(script.steps,
			nativeMemberNetworkQuery{query: `SELECT attempt FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, args: []driver.Value{a.ID.String(), policy.ID.String(), policy.Metadata.Namespace}, value: marshal(a)},
			nativeMemberNetworkQuery{query: `SELECT CASE WHEN octet_length(p.record::text)<=8388608 THEN p.record END FROM public.capacity_native_worker_member_permits p JOIN public.capacity_native_worker_member_plans plan ON plan.id=p.plan_id WHERE p.attempt_id=$1 AND plan.kind='retirement' AND plan.mode='never_admitted' AND plan.state='active' AND p.action='retire_registry' AND p.state='observed' ORDER BY p.created_at DESC,p.id DESC LIMIT 1`, args: []driver.Value{a.ID.String()}, noRows: true},
		)
	}
	db := sql.OpenDB(nativeMemberNetworkConnector{script})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error("close scripted database", err)
		}
	})
	runtime := &nativeMemberNetworkRedeemRuntime{source: life.SourceCommit}
	workers := CapacityNativeWorkerStore{Capacity: CapacityStore{DB: db, ExecutorID: executor, WorkflowID: workflow, ExecutionEnabled: true}, Runtime: runtime, Enabled: true}
	return nativeMemberNetworkRedeemFixture{store: CapacityNativeWorkerNetworkStore{Workers: workers, Runtime: runtime, Enabled: true, RecoveryWorkflowID: workflow}, policy: policy, permit: permit, caller: caller, runtime: runtime, script: script}
}

type nativeMemberNetworkRedeemRuntime struct {
	source                                                           string
	phaseReads, poolReads, networkPrepares, networkReads, otherCalls int
}

func (s *nativeMemberNetworkRedeemRuntime) SourceCommit() string { return s.source }
func (s *nativeMemberNetworkRedeemRuntime) ObservePhaseAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	s.phaseReads++
	return nil, errNativeMemberNetworkAuthenticationReached
}
func (s *nativeMemberNetworkRedeemRuntime) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	s.poolReads++
	return nil, errNativeMemberNetworkUnexpectedOperation
}
func (s *nativeMemberNetworkRedeemRuntime) Prepare(model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	s.otherCalls++
	return model.CapacityNativeWorkerLaunch{}, errNativeMemberNetworkUnexpectedOperation
}
func (s *nativeMemberNetworkRedeemRuntime) CaptureOriginalReturn(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	s.otherCalls++
	return model.CapacityNativeWorkerOriginalReturn{}, errNativeMemberNetworkUnexpectedOperation
}
func (s *nativeMemberNetworkRedeemRuntime) Qualify(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	s.otherCalls++
	return model.CapacityNativeWorkerObservation{}, errNativeMemberNetworkUnexpectedOperation
}
func (s *nativeMemberNetworkRedeemRuntime) PrepareNetwork(context.Context, model.Manifest, model.CapacityNativeWorkerAttempt, string) (capacity.NativeWorkerNetworkPreparation, error) {
	s.networkPrepares++
	return capacity.NativeWorkerNetworkPreparation{}, errNativeMemberNetworkUnexpectedOperation
}
func (s *nativeMemberNetworkRedeemRuntime) ObserveNetwork(context.Context, model.Manifest, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerNetworkGrant) (model.CapacityNativeWorkerNetworkObservation, error) {
	s.networkReads++
	return model.CapacityNativeWorkerNetworkObservation{}, errNativeMemberNetworkUnexpectedOperation
}

type nativeMemberNetworkQuery struct {
	query  string
	args   []driver.Value
	value  []byte
	noRows bool
}
type nativeMemberNetworkReadScript struct {
	mu                               sync.Mutex
	steps                            []nativeMemberNetworkQuery
	queries, begins, execs, prepares int
	faults                           []string
}

func (s *nativeMemberNetworkReadScript) requireCompleteReadOnly(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queries != len(s.steps) || s.begins != 0 || s.execs != 0 || s.prepares != 0 || len(s.faults) != 0 {
		t.Fatalf("script boundary: queries=%d/%d begin=%d exec=%d prepare=%d faults=%v", s.queries, len(s.steps), s.begins, s.execs, s.prepares, s.faults)
	}
}

type nativeMemberNetworkConnector struct {
	script *nativeMemberNetworkReadScript
}
type nativeMemberNetworkDriver struct{}
type nativeMemberNetworkConn struct {
	script *nativeMemberNetworkReadScript
}

func (c nativeMemberNetworkConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &nativeMemberNetworkConn{c.script}, nil
}
func (nativeMemberNetworkConnector) Driver() driver.Driver { return nativeMemberNetworkDriver{} }
func (nativeMemberNetworkDriver) Open(string) (driver.Conn, error) {
	return nil, errNativeMemberNetworkUnexpectedOperation
}
func (c *nativeMemberNetworkConn) Close() error { return nil }
func (c *nativeMemberNetworkConn) Prepare(string) (driver.Stmt, error) {
	c.script.mu.Lock()
	c.script.prepares++
	c.script.mu.Unlock()
	return nil, errNativeMemberNetworkUnexpectedOperation
}
func (c *nativeMemberNetworkConn) Begin() (driver.Tx, error) {
	c.script.mu.Lock()
	c.script.begins++
	c.script.mu.Unlock()
	return nil, errNativeMemberNetworkUnexpectedOperation
}
func (c *nativeMemberNetworkConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *nativeMemberNetworkConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.script.mu.Lock()
	c.script.execs++
	c.script.mu.Unlock()
	return nil, errNativeMemberNetworkUnexpectedOperation
}
func (c *nativeMemberNetworkConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := c.script
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.queries
	s.queries++
	if index >= len(s.steps) {
		s.faults = append(s.faults, "unexpected query")
		return nil, errNativeMemberNetworkUnexpectedOperation
	}
	want := s.steps[index]
	if query != want.query || len(args) != len(want.args) {
		s.faults = append(s.faults, fmt.Sprintf("query %d shape", index))
		return nil, errNativeMemberNetworkUnexpectedOperation
	}
	for i, arg := range args {
		if arg.Ordinal != i+1 || arg.Name != "" || arg.Value != want.args[i] {
			s.faults = append(s.faults, fmt.Sprintf("query %d selector %d", index, i))
			return nil, errNativeMemberNetworkUnexpectedOperation
		}
	}
	return &nativeMemberNetworkRows{value: bytes.Clone(want.value), done: want.noRows}, nil
}

type nativeMemberNetworkRows struct {
	value []byte
	done  bool
}

func (*nativeMemberNetworkRows) Columns() []string { return []string{"private_record"} }
func (*nativeMemberNetworkRows) Close() error      { return nil }
func (r *nativeMemberNetworkRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = bytes.Clone(r.value)
	return nil
}
