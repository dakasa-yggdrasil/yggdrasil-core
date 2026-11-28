package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only Source-owned composition installs the independently authenticated host
// and provider readers. No machine request can construct this runtime.
type NativeWorkerNetworkRuntime interface {
	SourceCommit() string
	PrepareNetwork(context.Context, model.Manifest, model.CapacityNativeWorkerAttempt, string) (capacity.NativeWorkerNetworkPreparation, error)
	ObserveNetwork(context.Context, model.Manifest, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerNetworkGrant) (model.CapacityNativeWorkerNetworkObservation, error)
}

type CapacityNativeWorkerNetworkStore struct {
	Workers            CapacityNativeWorkerStore
	Runtime            NativeWorkerNetworkRuntime
	AbortRuntime       NativeWorkerAbortRuntime
	RecoveryWorkflowID uuid.UUID
	Enabled            bool
}

type nativeWorkerNetworkRecord struct {
	Context              model.CapacityNativeWorkerNetworkGrant           `json:"context"`
	Attempt              model.CapacityNativeWorkerAttempt                `json:"attempt"`
	Binding              model.CapacityNativeWorkerNetworkBinding         `json:"binding"`
	SourceCommit         string                                           `json:"source_commit"`
	ExecutorID           string                                           `json:"executor_id"`
	WorkflowID           uuid.UUID                                        `json:"workflow_id"`
	RecoveryWorkflowID   uuid.UUID                                        `json:"recovery_workflow_id"`
	Revision             int64                                            `json:"revision"`
	OriginalCallerClosed bool                                             `json:"original_caller_closed"`
	Original             *model.CapacityNativeWorkerNetworkOriginalReturn `json:"original,omitempty"`
	Observation          *model.CapacityNativeWorkerNetworkObservation    `json:"observation,omitempty"`
}

type CapacityNativeWorkerNetworkCaller struct {
	PrincipalID, InstanceID, SystemSourceCommit, BindingName, Capability string
}

func nativeNetworkContext(r nativeWorkerNetworkRecord) model.CapacityNativeWorkerNetworkGrant {
	g := r.Context
	g.MutationPermitted, g.Redeemable = false, false
	return g
}

func nativeNetworkCaller(r nativeWorkerNetworkRecord, c CapacityNativeWorkerNetworkCaller) bool {
	w := r.Binding.Writer
	return c.PrincipalID == w.PrincipalID && c.InstanceID == w.AdapterID && c.SystemSourceCommit == w.SystemSourceCommit && c.BindingName == w.BindingName && c.Capability == r.Context.Capability
}

func (s CapacityNativeWorkerNetworkStore) load(ctx context.Context, policy model.Manifest, id uuid.UUID) (nativeWorkerNetworkRecord, error) {
	var r nativeWorkerNetworkRecord
	if s.Workers.Capacity.DB == nil {
		return r, ErrCapacityDisabled
	}
	var raw []byte
	e := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e != nil || json.Unmarshal(raw, &r) != nil || r.Context.PermitID != id.String() {
		return r, ErrCapacityMutationAuthorization
	}
	return r, nil
}

// The Attempt row is always locked before the network permit row. Cleanup uses
// that same order, so a stale preflight cannot expose a send after abort wins.
func nativeNetworkLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, r nativeWorkerNetworkRecord) (model.CapacityNativeWorkerAttempt, nativeWorkerNetworkRecord, error) {
	a, _, e := nativeAttemptLoadTx(ctx, tx, policy, r.Attempt.ID)
	if e != nil {
		return a, r, e
	}
	var raw []byte
	e = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE id=$1 AND attempt_id=$2 AND policy_id=$3 AND namespace=$4 FOR UPDATE`, r.Context.PermitID, a.ID, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e != nil || json.Unmarshal(raw, &r) != nil {
		return a, r, ErrCapacityConflict
	}
	return a, r, nil
}

// Migration117 atomically appends the exact private event for every row write.
// There is no separate event write which could omit an internal SQL fence.
func nativeNetworkWriteTx(ctx context.Context, tx *sql.Tx, r nativeWorkerNetworkRecord, insert bool) error {
	if r.Context.MutationPermitted || r.Context.Redeemable {
		return ErrCapacityConflict
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if insert {
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_network_permits(id,attempt_id,policy_id,namespace,action,state,revision,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.Context.PermitID, r.Attempt.ID, r.Attempt.PolicyID, r.Attempt.Namespace, r.Context.Action, r.Context.State, r.Revision, raw, r.Context.ExpiresAt)
		return e
	}
	result, e := tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_network_permits SET state=$2,revision=$3,record=$4 WHERE id=$1 AND revision=$5`, r.Context.PermitID, r.Context.State, r.Revision, raw, r.Revision-1)
	if e != nil {
		return e
	}
	count, e := result.RowsAffected()
	if e != nil || count != 1 {
		return ErrCapacityConflict
	}
	return nil
}

func nativeNetworkBindingEqual(a, b model.CapacityNativeWorkerNetworkBinding) bool { return a == b }

// A failed capture is not automatically an active writer. The exact private
// Source batch can independently prove that every started process returned.
// This does not relabel a partial/failed original as successful or no-effect.
func nativeNetworkOriginalCallerClosed(g model.CapacityNativeWorkerNetworkGrant, v model.CapacityNativeWorkerNetworkOriginalReturn, now time.Time) bool {
	var original struct {
		Schema     string    `json:"schema"`
		PermitID   string    `json:"permit_id"`
		AttemptID  string    `json:"attempt_id"`
		Action     string    `json:"action"`
		StartedAt  time.Time `json:"started_at"`
		ReturnedAt time.Time `json:"returned_at"`
		Steps      []struct {
			Step            string    `json:"step"`
			StartedAt       time.Time `json:"started_at"`
			ReturnedAt      time.Time `json:"returned_at"`
			ProcessStarted  *bool     `json:"process_started"`
			WaitReturned    *bool     `json:"wait_returned"`
			ExitCode        int       `json:"exit_code"`
			CaptureComplete bool      `json:"capture_complete"`
			Stdout          []byte    `json:"stdout"`
			Stderr          []byte    `json:"stderr"`
		} `json:"steps"`
		ExecutionComplete bool `json:"execution_complete"`
	}
	if capacity.DecodeNativeCapacity(json.RawMessage(v.OriginalReturn), &original) != nil || original.Schema != "native_worker_network_original_batch_v1" || original.PermitID != g.PermitID || original.AttemptID != g.AttemptID || original.Action != g.Action || original.StartedAt.IsZero() || original.ReturnedAt.Before(original.StartedAt) || original.ReturnedAt.After(now) || original.Steps == nil || len(original.Steps) > 16 {
		return false
	}
	seenSteps := make(map[string]bool, len(original.Steps))
	for _, step := range original.Steps {
		if step.Step == "" || len(step.Step) > 128 || seenSteps[step.Step] || step.ProcessStarted == nil || step.WaitReturned == nil || len(step.Stdout) > 32<<10 || len(step.Stderr) > 32<<10 {
			return false
		}
		seenSteps[step.Step] = true
		if !*step.ProcessStarted && *step.WaitReturned || *step.ProcessStarted && (!*step.WaitReturned || step.StartedAt.Before(original.StartedAt) || step.ReturnedAt.Before(step.StartedAt) || step.ReturnedAt.After(original.ReturnedAt)) {
			return false
		}
	}
	return true
}

func (s CapacityNativeWorkerNetworkStore) current(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, r nativeWorkerNetworkRecord, now time.Time) error {
	life := p.NativeWorkerLifecycleBinding
	if !s.Enabled || !s.Workers.Enabled || !s.Workers.Capacity.ExecutionEnabled || s.Runtime == nil || life == nil || life.Network == nil || s.Runtime.SourceCommit() != life.SourceCommit || r.SourceCommit != life.SourceCommit || !nativeNetworkBindingEqual(*life.Network, r.Binding) || r.ExecutorID != s.Workers.Capacity.ExecutorID || r.WorkflowID != s.Workers.Capacity.WorkflowID || r.Attempt.PolicyChecksum != policy.Checksum || a.PolicyChecksum != policy.Checksum || a.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || a.BirthSHA256 != r.Attempt.BirthSHA256 || a.LaunchSHA256 != r.Attempt.LaunchSHA256 || a.Physical == nil {
		return ErrCapacityDisabled
	}
	if r.Context.Action == "remove" && a.State == "aborting" {
		if r.RecoveryWorkflowID != s.RecoveryWorkflowID {
			return ErrCapacityMutationAuthorization
		}
		abort := CapacityNativeWorkerAbortStore{Workers: s.Workers, Runtime: s.AbortRuntime, RecoveryWorkflowID: s.RecoveryWorkflowID, Enabled: s.Enabled}
		return abort.current(ctx, tx, policy, p, a, now)
	}
	if r.Context.Action == "install" && a.State != "acknowledged" && a.State != "registered" || r.Context.Action == "remove" && a.State != "draining" {
		return ErrCapacityConflict
	}
	_, e := s.Workers.current(ctx, tx, policy, p, model.CapacityNativeWorkerAuthority{Generation: r.Attempt.Generation, FencingToken: r.Attempt.FencingToken}, now)
	return e
}

func (s CapacityNativeWorkerNetworkStore) prepare(ctx context.Context, policy model.Manifest, id uuid.UUID, action string) (model.CapacityNativeWorkerAttempt, capacity.NativeWorkerNetworkPreparation, json.RawMessage, error) {
	a, e := s.Workers.Read(ctx, policy, id)
	if e != nil {
		return a, capacity.NativeWorkerNetworkPreparation{}, nil, e
	}
	p, e := parseCapacityPolicy(policy)
	if e != nil || s.Runtime == nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil || s.Runtime.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit || action != "install" && action != "remove" {
		return a, capacity.NativeWorkerNetworkPreparation{}, nil, ErrCapacityDisabled
	}
	var launch json.RawMessage
	e = s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, policy.ID, policy.Metadata.Namespace).Scan(&launch)
	if e != nil {
		return a, capacity.NativeWorkerNetworkPreparation{}, nil, e
	}
	prepared, e := s.Runtime.PrepareNetwork(ctx, policy, a, action)
	if e == nil && action == "remove" {
		// The original permission remains the authority for this endpoint even
		// after a real provider not_found. No new endpoint may be substituted.
		var raw []byte
		e = s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE attempt_id=$1 AND policy_id=$2 AND namespace=$3 AND action='install' AND state IN ('redeemed','received','unknown','observed') ORDER BY created_at DESC,id DESC LIMIT 1`, a.ID, policy.ID, policy.Metadata.Namespace).Scan(&raw)
		var original nativeWorkerNetworkRecord
		if e == nil && (json.Unmarshal(raw, &original) != nil || original.Attempt.ID != a.ID || original.Attempt.BirthSHA256 != a.BirthSHA256 || original.Attempt.LaunchSHA256 != a.LaunchSHA256 || original.Context.AttemptID != a.ID.String() || original.Context.CreationProofSHA256 != a.BirthSHA256 || original.Context.LaunchSHA256 != a.LaunchSHA256 || original.Context.Peer.WorkerIPv4 != a.OverlayIPv4 || !nativeNetworkBindingEqual(original.Binding, *p.NativeWorkerLifecycleBinding.Network)) {
			e = ErrCapacityConflict
		}
		if e == nil {
			prepared.TransportEndpointIPv4 = original.Context.Peer.TransportEndpointIPv4
		}
	}
	if e == nil && !capacity.NativeWorkerNetworkPreparationValidForAction(p, a, launch, prepared, action, time.Now().UTC()) {
		e = ErrCapacityConflict
	}
	return a, prepared, launch, e
}

func (s CapacityNativeWorkerNetworkStore) Begin(ctx context.Context, policy model.Manifest, id uuid.UUID, action string) (model.CapacityNativeWorkerNetworkGrant, error) {
	w, e := s.Workers.authenticate(ctx, policy)
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	s.Workers = w
	a, prepared, launch, e := s.prepare(ctx, policy, id, action)
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	var original struct {
		Network struct {
			WorkerPublicKey string `json:"worker_public_key"`
		} `json:"network"`
	}
	if json.Unmarshal(launch, &original) != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityConflict
	}
	preimage, e := prepared.Floor.PreimageSHA256()
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityConflict
	}
	var out model.CapacityNativeWorkerNetworkGrant
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, _, err := nativeAttemptLoadTx(ctx, tx, policy, id)
		if err != nil {
			return err
		}
		if current.Revision != a.Revision || !capacity.NativeWorkerNetworkPreparationValidForAction(p, current, launch, prepared, action, now) {
			return ErrCapacityConflict
		}
		b := *p.NativeWorkerLifecycleBinding.Network
		capability := capacity.NativeWorkerNetworkInstall
		if action == "remove" {
			capability = capacity.NativeWorkerNetworkRemove
		}
		r := nativeWorkerNetworkRecord{Attempt: current, Binding: b, SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, ExecutorID: s.Workers.Capacity.ExecutorID, WorkflowID: s.Workers.Capacity.WorkflowID, RecoveryWorkflowID: s.RecoveryWorkflowID, Revision: 1}
		r.Context = model.CapacityNativeWorkerNetworkGrant{Schema: model.CapacityNativeWorkerNetworkPermitSchema, PermitID: uuid.NewString(), AttemptID: id.String(), BindingName: b.Writer.BindingName, Action: action, Capability: capability, State: "issued", ExpiresAt: now.Add(time.Duration(b.MaxPermitSeconds) * time.Second), SystemSourceCommit: b.Writer.SystemSourceCommit, WriterScopeSHA256: b.Writer.ScopeSHA256, Owner: p.Owner, PolicyID: policy.ID.String(), PoolUID: a.PoolUID, RegistryUID: a.Registry.UID, PoolEpoch: a.PoolEpoch, IntentGeneration: a.Generation, FencingToken: a.FencingToken, LaunchSHA256: a.LaunchSHA256, CreationProofSHA256: a.BirthSHA256, NetworkTemplateSHA256: b.TemplateSHA256, FloorNodeUID: b.Floor.NodeUID, ExpectedPreimageSHA256: preimage, Peer: model.CapacityNativeWorkerNetworkPeer{WorkerPublicKey: original.Network.WorkerPublicKey, WorkerIPv4: a.OverlayIPv4, TransportEndpointIPv4: prepared.TransportEndpointIPv4}, MTU: capacity.NativeWorkerNetworkMTU}
		if err = s.current(ctx, tx, policy, p, current, r, now); err != nil {
			return err
		}
		var oldRaw []byte
		err = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE attempt_id=$1 AND action=$2 AND state<>'no_effect' FOR UPDATE`, id, action).Scan(&oldRaw)
		if err == nil {
			var old nativeWorkerNetworkRecord
			if json.Unmarshal(oldRaw, &old) != nil {
				return ErrCapacityConflict
			}
			out = nativeNetworkContext(old)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err = nativeNetworkWriteTx(ctx, tx, r, true); err != nil {
			return err
		}
		out = nativeNetworkContext(r)
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	return out, nil
}

func (s CapacityNativeWorkerNetworkStore) Read(ctx context.Context, policy model.Manifest, id uuid.UUID, caller CapacityNativeWorkerNetworkCaller) (model.CapacityNativeWorkerNetworkGrant, error) {
	r, e := s.load(ctx, policy, id)
	if e != nil || !nativeNetworkCaller(r, caller) {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityMutationAuthorization
	}
	out := nativeNetworkContext(r)
	if r.Context.State != "issued" {
		return out, nil
	}
	w, e := s.Workers.authenticate(ctx, policy)
	if e != nil {
		return out, nil
	}
	s.Workers = w
	a, prepared, launch, e := s.prepare(ctx, policy, r.Attempt.ID, r.Context.Action)
	if e != nil {
		return out, nil
	}
	preimage, e := prepared.Floor.PreimageSHA256()
	if e != nil || preimage != r.Context.ExpectedPreimageSHA256 || prepared.TransportEndpointIPv4 != r.Context.Peer.TransportEndpointIPv4 {
		return out, nil
	}
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, actual, err := nativeNetworkLoadTx(ctx, tx, policy, r)
		if err != nil {
			return err
		}
		out = nativeNetworkContext(actual)
		if err = s.current(ctx, tx, policy, p, current, actual, now); err != nil {
			return err
		}
		out.Redeemable = nativeNetworkCaller(actual, caller) && actual.Context.State == "issued" && actual.Context.ExpiresAt.After(now) && current.Revision == a.Revision && capacity.NativeWorkerNetworkPreparationValidForAction(p, current, launch, prepared, actual.Context.Action, now)
		return nil
	})
	if e != nil {
		out.Redeemable = false
	}
	return out, nil
}

func (s CapacityNativeWorkerNetworkStore) Redeem(ctx context.Context, policy model.Manifest, id uuid.UUID, caller CapacityNativeWorkerNetworkCaller) (model.CapacityNativeWorkerNetworkGrant, error) {
	r, e := s.load(ctx, policy, id)
	if e != nil || !nativeNetworkCaller(r, caller) {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityMutationAuthorization
	}
	var members *nativeMemberNetworkPreflight
	p, pe := parseCapacityPolicy(policy)
	if pe != nil || p.NativeWorkerLifecycleBinding == nil {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityDisabled
	}
	if r.Context.Action == "remove" && p.NativeWorkerLifecycleBinding.Members != nil {
		if s.Workers.Members == nil {
			return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityDisabled
		}
		currentMember, readErr := s.Workers.Read(ctx, policy, r.Attempt.ID)
		if readErr != nil {
			return model.CapacityNativeWorkerNetworkGrant{}, readErr
		}
		members, e = s.Workers.Members.networkPreflight(ctx, currentMember)
		if e != nil {
			return model.CapacityNativeWorkerNetworkGrant{}, e
		}
	}
	w, e := s.Workers.authenticate(ctx, policy)
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	s.Workers = w
	a, prepared, launch, e := s.prepare(ctx, policy, r.Attempt.ID, r.Context.Action)
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	preimage, e := prepared.Floor.PreimageSHA256()
	if e != nil || preimage != r.Context.ExpectedPreimageSHA256 || prepared.TransportEndpointIPv4 != r.Context.Peer.TransportEndpointIPv4 {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityConflict
	}
	var out model.CapacityNativeWorkerNetworkGrant
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, actual, err := nativeNetworkLoadTx(ctx, tx, policy, r)
		if err != nil {
			return err
		}
		if !nativeNetworkCaller(actual, caller) || actual.Context.State != "issued" || actual.Original != nil || !actual.Context.ExpiresAt.After(now) || current.Revision != a.Revision || !capacity.NativeWorkerNetworkPreparationValidForAction(p, current, launch, prepared, actual.Context.Action, now) {
			return ErrCapacityConflict
		}
		if err = s.current(ctx, tx, policy, p, current, actual, now); err != nil {
			return err
		}
		if actual.Context.Action == "remove" && p.NativeWorkerLifecycleBinding.Members != nil {
			if s.Workers.Members == nil {
				return ErrCapacityDisabled
			}
			if err = s.Workers.Members.networkCurrentTx(ctx, tx, p, current, id, members, now); err != nil {
				return err
			}
			if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !actual.Context.ExpiresAt.After(now) {
				return ErrCapacityConflict
			}
		}
		actual.Context.State = "redeemed"
		actual.Revision++
		if err = nativeNetworkWriteTx(ctx, tx, actual, false); err != nil {
			return err
		}
		out = nativeNetworkContext(actual)
		out.MutationPermitted = true
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	return out, nil
}

// The original host-batch bytes stay private and immutable. Receiving performs
// no kernel write or semantic success assertion, including after process gates
// close. An unknown batch never becomes another install/remove permission.
func (s CapacityNativeWorkerNetworkStore) Receive(ctx context.Context, policy model.Manifest, caller CapacityNativeWorkerNetworkCaller, v model.CapacityNativeWorkerNetworkOriginalReturn) error {
	id, e := uuid.Parse(v.PermitID)
	if e != nil || id.String() != v.PermitID || v.Schema != "native_worker_network_receive_v1" || v.BindingName != caller.BindingName || len(v.OriginalReturn) > 1<<20 || len(v.ErrorClass) > 128 || strings.ContainsAny(v.ErrorClass, "\x00\r\n") {
		return ErrCapacityConflict
	}
	r, e := s.load(ctx, policy, id)
	if e != nil || !nativeNetworkCaller(r, caller) {
		return ErrCapacityMutationAuthorization
	}
	return s.Workers.tx(ctx, policy, func(tx *sql.Tx, _ model.CapacityPolicySpec, now time.Time) error {
		_, actual, err := nativeNetworkLoadTx(ctx, tx, policy, r)
		if err != nil {
			return err
		}
		if !nativeNetworkCaller(actual, caller) {
			return ErrCapacityMutationAuthorization
		}
		if actual.Original != nil {
			a, _ := json.Marshal(actual.Original)
			b, _ := json.Marshal(v)
			if string(a) != string(b) {
				return ErrCapacityConflict
			}
			return nil
		}
		if actual.Context.State != "redeemed" && actual.Context.State != "unknown" && actual.Context.State != "observed" {
			return ErrCapacityConflict
		}
		v.OriginalReturn = append([]byte{}, v.OriginalReturn...)
		actual.Original = &v
		actual.OriginalCallerClosed = nativeNetworkOriginalCallerClosed(actual.Context, v, now)
		if actual.Context.State != "observed" {
			actual.Context.State = "unknown"
			if v.CaptureComplete && v.ErrorClass == "" {
				actual.Context.State = "received"
			}
		}
		actual.Revision++
		return nativeNetworkWriteTx(ctx, tx, actual, false)
	})
}

// GET-only receiving uses independent actual kernel facts. The original private
// batch must prove every started process returned before any observation can
// settle an exposed writer; a momentary absent peer alone cannot do that.
func (s CapacityNativeWorkerNetworkStore) Reconcile(ctx context.Context, policy model.Manifest, id uuid.UUID, caller CapacityNativeWorkerNetworkCaller) (model.CapacityNativeWorkerNetworkGrant, error) {
	r, e := s.load(ctx, policy, id)
	if e != nil || !nativeNetworkCaller(r, caller) {
		return model.CapacityNativeWorkerNetworkGrant{}, ErrCapacityMutationAuthorization
	}
	out := nativeNetworkContext(r)
	p, e := parseCapacityPolicy(policy)
	if e != nil || s.Runtime == nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil || s.Runtime.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit || r.SourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit || !nativeNetworkBindingEqual(r.Binding, *p.NativeWorkerLifecycleBinding.Network) {
		return out, ErrCapacityDisabled
	}
	a, e := s.Workers.Read(ctx, policy, r.Attempt.ID)
	if e != nil {
		return out, e
	}
	var launch json.RawMessage
	e = s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, a.ID, policy.ID, policy.Metadata.Namespace).Scan(&launch)
	if e != nil {
		return out, e
	}
	o, e := s.Runtime.ObserveNetwork(ctx, policy, a, r.Context)
	if e != nil || !capacity.NativeWorkerNetworkObservationValid(p, a, launch, o, time.Now().UTC()) {
		return out, ErrCapacityConflict
	}
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, actual, err := nativeNetworkLoadTx(ctx, tx, policy, r)
		if err != nil {
			return err
		}
		if !nativeNetworkCaller(actual, caller) || current.Revision != a.Revision || current.BirthSHA256 != r.Attempt.BirthSHA256 || !capacity.NativeWorkerNetworkObservationValid(p, current, launch, o, now) {
			return ErrCapacityConflict
		}
		if actual.Context.State == "observed" || actual.Context.State == "no_effect" {
			out = nativeNetworkContext(actual)
			return nil
		}
		actual.Observation = &o
		if actual.Context.State == "issued" {
			if actual.Context.ExpiresAt.After(now) {
				out = nativeNetworkContext(actual)
				return nil
			}
			actual.Context.State = "no_effect"
		} else {
			actual.Context.State = "unknown"
			if actual.Original != nil && actual.OriginalCallerClosed && capacity.NativeWorkerNetworkDesired(actual.Binding, actual.Context, o) {
				actual.Context.State = "observed"
			}
		}
		actual.Revision++
		if err = nativeNetworkWriteTx(ctx, tx, actual, false); err != nil {
			return err
		}
		out = nativeNetworkContext(actual)
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerNetworkGrant{}, e
	}
	return out, nil
}
