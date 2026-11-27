package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only installed protected composition supplies this GET-only observation.
// No mutation actor or workflow may supply closure, ownership or Node facts.
type NativeWorkerAbortRuntime interface {
	SourceCommit() string
	ObserveAbort(context.Context, model.Manifest, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAbortObservation, error)
}

type CapacityNativeWorkerAbortStore struct {
	Workers            CapacityNativeWorkerStore
	Runtime            NativeWorkerAbortRuntime
	RecoveryWorkflowID uuid.UUID
	Enabled            bool
}

type nativeWorkerAbortRecord struct {
	Context      model.CapacityNativeWorkerAbortPermit       `json:"context"`
	Attempt      model.CapacityNativeWorkerAttempt           `json:"attempt"`
	Binding      model.CapacityNativeWorkerAbortBinding      `json:"binding"`
	SourceCommit string                                      `json:"source_commit"`
	ExecutorID   string                                      `json:"executor_id"`
	WorkflowID   uuid.UUID                                   `json:"workflow_id"`
	Revision     int64                                       `json:"revision"`
	TokenSHA256  string                                      `json:"token_sha256,omitempty"`
	Original     *model.CapacityNativeWorkerAbortReceive     `json:"original,omitempty"`
	Observation  *model.CapacityNativeWorkerAbortObservation `json:"observation,omitempty"`
}

func abortContext(r nativeWorkerAbortRecord) model.CapacityNativeWorkerAbortPermit {
	c := r.Context
	c.Redeemable, c.MutationPermitted, c.SettlementToken = false, false, ""
	return c
}
func abortCaller(r nativeWorkerAbortRecord, c model.CapacityNativeWorkerCommandCaller) bool {
	return c.BindingName == r.Attempt.Execution.BindingName && c.InstanceID == r.Attempt.Execution.Adapter.ManifestID &&
		c.SDKSourceCommit == r.Attempt.Execution.SDKSourceCommit && c.Capability == r.Attempt.Execution.DestroyCapability
}

func (s CapacityNativeWorkerAbortStore) boundRecord(r nativeWorkerAbortRecord, p model.CapacityPolicySpec) bool {
	b := p.NativeWorkerLifecycleBinding
	return b != nil && b.PreAdmissionAbort != nil && r.Binding == *b.PreAdmissionAbort &&
		r.SourceCommit == b.SourceCommit && r.ExecutorID == s.Workers.Capacity.ExecutorID && r.WorkflowID == s.RecoveryWorkflowID
}
func abortLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, id uuid.UUID) (nativeWorkerAbortRecord, error) {
	var r nativeWorkerAbortRecord
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_abort_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e == nil {
		e = json.Unmarshal(raw, &r)
	}
	return r, e
}
func abortWriteTx(ctx context.Context, tx *sql.Tx, r nativeWorkerAbortRecord, insert bool, now time.Time) error {
	if r.Context.SettlementToken != "" || r.Context.MutationPermitted || r.Context.Redeemable {
		return ErrCapacityConflict
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if insert {
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_abort_permits(id,attempt_id,policy_id,namespace,state,revision,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.Context.PermitID, r.Context.AttemptID, r.Attempt.PolicyID, r.Attempt.Namespace, r.Context.State, r.Revision, raw, r.Context.ExpiresAt)
	} else {
		var result sql.Result
		result, e = tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_abort_permits SET state=$2,revision=$3,record=$4 WHERE id=$1 AND revision=$5`, r.Context.PermitID, r.Context.State, r.Revision, raw, r.Revision-1)
		if e == nil {
			n, x := result.RowsAffected()
			if x != nil || n != 1 {
				return ErrCapacityConflict
			}
		}
	}
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_abort_events(permit_id,revision,record,recorded_at) VALUES($1,$2,$3,$4)`, r.Context.PermitID, r.Revision, raw, now)
	return e
}
func (s CapacityNativeWorkerAbortStore) observe(ctx context.Context, policy model.Manifest, id uuid.UUID) (model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerAbortObservation, error) {
	a, e := s.Workers.Read(ctx, policy, id)
	if e != nil {
		return a, model.CapacityNativeWorkerAbortObservation{}, e
	}
	p, e := parseCapacityPolicy(policy)
	if e != nil || s.Runtime == nil || p.NativeWorkerLifecycleBinding == nil || s.Runtime.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit {
		return a, model.CapacityNativeWorkerAbortObservation{}, ErrCapacityDisabled
	}
	o, e := s.Runtime.ObserveAbort(ctx, policy, a) // No WAN I/O under a database lock.
	if e == nil && !capacity.NativeWorkerAbortObservationValid(p, a, o, time.Now().UTC()) {
		e = ErrCapacityConflict
	}
	return a, o, e
}

// Shared policy mutation lock and Attempt FOR UPDATE arbitrate against all
// admission issue/redeem operations. A TTL never settles an exposed right.
func abortFenceAdmissionTx(ctx context.Context, tx *sql.Tx, a model.CapacityNativeWorkerAttempt, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 FOR UPDATE`, a.ID)
	if e != nil {
		return e
	}
	var issued []nativeWorkerPhaseRecord
	for rows.Next() {
		var raw []byte
		var r nativeWorkerPhaseRecord
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return e
		}
		if json.Unmarshal(raw, &r) != nil {
			rows.Close()
			return ErrCapacityConflict
		}
		switch r.Context.PhaseState {
		case "no_effect":
		case "issued":
			if r.SettlementTokenSHA256 != "" || r.Original != nil {
				rows.Close()
				return ErrCapacityConflict
			}
			issued = append(issued, r)
		case "observed":
			if r.Context.Action == "release_quarantine" {
				rows.Close()
				return ErrCapacityConflict
			}
		default:
			rows.Close()
			return ErrCapacityConflict
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, r := range issued {
		r.Context.PhaseState = "no_effect"
		r.NoEffectReason = "pre_admission_abort_unredeemed"
		r.Revision++
		if e = nativePhaseWriteTx(ctx, tx, r, now); e != nil {
			return e
		}
	}
	return nil
}

func (s CapacityNativeWorkerAbortStore) current(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, now time.Time) error {
	b := p.NativeWorkerLifecycleBinding
	if !s.Enabled || !s.Workers.Enabled || !s.Workers.Capacity.ExecutionEnabled || b == nil || b.PreAdmissionAbort == nil || s.Runtime == nil || s.Runtime.SourceCommit() != b.SourceCommit ||
		s.RecoveryWorkflowID == uuid.Nil || !validCapacityExecutor(s.Workers.Capacity.ExecutorID) || a.PolicyID != policy.ID || a.PolicyChecksum != policy.Checksum ||
		a.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || a.Physical == nil {
		return ErrCapacityDisabled
	}
	var checksum string
	var active bool
	e := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 FOR SHARE`, policy.ID, policy.Metadata.Namespace).Scan(&checksum, &active)
	if e != nil || !active || checksum != policy.Checksum {
		return ErrCapacityConflict
	}
	w := b.PreAdmissionAbort.Workflow
	e = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.RecoveryWorkflowID, w.Namespace, w.Name).Scan(&active)
	if e != nil || !active {
		return ErrCapacityMutationAuthorization
	}
	matched := false
	for _, profile := range b.Profiles {
		matched = matched || capacity.NativeWorkerSameExecution(profile, a.Execution)
	}
	if !matched {
		return ErrCapacityConflict
	}
	mb := model.CapacityMutationBinding{IntegrationInstanceID: a.Execution.Adapter.ManifestID, IntegrationChecksum: a.Execution.Adapter.Checksum, IntegrationTypeID: a.Execution.Adapter.IntegrationTypeID, IntegrationTypeChecksum: a.Execution.Adapter.TypeChecksum}
	if e = checkMutationIntegration(ctx, tx, mb); e != nil {
		return e
	}
	var version int
	e = tx.QueryRowContext(ctx, `SELECT version FROM public.manifests WHERE id=$1`, a.Execution.Adapter.ManifestID).Scan(&version)
	if e != nil || version != a.Execution.Adapter.Version {
		return ErrCapacityConflict
	}
	return nil
}

// Begin does not mutate a provider. It atomically fences admission and retains
// every charge/IP reservation in the explicit aborting state. Unknown Node facts
// can be retained, but never become a destructive mutation permission.
func (s CapacityNativeWorkerAbortStore) Begin(ctx context.Context, policy model.Manifest, id uuid.UUID) (model.CapacityNativeWorkerAbortPermit, error) {
	a, o, e := s.observe(ctx, policy, id)
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	var out model.CapacityNativeWorkerAbortPermit
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, _, e := nativeAttemptLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if current.Revision != a.Revision || !capacity.NativeWorkerAbortObservationValid(p, current, o, now) || o.NodeState == "admitted" || o.ApplicationPods != 0 {
			return ErrCapacityConflict
		}
		if e = s.current(ctx, tx, policy, p, current, now); e != nil {
			return e
		}
		if current.State != "acknowledged" && current.State != "registered" && current.State != "aborting" {
			return ErrCapacityConflict
		}
		if e = abortFenceAdmissionTx(ctx, tx, current, now); e != nil {
			return e
		}
		var oldRaw []byte
		e = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_abort_permits WHERE attempt_id=$1 AND state<>'no_effect' FOR UPDATE`, id).Scan(&oldRaw)
		if e == nil {
			var old nativeWorkerAbortRecord
			if json.Unmarshal(oldRaw, &old) != nil {
				return ErrCapacityConflict
			}
			if old.Context.State == "issued" && old.TokenSHA256 == "" && old.Original == nil && !old.Context.ExpiresAt.After(now) {
				old.Context.State = "no_effect"
				old.Revision++
				if e = abortWriteTx(ctx, tx, old, false, now); e != nil {
					return e
				}
			} else {
				out = abortContext(old)
				return nil
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if current.State != "aborting" {
			current.State = "aborting"
			current.Revision++
			current.UpdatedAt = now
			if e = nativeAttemptWriteTx(ctx, tx, current, nil, false, nil); e != nil {
				return e
			}
		}
		r := nativeWorkerAbortRecord{Attempt: current, Binding: *p.NativeWorkerLifecycleBinding.PreAdmissionAbort, SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, ExecutorID: s.Workers.Capacity.ExecutorID, WorkflowID: s.RecoveryWorkflowID, Revision: 1, Observation: &o}
		r.Context = model.CapacityNativeWorkerAbortPermit{Schema: model.CapacityNativeWorkerAbortSchema, PermitID: uuid.New(), AttemptID: id, State: "issued", BindingName: current.Execution.BindingName, SDKSourceCommit: current.Execution.SDKSourceCommit, ExecutionScopeSHA256: current.Execution.ScopeSHA256, Capability: current.Execution.DestroyCapability, PoolUID: current.PoolUID, PoolEpoch: current.PoolEpoch, Registry: current.Registry, Physical: *current.Physical, ExpiresAt: now.Add(time.Duration(r.Binding.MaxPermitSeconds) * time.Second)}
		if e = abortWriteTx(ctx, tx, r, true, now); e != nil {
			return e
		}
		out = abortContext(r)
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	return out, nil
}

func (s CapacityNativeWorkerAbortStore) load(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (nativeWorkerAbortRecord, error) {
	var r nativeWorkerAbortRecord
	if s.Workers.Capacity.DB == nil {
		return r, ErrCapacityDisabled
	}
	var raw []byte
	e := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_abort_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e != nil || json.Unmarshal(raw, &r) != nil || !abortCaller(r, caller) {
		return r, ErrCapacityMutationAuthorization
	}
	return r, nil
}
func (s CapacityNativeWorkerAbortStore) Read(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (model.CapacityNativeWorkerAbortPermit, error) {
	r, e := s.load(ctx, policy, id, caller)
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	out := abortContext(r)
	a, o, e := s.observe(ctx, policy, r.Context.AttemptID)
	if e != nil {
		return out, nil
	}
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		if e = s.current(ctx, tx, policy, p, a, now); e != nil {
			return e
		}
		current, _, e := nativeAttemptLoadTx(ctx, tx, policy, a.ID)
		if e != nil {
			return e
		}
		actual, e := abortLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		out = abortContext(actual)
		out.Redeemable = s.boundRecord(actual, p) && current.State == "aborting" && current.Revision == a.Revision && actual.Context.State == "issued" && actual.Context.ExpiresAt.After(now) && capacity.NativeWorkerAbortObservationValid(p, current, o, now) && capacity.NativeWorkerAbortSendSafe(o)
		return nil
	})
	if e != nil {
		out.Redeemable = false
	}
	return out, nil
}
func (s CapacityNativeWorkerAbortStore) Redeem(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (model.CapacityNativeWorkerAbortPermit, error) {
	r, e := s.load(ctx, policy, id, caller)
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	a, o, e := s.observe(ctx, policy, r.Context.AttemptID)
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	var out model.CapacityNativeWorkerAbortPermit
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, _, e := nativeAttemptLoadTx(ctx, tx, policy, a.ID)
		if e != nil {
			return e
		}
		r, e = abortLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if !abortCaller(r, caller) || !s.boundRecord(r, p) || r.Context.State != "issued" || !r.Context.ExpiresAt.After(now) || current.State != "aborting" || current.Revision != a.Revision || !capacity.NativeWorkerAbortObservationValid(p, current, o, now) || !capacity.NativeWorkerAbortSendSafe(o) {
			return ErrCapacityConflict
		}
		if e = s.current(ctx, tx, policy, p, current, now); e != nil {
			return e
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			return e
		}
		token := base64.RawURLEncoding.EncodeToString(nonce)
		r.TokenSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
		r.Context.State = "redeemed"
		r.Revision++
		if e = abortWriteTx(ctx, tx, r, false, now); e != nil {
			return e
		}
		out = abortContext(r)
		out.MutationPermitted = true
		out.SettlementToken = token
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	return out, nil
}

// Receive is original private custody, never a provider success assertion.
// A late original cannot downgrade observed truth or re-open a used right.
func (s CapacityNativeWorkerAbortStore) Receive(ctx context.Context, policy model.Manifest, caller model.CapacityNativeWorkerCommandCaller, v model.CapacityNativeWorkerAbortReceive) error {
	if len(v.OriginalReturn) > 1<<20 || len(v.ErrorClass) > 128 || strings.ContainsAny(v.ErrorClass, "\r\n\x00") || v.SettlementToken == "" {
		return ErrCapacityConflict
	}
	return s.Workers.tx(ctx, policy, func(tx *sql.Tx, _ model.CapacityPolicySpec, now time.Time) error {
		r, e := abortLoadTx(ctx, tx, policy, v.PermitID)
		if e != nil {
			return e
		}
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(v.SettlementToken)))
		if !abortCaller(r, caller) || v.BindingName != r.Context.BindingName || subtle.ConstantTimeCompare([]byte(hash), []byte(r.TokenSHA256)) != 1 {
			return ErrCapacityMutationAuthorization
		}
		if r.Original != nil {
			if string(r.Original.OriginalReturn) != string(v.OriginalReturn) || r.Original.CaptureComplete != v.CaptureComplete || r.Original.ErrorClass != v.ErrorClass {
				return ErrCapacityConflict
			}
			return nil
		}
		if r.Context.State != "redeemed" && r.Context.State != "unknown" && r.Context.State != "observed" {
			return ErrCapacityConflict
		}
		prior := r.Context.State
		v.SettlementToken = ""
		v.OriginalReturn = append([]byte{}, v.OriginalReturn...)
		r.Original = &v
		if prior != "observed" {
			r.Context.State = "unknown"
			if v.CaptureComplete && v.ErrorClass == "" {
				r.Context.State = "received"
			}
		}
		r.Revision++
		return abortWriteTx(ctx, tx, r, false, now)
	})
}

// GET-only truth can settle after permit expiry. Each external cleanup writer
// remains a separate required capability; this store performs none of them.
func (s CapacityNativeWorkerAbortStore) Reconcile(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (model.CapacityNativeWorkerAbortPermit, error) {
	r, e := s.load(ctx, policy, id, caller)
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	a, o, e := s.observe(ctx, policy, r.Context.AttemptID)
	if e != nil {
		return abortContext(r), e
	}
	var out model.CapacityNativeWorkerAbortPermit
	e = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, _, e := nativeAttemptLoadTx(ctx, tx, policy, a.ID)
		if e != nil {
			return e
		}
		r, e = abortLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if !abortCaller(r, caller) || !capacity.NativeWorkerAbortObservationValid(p, current, o, now) {
			return ErrCapacityConflict
		}
		if r.Context.State == "observed" {
			out = abortContext(r)
			return nil
		}
		if current.State != "aborting" || r.Context.State == "no_effect" || current.Revision != a.Revision {
			return ErrCapacityConflict
		}
		r.Observation = &o
		if capacity.NativeWorkerAbortSettled(o) {
			current.State = "absent"
			current.Revision++
			current.UpdatedAt = now
			if e = nativeAttemptWriteTx(ctx, tx, current, nil, false, nil); e != nil {
				return e
			}
			r.Context.State = "observed"
		} else if r.Context.State != "issued" {
			r.Context.State = "unknown"
		}
		r.Revision++
		if e = abortWriteTx(ctx, tx, r, false, now); e != nil {
			return e
		}
		out = abortContext(r)
		return nil
	})
	if e != nil {
		return model.CapacityNativeWorkerAbortPermit{}, e
	}
	return out, nil
}
