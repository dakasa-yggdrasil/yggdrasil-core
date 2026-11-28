package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// NativeWorkerRuntime is installed only in protected server composition.
// Prepare MUST be pure: no WAN, credentials resolution or external writes under
// the transaction. Capture reads the one original send's private return; it
// cannot send or retry. Qualify performs independent GET-only SDK/runtime reads.
// None of these functions is constructed from a workflow/RPC observation DTO.
type NativeWorkerRuntime interface {
	SourceCommit() string
	ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error)
	Prepare(model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error)
	CaptureOriginalReturn(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error)
	Qualify(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error)
}

// Phase authority is a separate complete header/registry observation. It must
// never be converted into a fabricated zero-member useful pool snapshot.
type NativeWorkerPhaseAuthorityRuntime interface {
	ObservePhaseAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error)
}

// A protected capture must wait for its original sender/pipe closure. A pending
// return is not an empty completed response and must remain receivable later.
var ErrCapacityNativeReturnPending = errors.New("original Native return is still pending; GET-only receive")

type CapacityNativeWorkerStore struct {
	Capacity         CapacityStore
	Runtime          NativeWorkerRuntime
	Enabled          bool                                       // Separate process gate, default false.
	authority        *model.CapacityNativeWorkerPoolObservation // Private per-call observation.
	phaseAuthority   *model.CapacityNativeWorkerPhaseReadObservation
	commandExpiresAt time.Time // Private immutable original actor command deadline.
}

// Authenticate outside transaction locks. A fresh Lease read is necessary but
// not cross-resource atomicity: epoch rotation must separately fence Node RVs
// and all in-flight permits before handoff. Initial cycles have one stable owner.
func (s CapacityNativeWorkerStore) authenticate(ctx context.Context, policy model.Manifest) (CapacityNativeWorkerStore, error) {
	if s.Runtime == nil {
		return s, ErrCapacityDisabled
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.NativeWorkerLifecycleBinding == nil {
		return s, ErrCapacityDisabled
	}
	if p.NativeWorkerLifecycleBinding.PhaseObserver != nil {
		reader, ok := s.Runtime.(NativeWorkerPhaseAuthorityRuntime)
		if !ok {
			return s, ErrCapacityDisabled
		}
		observed, readErr := reader.ObservePhaseAuthority(ctx, policy)
		if readErr != nil || observed == nil {
			return s, ErrCapacityConflict
		}
		raw, marshalErr := json.Marshal(observed)
		var own model.CapacityNativeWorkerPhaseReadObservation
		if marshalErr != nil || json.Unmarshal(raw, &own) != nil || own.CandidateSelected || capacity.NativeWorkerPhaseHeaderValid(p, own, time.Now().UTC()) != nil {
			return s, ErrCapacityConflict
		}
		s.phaseAuthority, s.authority = &own, nil
		return s, nil
	}
	s.phaseAuthority = nil
	o, err := s.Runtime.ObserveAuthority(ctx, policy)
	if err != nil || o == nil {
		return s, ErrCapacityConflict
	}
	// Do not retain a producer-owned mutable pointer across the transaction.
	raw, err := json.Marshal(o)
	if err != nil {
		return s, ErrCapacityConflict
	}
	var own model.CapacityNativeWorkerPoolObservation
	if json.Unmarshal(raw, &own) != nil {
		return s, ErrCapacityConflict
	}
	if err = capacity.ValidateNativeWorkerPoolAuthority(p, &own, time.Now().UTC()); err != nil {
		return s, ErrCapacityConflict
	}
	s.authority = &own
	return s, nil
}

func (s CapacityNativeWorkerStore) Read(ctx context.Context, policy model.Manifest, id uuid.UUID) (model.CapacityNativeWorkerAttempt, error) {
	if s.Capacity.DB == nil {
		return model.CapacityNativeWorkerAttempt{}, ErrCapacityDisabled
	}
	var raw []byte
	err := s.Capacity.DB.QueryRowContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	var a model.CapacityNativeWorkerAttempt
	if err == nil {
		err = json.Unmarshal(raw, &a)
	}
	return a, err
}

func (s CapacityNativeWorkerStore) current(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityNativeWorkerAuthority, now time.Time) (model.CapacityIntent, error) {
	var old model.CapacityIntent
	if !s.Enabled || !s.Capacity.ExecutionEnabled || !p.ExecutionEnabled || s.Runtime == nil ||
		p.NativeWorkerLifecycleBinding == nil || s.Runtime.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit ||
		!validCapacityExecutor(s.Capacity.ExecutorID) || s.Capacity.WorkflowID == uuid.Nil {
		return old, ErrCapacityDisabled
	}
	if p.NativeWorkerLifecycleBinding.PhaseObserver != nil {
		if s.phaseAuthority == nil || s.phaseAuthority.CandidateSelected || capacity.NativeWorkerPhaseHeaderValid(p, *s.phaseAuthority, now) != nil {
			return old, ErrCapacityLease
		}
	} else {
		if s.authority == nil || capacity.ValidateNativeWorkerPoolAuthority(p, s.authority, now) != nil {
			return old, ErrCapacityLease
		}
	}
	var checksum string
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return old, err
	}
	if !active || checksum != policy.Checksum {
		return old, ErrCapacityConflict
	}
	workflow := nativeCapacityWorkflow(p, false)
	if err := tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.Capacity.WorkflowID, workflow.Namespace, workflow.Name).Scan(&active); err != nil {
		return old, err
	}
	if !active {
		return old, ErrCapacityMutationAuthorization
	}
	var err error
	old, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return old, err
	}
	// Dedicated authority: never loosen generic legacy checkLease or renew.
	if old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Generation != a.Generation ||
		old.FencingToken != a.FencingToken || old.RecoveryOnly || !old.Decision.ExecutionPermitted || old.LeaseOwner == "" ||
		old.LeaseExecutorID != s.Capacity.ExecutorID || old.LeaseExpiresAt == nil || !old.LeaseExpiresAt.After(now) ||
		(old.Phase != "preparing" && old.Phase != "draining") ||
		old.Assessment.NativeWorkerPool == nil || old.Assessment.NativeWorkerPool.OwnerEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch {
		return old, ErrCapacityLease
	}
	for _, profile := range p.NativeWorkerLifecycleBinding.Profiles {
		b := model.CapacityMutationBinding{IntegrationInstanceID: profile.Adapter.ManifestID, IntegrationChecksum: profile.Adapter.Checksum, IntegrationTypeID: profile.Adapter.IntegrationTypeID, IntegrationTypeChecksum: profile.Adapter.TypeChecksum}
		if err = checkMutationIntegration(ctx, tx, b); err != nil {
			return old, err
		}
		var version int
		if err = tx.QueryRowContext(ctx, `SELECT version FROM public.manifests WHERE id=$1`, profile.Adapter.ManifestID).Scan(&version); err != nil {
			return old, err
		}
		if version != profile.Adapter.Version {
			return old, ErrCapacityConflict
		}
	}
	return old, nil
}

func (s CapacityNativeWorkerStore) tx(ctx context.Context, policy model.Manifest, fn func(*sql.Tx, model.CapacityPolicySpec, time.Time) error) error {
	if s.Capacity.DB == nil {
		return ErrCapacityDisabled
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	if capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil {
		return ErrCapacityDisabled
	}
	tx, err := s.Capacity.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, p, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func nativeAttemptLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, id uuid.UUID) (model.CapacityNativeWorkerAttempt, []byte, error) {
	var raw, launch []byte
	var a model.CapacityNativeWorkerAttempt
	err := tx.QueryRowContext(ctx, `SELECT attempt,launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw, &launch)
	if err == nil {
		err = json.Unmarshal(raw, &a)
	}
	return a, launch, err
}

func nativeAttemptWriteTx(ctx context.Context, tx *sql.Tx, a model.CapacityNativeWorkerAttempt, birth *model.CapacityNativeWorkerBirth, insert bool, launch []byte) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if insert {
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_attempts(id,policy_id,namespace,environment,domain,dimension,generation,fencing_token,ipam_scope,overlay_ipv4,state,revision,attempt,launch_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, a.ID, a.PolicyID, a.Namespace, a.Environment, a.Domain, a.Dimension, a.Generation, a.FencingToken, a.Execution.IPAMScope, a.OverlayIPv4, a.State, a.Revision, raw, launch)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_attempts SET state=$2,revision=$3,attempt=$4 WHERE id=$1 AND revision=$5`, a.ID, a.State, a.Revision, raw, a.Revision-1)
		if err == nil {
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return ErrCapacityConflict
			}
		}
	}
	if err != nil {
		return err
	}
	record, _ := json.Marshal(struct {
		Attempt model.CapacityNativeWorkerAttempt `json:"attempt"`
		Birth   *model.CapacityNativeWorkerBirth  `json:"birth,omitempty"`
	}{a, birth})
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_events(attempt_id,revision,record) VALUES($1,$2,$3)`, a.ID, a.Revision, record)
	return err
}

func allocateNativeOverlayTx(ctx context.Context, tx *sql.Tx, p model.CapacityNativeWorkerExecutionProfile) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT host(overlay_ipv4) FROM public.capacity_native_worker_attempts WHERE ipam_scope=$1 AND state<>'absent'`, p.IPAMScope)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, ip := range p.ExcludedIPv4 {
		used[ip] = true
	}
	for rows.Next() {
		var ip string
		if err = rows.Scan(&ip); err != nil {
			rows.Close()
			return "", err
		}
		used[ip] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	prefix, err := netip.ParsePrefix(p.OverlayCIDR)
	if err != nil {
		return "", err
	}
	for ip := prefix.Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		if !prefix.Contains(ip.Next()) {
			break
		} // Network/broadcast are not allocatable.
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("declared overlay CIDR exhausted; no fake address or unlimited quota")
}

// The Claim baseline is immutable for this generation. Market reservations
// already charge only new units; never subtract the baseline a second time or
// treat the total target as a fresh create budget after a fence rotation.
func nativeAttemptCreationBudget(parent model.CapacityIntent, now time.Time) (int, error) {
	r, baseline := parent.MarketReservation, parent.BaselineSnapshot
	if parent.Phase != "preparing" || (parent.Decision.Action != "expand" && parent.Decision.Action != "prepare") ||
		r == nil || r.Schema != capacity.CapacityMarketMode || r.Profile != parent.Decision.Profile || r.Units < 1 || parent.Decision.Units < 1 ||
		baseline.Profile == "" || baseline.Units < 0 || baseline.ObservedAt.IsZero() || baseline.ObservedAt.After(now) ||
		baseline.TargetIdentity == "" || baseline.Owner == "" || baseline.ResourceUID == "" || baseline.WorkloadUID == "" ||
		baseline.ResourceVersion == "" || baseline.WorkloadResourceVersion == "" ||
		parent.Assessment.Market == nil || !parent.Assessment.Market.ValidUntil.After(now) {
		return 0, ErrCapacityConflict
	}
	budget := parent.Decision.Units
	if parent.Decision.Profile == baseline.Profile {
		budget -= baseline.Units
	}
	if budget < 1 || r.Units != budget {
		return 0, ErrCapacityConflict
	}
	matched := false
	for _, q := range parent.Assessment.Market.Profiles {
		if q.Profile != parent.Decision.Profile {
			continue
		}
		if matched || !capacity.ValidDigest(q.EvidenceSHA256) || q.Provider != r.Provider || q.Region != r.Region || q.Currency != r.Currency ||
			q.EvidenceSHA256 != r.QuoteEvidenceSHA256 || !q.ValidUntil.After(now) || !q.ValidationValidUntil.After(now) {
			return 0, ErrCapacityConflict
		}
		for _, c := range q.Costs {
			if c.State == "known" && !c.ValidUntil.After(now) {
				return 0, ErrCapacityConflict
			}
		}
		matched = true
	}
	if !matched {
		return 0, ErrCapacityConflict
	}
	return budget, nil
}

func nativeAttemptGenerationCountTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, generation int64) (int, error) {
	var count int
	// Every original child counts, including absent/unknown children and those
	// owned by an older fence. Recovery cannot replenish consumed create slots.
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_attempts WHERE policy_id=$1 AND generation=$2`, policy.ID, generation).Scan(&count)
	return count, err
}

func (s CapacityNativeWorkerStore) Reserve(ctx context.Context, policy model.Manifest, authority model.CapacityNativeWorkerAuthority) (model.CapacityNativeWorkerAttempt, error) {
	authorized, authErr := s.authenticate(ctx, policy)
	if authErr != nil {
		return model.CapacityNativeWorkerAttempt{}, authErr
	}
	s = authorized
	var out model.CapacityNativeWorkerAttempt
	err := s.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		return s.reserveNativeWorkerTx(ctx, tx, policy, p, authority, now, &out)
	})
	if err != nil {
		return model.CapacityNativeWorkerAttempt{}, err
	}
	return out, nil
}

func (s CapacityNativeWorkerStore) Redeem(ctx context.Context, policy model.Manifest, authority model.CapacityNativeWorkerAuthority, id uuid.UUID) (model.CapacityNativeWorkerPermit, error) {
	authorized, authErr := s.authenticate(ctx, policy)
	if authErr != nil {
		return model.CapacityNativeWorkerPermit{}, authErr
	}
	s = authorized
	var permit model.CapacityNativeWorkerPermit
	err := s.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		parent, err := s.current(ctx, tx, policy, p, authority, now)
		if err != nil {
			return err
		}
		budget, err := nativeAttemptCreationBudget(parent, now)
		if err != nil {
			return err
		}
		if !s.commandExpiresAt.IsZero() && !now.Before(s.commandExpiresAt) {
			return ErrCapacityLease
		}
		count, err := nativeAttemptGenerationCountTx(ctx, tx, policy, parent.Generation)
		if err != nil {
			return err
		}
		if count < 1 || count > budget {
			return ErrCapacityConflict
		}
		a, launch, err := nativeAttemptLoadTx(ctx, tx, policy, id)
		if err != nil {
			return err
		}
		if a.State != "reserved" || a.Generation != parent.Generation || a.FencingToken != parent.FencingToken || a.Profile != parent.Decision.Profile ||
			a.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || a.SourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit ||
			parent.Assessment.Market == nil || !parent.Assessment.Market.ValidUntil.After(now) {
			return ErrCapacityConflict
		}
		matched := false
		for _, v := range p.NativeWorkerLifecycleBinding.Profiles {
			if v.Profile == a.Profile && capacity.NativeWorkerSameExecution(v, a.Execution) {
				matched = true
			}
		}
		if !matched {
			return ErrCapacityConflict
		}
		a.State, a.Revision, a.UpdatedAt = "send_started", a.Revision+1, now
		if err = nativeAttemptWriteTx(ctx, tx, a, nil, false, nil); err != nil {
			return err
		}
		permit = model.CapacityNativeWorkerPermit{AttemptID: a.ID, LaunchSHA256: a.LaunchSHA256, OverlayIPv4: a.OverlayIPv4, Adapter: a.Execution.Adapter, BindingName: a.Execution.BindingName, Capability: a.Execution.EnsureCapability, PublicLaunchJSON: launch}
		return nil
	})
	// Unknown Commit never returns a permit; GET-only receiving finds the row.
	if err != nil {
		return model.CapacityNativeWorkerPermit{}, err
	}
	return permit, nil
}

// Renew extends only the existing progress lease. It cannot refresh original
// quote validity or mint a send permit after that quote expired.
func (s CapacityNativeWorkerStore) Renew(ctx context.Context, policy model.Manifest, authority model.CapacityNativeWorkerAuthority) error {
	authorized, authErr := s.authenticate(ctx, policy)
	if authErr != nil {
		return authErr
	}
	s = authorized
	_, err := s.Capacity.transactionWithTx(ctx, policy, func(p model.CapacityPolicySpec, _ *model.CapacityIntent, now time.Time, tx *sql.Tx) (model.CapacityIntent, string, error) {
		parent, err := s.current(ctx, tx, policy, p, authority, now)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		expiry := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		parent.LeaseExpiresAt, parent.UpdatedAt = &expiry, now
		return parent, "", nil
	})
	return err
}

func (s CapacityNativeWorkerStore) original(ctx context.Context, policy model.Manifest, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, string, error) {
	var out model.CapacityNativeWorkerOriginalReturn
	var digest string
	err := s.Capacity.DB.QueryRowContext(ctx, `SELECT wire,raw_sha256,capture_complete,error_class FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, a.ID).Scan(&out.Wire, &digest, &out.CaptureComplete, &out.ErrorClass)
	if err == nil {
		return out, digest, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, "", err
	}
	if s.Runtime == nil || s.Runtime.SourceCommit() != a.SourceCommit || a.State == "reserved" || a.State == "absent" {
		return out, "", ErrCapacityDisabled
	}
	out, captureErr := s.Runtime.CaptureOriginalReturn(ctx, a)
	if errors.Is(captureErr, ErrCapacityNativeReturnPending) {
		return model.CapacityNativeWorkerOriginalReturn{}, "", captureErr
	}
	if captureErr != nil && out.ErrorClass == "" {
		out.ErrorClass = "ORIGINAL_CAPTURE_UNCERTAIN"
		out.CaptureComplete = false
	}
	if len(out.Wire) > 1<<20 {
		out.Wire = append([]byte{}, out.Wire[:1<<20]...)
		out.ErrorClass = "ORIGINAL_CAPTURE_BOUND_EXCEEDED"
		out.CaptureComplete = false
	}
	if len(out.ErrorClass) > 128 || strings.ContainsAny(out.ErrorClass, "\r\n\x00") {
		out.ErrorClass = "ORIGINAL_ERROR_CLASS_REDACTED"
		out.CaptureComplete = false
	}
	if out.Wire == nil {
		out.Wire = []byte{}
	}
	// The shared writer commits private custody before any independent SDK read.
	return persistNativeWorkerOriginal(ctx, s.Capacity.DB, a.ID, out)
}

// Record's independent SDK callback runs ONLY after original private custody
// has committed. Public rows and birth hashes never contain raw ACK hashes.
func (s CapacityNativeWorkerStore) Record(ctx context.Context, policy model.Manifest, authority model.CapacityNativeWorkerAuthority, id uuid.UUID) (model.CapacityNativeWorkerAttempt, error) {
	a, err := s.Read(ctx, policy, id)
	if err != nil {
		return a, err
	}
	raw, rawSHA, err := s.original(ctx, policy, a)
	if err != nil {
		return model.CapacityNativeWorkerAttempt{}, err
	}
	if s.Runtime == nil || s.Runtime.SourceCommit() != a.SourceCommit {
		return model.CapacityNativeWorkerAttempt{}, ErrCapacityDisabled
	}
	observation, qualifyErr := s.Runtime.Qualify(ctx, a, raw) // WAN GET-only, outside Tx.
	if qualifyErr != nil {
		if a.State != "send_started" && a.State != "unknown" {
			return a, ErrCapacityConflict
		}
		observation = model.CapacityNativeWorkerObservation{State: "unknown", ExecutionScopeSHA256: a.Execution.ScopeSHA256, ObservedAt: time.Now().UTC(), OriginalReturnSHA256: rawSHA}
	}
	if observation.HCloudWitness != nil {
		observation.HCloudWitness = capacity.CloneNativeWorkerHCloudWitness(observation.HCloudWitness)
		if observation.HCloudWitness == nil {
			return model.CapacityNativeWorkerAttempt{}, ErrCapacityConflict
		}
	}
	if observation.OriginalReturnSHA256 != rawSHA {
		return model.CapacityNativeWorkerAttempt{}, ErrCapacityConflict
	}
	if observation.State != "unknown" && (!raw.CaptureComplete || raw.ErrorClass != "") {
		return model.CapacityNativeWorkerAttempt{}, ErrCapacityConflict
	}
	if observation.State != "unknown" && observation.State != "acknowledged" {
		authorized, authErr := s.authenticate(ctx, policy)
		if authErr != nil {
			return model.CapacityNativeWorkerAttempt{}, authErr
		}
		s = authorized
	}
	var out model.CapacityNativeWorkerAttempt
	err = s.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		current, _, err := nativeAttemptLoadTx(ctx, tx, policy, id)
		if err != nil {
			return err
		}
		if current.Revision != a.Revision || !capacity.NativeWorkerTransitionAllowed(current.State, observation.State) {
			return ErrCapacityConflict
		}
		if err = capacity.NativeWorkerObservationValid(current, observation, now, p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds); err != nil {
			return err
		}
		if observation.State != "unknown" && current.Provider == "hetzner" {
			witness := observation.HCloudWitness
			if observation.State == "absent" && witness == nil {
				witness = current.HCloudWitness
			}
			if !capacity.NativeWorkerHCloudWitnessBindingValid(p, current, witness) {
				return ErrCapacityConflict
			}
		}
		for _, protected := range p.NativeWorkerPoolBinding.ProtectedNodes {
			if observation.IndependentCurrent.ProviderID == protected.ProviderID || observation.NodeUID != "" && observation.NodeUID == protected.NodeUID {
				return ErrCapacityConflict
			}
		}
		// ACK/unknown are read-only historical truth. Every registry/admission/
		// drain/absence transition still requires current dedicated authority.
		if observation.State != "acknowledged" && observation.State != "unknown" {
			parent, err := s.current(ctx, tx, policy, p, authority, now)
			if err != nil {
				return err
			}
			if current.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch {
				return ErrCapacityConflict
			}
			if observation.State == "draining" || observation.State == "absent" {
				if parent.Phase != "draining" || parent.Decision.Action != "drain" {
					return ErrCapacityConflict
				}
			} else if current.Generation != parent.Generation || current.FencingToken != parent.FencingToken {
				return ErrCapacityConflict
			}
		}
		var birth *model.CapacityNativeWorkerBirth
		if observation.State == "acknowledged" {
			physical := observation.IndependentCurrent
			current.Physical = &physical
			if current.Provider == "hetzner" {
				current.HCloudWitness = capacity.CloneNativeWorkerHCloudWitness(observation.HCloudWitness)
				if !capacity.NativeWorkerHCloudWitnessValid(current, physical, current.HCloudWitness) {
					return ErrCapacityConflict
				}
			}
			acceptance, _ := json.Marshal(observation.OriginalAcceptance)
			read, _ := json.Marshal(struct {
				Physical   model.CapacityNativeWorkerPhysical
				ObservedAt time.Time
				RequestID  string
			}{physical, observation.ObservedAt, observation.IndependentRequestID})
			if current.HCloudWitness != nil {
				// This is a safe typed witness, never the privately retained raw
				// original or its digest. Keep the legacy AWS projection exact.
				read, _ = json.Marshal(struct {
					Physical      model.CapacityNativeWorkerPhysical
					ObservedAt    time.Time
					RequestID     string
					HCloudWitness *model.CapacityNativeWorkerHCloudWitness
				}{physical, observation.ObservedAt, observation.IndependentRequestID, current.HCloudWitness})
			}
			birth = &model.CapacityNativeWorkerBirth{Schema: capacity.NativeWorkerLifecycleMode, AttemptID: current.ID, PolicyID: current.PolicyID, Generation: current.Generation, FencingToken: current.FencingToken, PoolUID: current.PoolUID, PoolEpoch: current.PoolEpoch, ExecutionAdapter: current.Execution.Adapter, ExecutionScopeSHA256: current.Execution.ScopeSHA256, LaunchSHA256: current.LaunchSHA256, OriginalAcceptanceSHA256: fmt.Sprintf("%x", sha256.Sum256(acceptance)), IndependentReadSHA256: fmt.Sprintf("%x", sha256.Sum256(read)), OriginalRequestID: observation.OriginalRequestID, IndependentRequestID: observation.IndependentRequestID, Physical: physical}
			birth.HCloudWitness = capacity.CloneNativeWorkerHCloudWitness(current.HCloudWitness)
			wire, _ := json.Marshal(birth)
			current.BirthSHA256 = fmt.Sprintf("%x", sha256.Sum256(wire))
		}
		if observation.State == "registered" {
			current.NodeUID = observation.NodeUID
		}
		if current.NodeUID != "" && observation.State != "absent" && observation.State != "unknown" && observation.NodeUID != current.NodeUID {
			return ErrCapacityConflict
		}
		current.State, current.Revision, current.UpdatedAt = observation.State, current.Revision+1, now
		if err = nativeAttemptWriteTx(ctx, tx, current, birth, false, nil); err != nil {
			return err
		}
		out = current
		return nil
	})
	if err != nil {
		return model.CapacityNativeWorkerAttempt{}, err
	}
	return out, nil
}

// Every pending/uncertain child retains a finite known charge even after its
// parent completes or a different healthy pool profile wins. It is not an
// unknown whole-account quantity. An active parent covers its original group
// once; otherwise each live child plus one group fixed charge is accounted.
func appendNativeAttemptReservationsTx(ctx context.Context, tx *sql.Tx, ledger *capacity.MarketLedgerObservation, p model.CapacityPolicySpec, covered map[string]bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE state<>'absent' LIMIT 100001`)
	if err != nil {
		return err
	}
	defer rows.Close()
	groups := map[string]bool{}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("native child ledger collection bound exceeded")
		}
		var raw []byte
		var a model.CapacityNativeWorkerAttempt
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			return err
		}
		group := fmt.Sprintf("%s/%d", a.PolicyID, a.Generation)
		if covered[group] {
			continue
		}
		r := a.Reservation
		if a.GroupFixedCostMicros < 0 {
			return fmt.Errorf("negative group charge")
		}
		if !groups[group] {
			if a.GroupFixedCostMicros > int64(^uint64(0)>>1)-r.CostMicros {
				return fmt.Errorf("group charge overflow")
			}
			r.CostMicros += a.GroupFixedCostMicros
			groups[group] = true
		}
		if err = appendMarketReservation(ledger, p, &r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Only the explicit new mode uses child birth proofs. Legacy mode still reads
// its original confirmed grant format; a child never forges that old protocol.
func marketNativeAttemptBirthsTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, o *model.CapacityNativeWorkerPoolObservation) error {
	if len(o.Nodes) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.attempt,e.record->'birth' FROM public.capacity_native_worker_attempts a JOIN public.capacity_native_worker_events e ON e.attempt_id=a.id AND e.record ? 'birth' WHERE a.namespace=$1 AND a.environment=$2 AND a.domain=$3 AND a.dimension=$4 AND a.state IN('acknowledged','registered','admitted','draining') LIMIT 100001`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	type physicalBirth struct{ nodeUID, providerID string }
	births := map[marketNativeBirthKey]physicalBirth{}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("native child birth collection bound exceeded")
		}
		var raw, wire []byte
		var a model.CapacityNativeWorkerAttempt
		var b model.CapacityNativeWorkerBirth
		if err = rows.Scan(&raw, &wire); err != nil {
			return err
		}
		if json.Unmarshal(raw, &a) != nil || json.Unmarshal(wire, &b) != nil {
			return fmt.Errorf("invalid typed native birth")
		}
		canonical, _ := json.Marshal(b)
		digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
		if b.Schema != capacity.NativeWorkerLifecycleMode || a.Physical == nil || b.AttemptID != a.ID ||
			b.PolicyID != a.PolicyID || b.Generation != a.Generation || b.FencingToken != a.FencingToken ||
			b.PoolUID != a.PoolUID || b.PoolEpoch != a.PoolEpoch || b.PoolUID != p.NativeWorkerPoolBinding.PoolUID ||
			b.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || b.ExecutionAdapter != a.Execution.Adapter ||
			b.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 || b.LaunchSHA256 != a.LaunchSHA256 || b.Physical != *a.Physical || digest != a.BirthSHA256 ||
			!capacity.ValidDigest(b.OriginalAcceptanceSHA256) || !capacity.ValidDigest(b.IndependentReadSHA256) ||
			!capacity.NativeWorkerPhysicalValid(a, b.Physical) {
			return fmt.Errorf("child birth no longer joins immutable launch and SDK acceptance")
		}
		if a.Provider == "hetzner" && (a.HCloudWitness == nil || b.HCloudWitness == nil ||
			a.HCloudWitness.EvidenceSHA256 != b.HCloudWitness.EvidenceSHA256 ||
			!capacity.NativeWorkerHCloudWitnessValid(a, b.Physical, b.HCloudWitness) ||
			!capacity.NativeWorkerHCloudWitnessBindingValid(p, a, b.HCloudWitness)) {
			return fmt.Errorf("hcloud birth no longer joins the complete source-pinned witness")
		}
		execMatched := false
		for _, e := range p.NativeWorkerLifecycleBinding.Profiles {
			if e.Profile == a.Profile && e.Adapter == b.ExecutionAdapter {
				execMatched = true
			}
		}
		if !execMatched {
			return fmt.Errorf("birth execution adapter differs from exact source binding")
		}
		births[marketNativeBirthKey{a.PolicyID.String(), a.Generation, a.FencingToken, a.Profile, b.Physical.ResourceID, b.ExecutionAdapter.ManifestID, digest}] = physicalBirth{a.NodeUID, b.Physical.ProviderID}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	adapters := map[string]string{}
	for _, v := range p.NativeWorkerLifecycleBinding.Profiles {
		adapters[v.Profile] = v.Adapter.ManifestID
	}
	for _, node := range o.Nodes {
		resource := node.ProviderID[strings.LastIndex(node.ProviderID, "/")+1:]
		key := marketNativeBirthKey{node.CapacityPolicyID, node.IntentGeneration, node.FencingToken, node.Profile, resource, adapters[node.Profile], node.RegistrationReceiptSHA256}
		birth, ok := births[key]
		if !ok || birth.providerID != node.ProviderID || birth.nodeUID != "" && birth.nodeUID != node.NodeUID {
			return fmt.Errorf("node lacks exact original typed child birth")
		}
	}
	return nil
}
