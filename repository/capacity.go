package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrCapacityConflict = errors.New("capacity intent conflict")
var ErrCapacityLease = errors.New("capacity lease unavailable or stale")
var ErrCapacityDisabled = errors.New("capacity execution is disabled")

const maxCapacityGeneration int64 = 9007199254740991

// CapacityStore serializes each logical dimension in PostgreSQL. The process
// gate is explicit and defaults to false in the workflow handler.
type CapacityStore struct {
	DB               *sql.DB
	ExecutionEnabled bool
	WorkflowID       uuid.UUID
	ExecutorID       string
}

// Assess persists a proposal, even in shadow mode. An outstanding generation
// is never overwritten by a concurrent assessment or a policy revision.
func (s CapacityStore) Assess(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	intent, err := s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if old != nil && pendingCapacityPhase(old.Phase) && old.Phase != "proposed" {
			if old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum {
				return model.CapacityIntent{}, "", fmt.Errorf("%w: pending generation belongs to another policy revision", ErrCapacityConflict)
			}
			return *old, "", nil
		}
		clock := model.CapacityClockState{}
		generation, fence := int64(0), int64(0)
		if old != nil {
			generation, fence = old.Generation, old.FencingToken
			clock.LastActionAt = old.Decision.Clock.LastActionAt
			if old.PolicyChecksum == policy.Checksum && sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) {
				clock = old.Decision.Clock
			}
		}
		decision, err := capacity.Assess(p, assessment, clock, now)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		decision.ExecutionPermitted = decision.ExecutionPermitted && s.ExecutionEnabled
		phase := "hold"
		if decision.Action != "hold" {
			if old == nil || old.Phase != "proposed" || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Decision.Action != decision.Action || old.Decision.Profile != decision.Profile || old.Decision.Units != decision.Units {
				if generation >= maxCapacityGeneration {
					return model.CapacityIntent{}, "", ErrCapacityConflict
				}
				generation++
			}
			phase = "proposed"
		}
		return model.CapacityIntent{
			Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum,
			Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension,
			Generation: generation, FencingToken: fence, Phase: phase,
			Decision: decision, Assessment: assessment, UpdatedAt: now,
		}, "", nil
	})
	return redactCapacityLease(intent), err
}

// Claim creates the first server-owned execution lease for an unclaimed plan.
// A previously started generation can only Recover after lease expiry; elapsed
// time never grants another normal execution lease over an uncertain mutation.
func (s CapacityStore) Claim(ctx context.Context, policy model.Manifest, generation int64, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !s.ExecutionEnabled || !p.ExecutionEnabled {
			return model.CapacityIntent{}, "", ErrCapacityDisabled
		}
		if !validCapacityExecutor(s.ExecutorID) {
			return model.CapacityIntent{}, "", ErrCapacityLease
		}
		if old == nil || old.Generation != generation || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.RecoveryOnly || !pendingCapacityPhase(old.Phase) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
			return model.CapacityIntent{}, "", ErrCapacityLease
		}
		if old.Phase != "proposed" {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: started generation requires recovery-only fencing", ErrCapacityConflict)
		}
		// A proposal can be reviewed for longer than the metric freshness bound.
		// Reassessment before claiming is mandatory, including source timestamps.
		if err := capacity.ValidateSnapshot(p, assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.Phase == "proposed" {
			if !sameCapacityResources(old.Assessment.Snapshot, assessment.Snapshot) {
				return model.CapacityIntent{}, "", ErrCapacityConflict
			}
			if old.Decision.Reason != "protected_floor_recovery" {
				if err := capacity.ValidateAssessment(p, assessment, now); err != nil {
					return model.CapacityIntent{}, "", err
				}
			}
			d, err := capacity.Assess(p, assessment, old.Decision.Clock, now)
			if err != nil {
				return model.CapacityIntent{}, "", err
			}
			if d.Action != old.Decision.Action || d.Units != old.Decision.Units || d.Profile != old.Decision.Profile {
				return model.CapacityIntent{}, "", fmt.Errorf("%w: proposal no longer matches current pressure", ErrCapacityConflict)
			}
		}
		next := *old
		next.Assessment = assessment
		next.Decision.ExecutionPermitted = capacityProfileCurrent(p, old.Decision, now)
		if next.FencingToken >= maxCapacityGeneration {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		next.FencingToken++
		next.LeaseOwner = uuid.NewString()
		next.LeaseExecutorID = s.ExecutorID
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt, next.UpdatedAt = &expires, now
		if next.Phase == "proposed" {
			next.BaselineSnapshot = assessment.Snapshot
			if next.Decision.Action == "drain" {
				next.Phase = "draining"
			} else {
				next.Phase = "preparing"
			}
		}
		return next, "", nil
	})
}

// Renew and Advance require the same generation, owner and fencing token.
// Database time, rather than a caller timestamp, is authoritative for leases.
func (s CapacityStore) Renew(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if err := s.checkLease(p, policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		next := *old
		next.Decision.ExecutionPermitted = capacityProfileCurrent(p, old.Decision, now)
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt, next.UpdatedAt = &expires, now
		return next, "", nil
	})
}

func (s CapacityStore) Advance(ctx context.Context, policy model.Manifest, generation, fence int64, owner, phase string, proof model.CapacityTransitionProof) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if err := s.checkLease(p, policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !capacityTransitionAllowed(old.Phase, phase) {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: phase transition %s to %s", ErrCapacityConflict, old.Phase, phase)
		}
		eligible := capacityProfileCurrent(p, old.Decision, now)
		if (phase == "prepared" || phase == "canary") && !eligible {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity profile quote or validation expired; recovery/readback required")
		}
		if proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || !proof.Healthy || proof.Inflight == nil || *proof.Inflight < 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity transition requires a fresh, healthy workflow receipt")
		}
		if err := capacity.ValidateAssessment(p, proof.Assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !sameCapacityResourceIdentity(old.Assessment.Snapshot, proof.Assessment.Snapshot) {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: resource replacement requires a separately authorized migration", ErrCapacityConflict)
		}
		if (phase == "drained" || (phase == "promoted" && capacityIntentReduction(*old))) && *proof.Inflight != 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity drain still has inflight work")
		}
		if phase == "promoted" && (proof.Assessment.Snapshot.Units != old.Decision.Units || proof.Assessment.Snapshot.Profile != old.Decision.Profile) {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity promotion does not match observed target state")
		}
		next := *old
		next.Decision.ExecutionPermitted = eligible
		next.Phase, next.Assessment, next.UpdatedAt = phase, proof.Assessment, now
		if phase == "promoted" {
			next.LeaseOwner, next.LeaseExecutorID, next.LeaseExpiresAt = "", "", nil
			next.Decision.Clock.LastActionAt = now
			next.Decision.Clock.UpSince, next.Decision.Clock.DownSince = time.Time{}, time.Time{}
		}
		return next, proof.ReceiptRef, nil
	})
}

func (s CapacityStore) checkLease(p model.CapacityPolicySpec, policy model.Manifest, old *model.CapacityIntent, generation, fence int64, owner string, now time.Time) error {
	if !s.ExecutionEnabled || !p.ExecutionEnabled {
		return ErrCapacityDisabled
	}
	if old == nil || old.Generation != generation || old.FencingToken != fence || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.RecoveryOnly || !pendingCapacityPhase(old.Phase) {
		return ErrCapacityConflict
	}
	if !validCapacityExecutor(s.ExecutorID) || old.LeaseExecutorID != s.ExecutorID || owner == "" || old.LeaseOwner != owner || old.LeaseExpiresAt == nil || !old.LeaseExpiresAt.After(now) {
		return ErrCapacityLease
	}
	return nil
}

func (s CapacityStore) Observe(ctx context.Context, policy model.Manifest) (model.CapacityIntent, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	intent, err := loadCapacityIntent(ctx, s.DB, policy.Metadata.Namespace, p, false)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	if intent.PolicyName != policy.Metadata.Name {
		return model.CapacityIntent{}, ErrCapacityConflict
	}
	return redactCapacityLease(intent), nil
}

// Recover obtains a new epoch solely for authoritative readback and remote
// quiescence/fencing. It never reopens acquisition or infers cancellation from
// elapsed lease time. The exact original revision may now be inactive.
func (s CapacityStore) Recover(ctx context.Context, policy model.Manifest, generation int64, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	return s.recoveryTransaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !validCapacityExecutor(s.ExecutorID) || old == nil || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Generation != generation || old.Phase == "proposed" || !pendingCapacityPhase(old.Phase) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
			return model.CapacityIntent{}, "", ErrCapacityLease
		}
		if err := capacity.ValidateSnapshot(p, assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !validCapacityBaseline(p, *old) || !sameCapacityResourceIdentity(old.BaselineSnapshot, assessment.Snapshot) {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: original resource identity/baseline is unavailable", ErrCapacityConflict)
		}
		if old.FencingToken >= maxCapacityGeneration {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		next := *old
		next.RecoveryOnly = true
		next.Decision.ExecutionPermitted = false
		next.Assessment, next.UpdatedAt = assessment, now
		next.FencingToken++
		next.LeaseOwner, next.LeaseExecutorID = uuid.NewString(), s.ExecutorID
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt = &expires
		return next, "", nil
	})
}

func (s CapacityStore) RenewRecovery(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (model.CapacityIntent, error) {
	return s.recoveryTransaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if err := s.checkRecoveryLease(policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		next := *old
		next.Decision.ExecutionPermitted = false
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt, next.UpdatedAt = &expires, now
		return next, "", nil
	})
}

// Reconcile closes a recovery epoch only from a trusted workflow's fresh
// provider-fencing and quiescence proof. A GET of baseline state alone cannot
// certify that a late writer has been cancelled, nor does recovery certify a
// canary, rollback, or absence of unrelated/orphan provider resources.
func (s CapacityStore) Reconcile(ctx context.Context, policy model.Manifest, generation, fence int64, owner, outcome string, proof model.CapacityTransitionProof) (model.CapacityIntent, error) {
	return s.recoveryTransaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if err := s.checkRecoveryLease(policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if outcome != "reconciled" && outcome != "reconciled_partial" && outcome != "aborted" {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity recovery requires reconciled, reconciled_partial or aborted outcome")
		}
		if proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || !proof.Healthy || proof.Inflight == nil || *proof.Inflight < 0 || proof.MutationInflight == nil || *proof.MutationInflight != 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity recovery requires fresh healthy proof, current provider fencing and explicitly zero outstanding mutations")
		}
		if proof.MutationAuthorityKind == "core_mutation_grants" {
			if len(p.MutationBindings) == 0 || proof.ProviderFencingToken != 0 {
				return model.CapacityIntent{}, "", fmt.Errorf("core mutation authority requires approved bindings and must not invent a provider fencing token")
			}
		} else if proof.MutationAuthorityKind != "" || proof.ProviderFencingToken != fence {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity recovery requires exact mutation authority")
		}
		// Floor repair admitted without demand metrics may record its observed
		// result during telemetry loss. This only closes a readback ledger fact;
		// it never certifies business readiness/canary or authorizes reduction.
		var assessmentErr error
		if old.Decision.Reason == "protected_floor_recovery" && !capacityIntentReduction(*old) {
			assessmentErr = capacity.ValidateSnapshot(p, proof.Assessment, now)
		} else {
			assessmentErr = capacity.ValidateAssessment(p, proof.Assessment, now)
		}
		if assessmentErr != nil {
			return model.CapacityIntent{}, "", assessmentErr
		}
		if !validCapacityBaseline(p, *old) || !sameCapacityResourceIdentity(old.BaselineSnapshot, proof.Assessment.Snapshot) {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: resource replacement cannot be reconciled implicitly", ErrCapacityConflict)
		}
		if capacityIntentReduction(*old) && *proof.Inflight != 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity reduction still has inflight business work")
		}
		wantedProfile, wantedUnits := old.Decision.Profile, old.Decision.Units
		if outcome == "reconciled_partial" {
			units := proof.Assessment.Snapshot.Units
			if proof.MutationAuthorityKind != "core_mutation_grants" || !proof.MembershipComplete || proof.NoMutationVerified || old.BaselineSnapshot.Profile != wantedProfile || proof.Assessment.Snapshot.Profile != wantedProfile || units < p.Floor || units > p.Ceiling || units < min(old.BaselineSnapshot.Units, wantedUnits) || units > max(old.BaselineSnapshot.Units, wantedUnits) || units == wantedUnits {
				return model.CapacityIntent{}, "", fmt.Errorf("partial recovery requires complete owned membership inside the original same-profile change and protected envelope")
			}
			wantedUnits = units
		}
		if outcome == "aborted" {
			if !proof.NoMutationVerified {
				return model.CapacityIntent{}, "", fmt.Errorf("capacity abort requires explicit no_mutation_verified provider proof")
			}
			wantedProfile, wantedUnits = old.BaselineSnapshot.Profile, old.BaselineSnapshot.Units
		}
		if proof.Assessment.Snapshot.Profile != wantedProfile || proof.Assessment.Snapshot.Units != wantedUnits {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity recovery observation does not match its terminal outcome")
		}
		next := *old
		next.Phase, next.Assessment, next.UpdatedAt = outcome, proof.Assessment, now
		next.Decision.ExecutionPermitted = false
		next.LeaseOwner, next.LeaseExecutorID, next.LeaseExpiresAt = "", "", nil
		next.Decision.Clock.LastActionAt = now
		next.Decision.Clock.UpSince, next.Decision.Clock.DownSince = time.Time{}, time.Time{}
		return next, proof.ReceiptRef, nil
	})
}

func (s CapacityStore) checkRecoveryLease(policy model.Manifest, old *model.CapacityIntent, generation, fence int64, owner string, now time.Time) error {
	if old == nil || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Generation != generation || old.FencingToken != fence || !old.RecoveryOnly || old.Phase == "proposed" || !pendingCapacityPhase(old.Phase) {
		return ErrCapacityConflict
	}
	if !validCapacityExecutor(s.ExecutorID) || old.LeaseExecutorID != s.ExecutorID || owner == "" || old.LeaseOwner != owner || old.LeaseExpiresAt == nil || !old.LeaseExpiresAt.After(now) {
		return ErrCapacityLease
	}
	return nil
}

func validCapacityExecutor(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil
}

func capacityProfileCurrent(p model.CapacityPolicySpec, decision model.CapacityDecision, now time.Time) bool {
	for _, profile := range p.Profiles {
		if profile.Name == decision.Profile && profile.MinUnits <= decision.Units && profile.MaxUnits >= decision.Units && profile.QuoteValidUntil.After(now) && profile.ValidationValidUntil.After(now) {
			return true
		}
	}
	return false
}

func validCapacityBaseline(p model.CapacityPolicySpec, intent model.CapacityIntent) bool {
	baseline := intent.BaselineSnapshot
	if baseline.ObservedAt.IsZero() || baseline.WorkloadResourceVersion == "" || baseline.ResourceVersion == "" || baseline.ResourceUID == "" || baseline.WorkloadUID == "" || baseline.TargetIdentity != p.TargetIdentity || baseline.Owner != p.Owner || baseline.Units < 0 || baseline.Units > p.Ceiling || !sameCapacityResourceIdentity(baseline, intent.Assessment.Snapshot) {
		return false
	}
	for _, profile := range p.Profiles {
		if profile.Name == baseline.Profile {
			return true
		}
	}
	return false
}

func capacityIntentReduction(intent model.CapacityIntent) bool {
	return intent.Decision.Action == "drain" || intent.Decision.Units < intent.BaselineSnapshot.Units
}

func redactCapacityLease(intent model.CapacityIntent) model.CapacityIntent {
	intent.LeaseOwner, intent.LeaseExecutorID = "", ""
	return intent
}

type capacityMutation func(model.CapacityPolicySpec, *model.CapacityIntent, time.Time) (model.CapacityIntent, string, error)

func (s CapacityStore) transaction(ctx context.Context, policy model.Manifest, mutate capacityMutation) (model.CapacityIntent, error) {
	return s.capacityTransaction(ctx, policy, false, mutate)
}

func (s CapacityStore) recoveryTransaction(ctx context.Context, policy model.Manifest, mutate capacityMutation) (model.CapacityIntent, error) {
	return s.capacityTransaction(ctx, policy, true, mutate)
}

func (s CapacityStore) capacityTransaction(ctx context.Context, policy model.Manifest, historical bool, mutate capacityMutation) (model.CapacityIntent, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	defer tx.Rollback()
	// Advisory lock covers the first insert as well as subsequent row updates.
	key, _ := json.Marshal([]string{policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(key)); err != nil {
		return model.CapacityIntent{}, err
	}
	var checksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT checksum, active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return model.CapacityIntent{}, err
	}
	if (!active && !historical) || checksum != policy.Checksum {
		return model.CapacityIntent{}, fmt.Errorf("%w: policy is no longer active", ErrCapacityConflict)
	}
	if s.WorkflowID != uuid.Nil {
		var workflowActive bool
		if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&workflowActive); err != nil {
			return model.CapacityIntent{}, err
		}
		if !workflowActive {
			return model.CapacityIntent{}, fmt.Errorf("%w: workflow is no longer active", ErrCapacityConflict)
		}
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return model.CapacityIntent{}, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	var previous *model.CapacityIntent
	if err == nil {
		if old.PolicyName != policy.Metadata.Name {
			return model.CapacityIntent{}, fmt.Errorf("%w: another policy owns this dimension", ErrCapacityConflict)
		}
		previous = &old
	} else if !errors.Is(err, sql.ErrNoRows) {
		return model.CapacityIntent{}, err
	}
	next, receipt, err := mutate(p, previous, now.UTC())
	if err != nil {
		return model.CapacityIntent{}, err
	}
	if next.Phase == "promoted" || next.Phase == "reconciled" || next.Phase == "reconciled_partial" || next.Phase == "aborted" {
		// Only never-redeemed permissions can expire without remote proof.
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state='expired',grant_record=jsonb_set(grant_record,'{grant,state}','"expired"'),updated_at=$5 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state='issued' AND expires_at<=$5`, next.Namespace, p.Environment, p.Domain, p.Dimension, now); err != nil {
			return model.CapacityIntent{}, err
		}
		var unresolved int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled')`, next.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unresolved); err != nil {
			return model.CapacityIntent{}, err
		}
		if unresolved != 0 {
			return model.CapacityIntent{}, fmt.Errorf("%w: unresolved provider mutation authority", ErrCapacityConflict)
		}
		if next.Phase == "reconciled_partial" {
			var live, fresh, matchingProfile int
			if err = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE (slot_record->>'observed_at')::timestamptz BETWEEN $5 AND $6),count(*) FILTER(WHERE profile_name=$7) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, next.Namespace, p.Environment, p.Domain, p.Dimension, now.Add(-time.Duration(p.MaxEvidenceAgeSeconds)*time.Second), now.Add(5*time.Second), next.Assessment.Snapshot.Profile).Scan(&live, &fresh, &matchingProfile); err != nil {
				return model.CapacityIntent{}, err
			}
			if live != next.Assessment.Snapshot.Units || fresh != live || matchingProfile != live {
				return model.CapacityIntent{}, fmt.Errorf("%w: partial recovery inventory does not match fresh immutable native membership", ErrCapacityConflict)
			}
		}
		if next.Phase == "aborted" {
			var mutations int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND state='confirmed'`, next.Namespace, p.Environment, p.Domain, p.Dimension, next.Generation).Scan(&mutations); err != nil {
				return model.CapacityIntent{}, err
			}
			if mutations != 0 {
				return model.CapacityIntent{}, fmt.Errorf("%w: a confirmed provider mutation cannot be certified as no mutation", ErrCapacityConflict)
			}
		}
	}
	data, err := json.Marshal(next)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intents (namespace, environment, domain, dimension, intent, updated_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT (namespace,environment,domain,dimension)
		DO UPDATE SET intent=EXCLUDED.intent, updated_at=EXCLUDED.updated_at`, next.Namespace, next.Environment, next.Domain, next.Dimension, data, next.UpdatedAt); err != nil {
		return model.CapacityIntent{}, err
	}
	if previous == nil || next.Generation != previous.Generation || next.FencingToken != previous.FencingToken || next.Phase != previous.Phase {
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events (namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, receipt); err != nil {
			return model.CapacityIntent{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityIntent{}, err
	}
	return next, nil
}

type capacityQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadCapacityIntent(ctx context.Context, db capacityQueryer, namespace string, p model.CapacityPolicySpec, lock bool) (model.CapacityIntent, error) {
	q := `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`
	if lock {
		q += ` FOR UPDATE`
	}
	var data []byte
	if err := db.QueryRowContext(ctx, q, namespace, p.Environment, p.Domain, p.Dimension).Scan(&data); err != nil {
		return model.CapacityIntent{}, err
	}
	var intent model.CapacityIntent
	err := json.Unmarshal(data, &intent)
	return intent, err
}

func parseCapacityPolicy(policy model.Manifest) (model.CapacityPolicySpec, error) {
	var p model.CapacityPolicySpec
	if policy.Kind != "capacity_policy" || policy.ID == uuid.Nil || policy.Checksum == "" || policy.Metadata.Namespace == "" || policy.Metadata.Name == "" {
		return p, fmt.Errorf("capacity requires a stored policy identity")
	}
	if err := json.Unmarshal(policy.Spec, &p); err != nil {
		return p, err
	}
	return p, capacity.ValidatePolicy(p)
}

func pendingCapacityPhase(phase string) bool {
	return phase != "hold" && phase != "promoted" && phase != "reconciled" && phase != "reconciled_partial" && phase != "aborted"
}
func sameCapacityResources(a, b model.CapacitySnapshot) bool {
	return sameCapacityResourceIdentity(a, b) && a.WorkloadResourceVersion == b.WorkloadResourceVersion
}
func sameCapacityResourceIdentity(a, b model.CapacitySnapshot) bool {
	return a.TargetIdentity == b.TargetIdentity && a.ResourceUID == b.ResourceUID && a.WorkloadUID == b.WorkloadUID && a.Owner == b.Owner
}
func capacityTransitionAllowed(from, to string) bool {
	return (from == "preparing" && to == "prepared") || (from == "prepared" && to == "canary") || (from == "canary" && to == "promoted") || (from == "draining" && to == "drained") || (from == "drained" && to == "promoted")
}
