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
}

// Assess persists a proposal, even in shadow mode. An outstanding generation
// is never overwritten by a concurrent assessment or a policy revision.
func (s CapacityStore) Assess(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if old != nil && pendingCapacityPhase(old.Phase) && old.Phase != "proposed" {
			if old.PolicyChecksum != policy.Checksum {
				return model.CapacityIntent{}, "", fmt.Errorf("%w: pending generation belongs to another policy revision", ErrCapacityConflict)
			}
			return *old, "", nil
		}
		clock := model.CapacityClockState{}
		generation, fence := int64(0), int64(0)
		if old != nil {
			generation, fence = old.Generation, old.FencingToken
			if old.PolicyChecksum == policy.Checksum && sameCapacityResources(old.Assessment.Snapshot, assessment.Snapshot) {
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
			if old == nil || old.Phase != "proposed" || old.PolicyChecksum != policy.Checksum || old.Decision.Action != decision.Action || old.Decision.Profile != decision.Profile || old.Decision.Units != decision.Units {
				if generation >= maxCapacityGeneration {
					return model.CapacityIntent{}, "", ErrCapacityConflict
				}
				generation++
			}
			phase = "proposed"
		}
		return model.CapacityIntent{
			Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyChecksum: policy.Checksum,
			Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension,
			Generation: generation, FencingToken: fence, Phase: phase,
			Decision: decision, Assessment: assessment, UpdatedAt: now,
		}, "", nil
	})
}

// Claim creates a server-owned lease. Expiry permits a new fenced owner to
// recover the same generation; it does not mark provider work completed.
func (s CapacityStore) Claim(ctx context.Context, policy model.Manifest, generation int64, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !s.ExecutionEnabled || !p.ExecutionEnabled {
			return model.CapacityIntent{}, "", ErrCapacityDisabled
		}
		if old == nil || old.Generation != generation || old.PolicyChecksum != policy.Checksum || !pendingCapacityPhase(old.Phase) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
			return model.CapacityIntent{}, "", ErrCapacityLease
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
		if next.FencingToken >= maxCapacityGeneration {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		next.FencingToken++
		next.LeaseOwner = uuid.NewString()
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt, next.UpdatedAt = &expires, now
		if next.Phase == "proposed" {
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
		if proof.ReceiptRef == "" || len(proof.ReceiptRef) > 512 || !capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) || !proof.Healthy || proof.Inflight < 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity transition requires a fresh, healthy workflow receipt")
		}
		if err := capacity.ValidateAssessment(p, proof.Assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if !sameCapacityResourceIdentity(old.Assessment.Snapshot, proof.Assessment.Snapshot) {
			return model.CapacityIntent{}, "", fmt.Errorf("%w: resource replacement requires a separately authorized migration", ErrCapacityConflict)
		}
		if phase == "drained" && proof.Inflight != 0 {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity drain still has inflight work")
		}
		if phase == "promoted" && (proof.Assessment.Snapshot.Units != old.Decision.Units || proof.Assessment.Snapshot.Profile != old.Decision.Profile) {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity promotion does not match observed target state")
		}
		next := *old
		next.Phase, next.Assessment, next.UpdatedAt = phase, proof.Assessment, now
		if phase == "promoted" {
			next.LeaseOwner, next.LeaseExpiresAt = "", nil
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
	if old == nil || old.Generation != generation || old.FencingToken != fence || old.PolicyChecksum != policy.Checksum || !pendingCapacityPhase(old.Phase) {
		return ErrCapacityConflict
	}
	if owner == "" || old.LeaseOwner != owner || old.LeaseExpiresAt == nil || !old.LeaseExpiresAt.After(now) {
		return ErrCapacityLease
	}
	eligible := false
	for _, profile := range p.Profiles {
		if profile.Name == old.Decision.Profile && profile.MinUnits <= old.Decision.Units && profile.MaxUnits >= old.Decision.Units && profile.QuoteValidUntil.After(now) && profile.ValidationValidUntil.After(now) {
			eligible = true
		}
	}
	if !eligible {
		return fmt.Errorf("capacity profile quote or validation expired")
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
	return intent, nil
}

type capacityMutation func(model.CapacityPolicySpec, *model.CapacityIntent, time.Time) (model.CapacityIntent, string, error)

func (s CapacityStore) transaction(ctx context.Context, policy model.Manifest, mutate capacityMutation) (model.CapacityIntent, error) {
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
	if err = tx.QueryRowContext(ctx, `SELECT checksum, active FROM public.manifests WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, policy.ID).Scan(&checksum, &active); err != nil {
		return model.CapacityIntent{}, err
	}
	if !active || checksum != policy.Checksum {
		return model.CapacityIntent{}, fmt.Errorf("%w: policy is no longer active", ErrCapacityConflict)
	}
	if s.WorkflowID != uuid.Nil {
		var workflowActive bool
		if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND deleted_at IS NULL FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&workflowActive); err != nil {
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
	if policy.Kind != "capacity_policy" || policy.Checksum == "" || policy.Metadata.Namespace == "" || policy.Metadata.Name == "" {
		return p, fmt.Errorf("capacity requires a stored policy identity")
	}
	if err := json.Unmarshal(policy.Spec, &p); err != nil {
		return p, err
	}
	return p, capacity.ValidatePolicy(p)
}

func pendingCapacityPhase(phase string) bool { return phase != "hold" && phase != "promoted" }
func sameCapacityResources(a, b model.CapacitySnapshot) bool {
	return sameCapacityResourceIdentity(a, b) && a.WorkloadResourceVersion == b.WorkloadResourceVersion
}
func sameCapacityResourceIdentity(a, b model.CapacitySnapshot) bool {
	return a.TargetIdentity == b.TargetIdentity && a.ResourceUID == b.ResourceUID && a.WorkloadUID == b.WorkloadUID && a.Owner == b.Owner
}
func capacityTransitionAllowed(from, to string) bool {
	return (from == "preparing" && to == "prepared") || (from == "prepared" && to == "canary") || (from == "canary" && to == "promoted") || (from == "draining" && to == "drained") || (from == "drained" && to == "promoted")
}
