//go:build linux && nativequalification

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

// Source-only accounting contract, NOT ordinary compensation. The original
// settled receipt/grant is preserved. Exactly one source-signed physically
// terminated failed parent may be excluded; every other unresolved row fails.
func (s CapacityStore) ReconcileSourceFailedFloorRecovery(ctx context.Context, policy model.Manifest, generation, fence int64, owner, parentID string, proof model.CapacityTransitionProof) (model.CapacityIntent, SourceFailureCleanupTerminal, error) {
	outcome := "reconciled_failed_floor"
	var captured SourceFailureCleanupTerminal
	result,err:=s.sourceFloorCapacityTransaction(ctx, policy, parentID, &captured, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if err := s.checkRecoveryLease(policy, old, generation, fence, owner, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		if outcome != "reconciled" && outcome != "reconciled_partial" && outcome != "reconciled_failed_floor" && outcome != "aborted" {
			return model.CapacityIntent{}, "", fmt.Errorf("capacity recovery requires reconciled, reconciled_partial, reconciled_failed_floor or aborted outcome")
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
		if outcome == "reconciled_failed_floor" {
			if proof.MutationAuthorityKind != "core_mutation_grants" || !proof.MembershipComplete || proof.NoMutationVerified || old.Decision.Reason != "protected_floor_recovery" || capacityIntentReduction(*old) || old.BaselineSnapshot.Units >= p.Floor || old.BaselineSnapshot.Profile != wantedProfile || proof.Assessment.Snapshot.Profile != old.BaselineSnapshot.Profile || proof.Assessment.Snapshot.Units != old.BaselineSnapshot.Units {
				return model.CapacityIntent{}, "", fmt.Errorf("failed floor recovery requires complete unchanged healthy baseline below the protected floor")
			}
			wantedProfile, wantedUnits = old.BaselineSnapshot.Profile, old.BaselineSnapshot.Units
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
		next.FloorDegraded = outcome == "reconciled_failed_floor"
		next.Decision.ExecutionPermitted = false
		next.LeaseOwner, next.LeaseExecutorID, next.LeaseExpiresAt = "", "", nil
		next.Decision.Clock.LastActionAt = now
		next.Decision.Clock.UpSince, next.Decision.Clock.DownSince = time.Time{}, time.Time{}
		return next, proof.ReceiptRef, nil
	})
	return result,captured,err
}


func (s CapacityStore) sourceFloorCapacityTransaction(ctx context.Context, policy model.Manifest, parentID string, captured *SourceFailureCleanupTerminal, mutate capacityMutation) (model.CapacityIntent, error) {
	historical := true
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
		workflow := nativeCapacityWorkflow(p, s.AdmissionOnly)
		if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 FOR SHARE`, s.WorkflowID, workflow.Namespace, workflow.Name).Scan(&workflowActive); err != nil {
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
	// The original Host claim is single-use. A durable association blocks
	// re-Claim, renewal, recovery and phase replacement even without its
	// private context, before an expired lease or a replay can be considered.
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return model.CapacityIntent{}, err
	}
	// Separate Source-only counterpart: the original production transaction
	// remains exact. Validate immutable signed cleanup INSIDE the same lock.
	if previous == nil || !previous.RecoveryOnly || p.Floor != 2 || p.Ceiling != 2 { return model.CapacityIntent{}, ErrCapacityConflict }
	terminal, err := s.ValidateSourceFailureCleanupTerminalTx(ctx,tx,policy,p,*previous,parentID,now.UTC())
	if err != nil || terminal.ParentGrantID != parentID { return model.CapacityIntent{}, ErrCapacityConflict }
	var authorityWire []byte
	if err=tx.QueryRowContext(ctx,`SELECT authority_wire FROM public.capacity_source_failure_cleanup_originals WHERE parent_grant_id=$1 AND namespace=$2`,parentID,policy.Metadata.Namespace).Scan(&authorityWire);err!=nil{return model.CapacityIntent{},err}
	var authority SourceFailureCleanupAuthority;var body SourceFailureCleanupBody
	if capacity.DecodeGuestLifecycle(authorityWire,&authority)!=nil || decodeSourceFailureCleanupBody(authority.Body,&body)!=nil || body.NativeCase!="source_live_failed_floor_recovery" {return model.CapacityIntent{},ErrCapacityConflict}

	next, receipt, err := mutate(p, previous, now.UTC())
	if err != nil {
		return model.CapacityIntent{}, err
	}
	// Assess constructs a fresh value for a later generation. Elapsed epochs
	// or ordinary policy changes cannot discard an unresolved original window.
	// The private canary methods update this bounded field under the SAME
	// native intent lock; legacy mutations never rewrite or erase it.
	if previous != nil && previous.OriginalNotifyWindow != nil {
		marker := *previous.OriginalNotifyWindow
		if marker.OriginalReturnsObservedAt != nil {
			observedAt := *marker.OriginalReturnsObservedAt
			marker.OriginalReturnsObservedAt = &observedAt
		}
		next.OriginalNotifyWindow = &marker
	}
	if next.Phase != "reconciled_failed_floor" { return model.CapacityIntent{}, ErrCapacityConflict }
	if next.Phase == "reconciled_failed_floor" {
		// Only never-redeemed permissions can expire without remote proof.
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants g SET state='expired',grant_record=jsonb_set(grant_record,'{grant,state}','"expired"'),updated_at=$5 WHERE NOT (grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state='issued' AND expires_at<=$5 AND NOT EXISTS (SELECT 1 FROM public.capacity_factory_original_grant_bindings h WHERE h.grant_id=g.id)`, next.Namespace, p.Environment, p.Domain, p.Dimension, now); err != nil {
			return model.CapacityIntent{}, err
		}
		var unresolved int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT (grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','settled','compensating') AND id<>$5::uuid`, next.Namespace, p.Environment, p.Domain, p.Dimension, terminal.ParentGrantID).Scan(&unresolved); err != nil {
			return model.CapacityIntent{}, err
		}
		if unresolved != 0 {
			return model.CapacityIntent{}, fmt.Errorf("%w: unresolved provider mutation authority", ErrCapacityConflict)
		}
		if next.Phase == "reconciled_partial" || next.Phase == "reconciled_failed_floor" {
			var live, fresh, matchingProfile int
			if err = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE (slot_record->>'observed_at')::timestamptz BETWEEN $5 AND $6),count(*) FILTER(WHERE profile_name=$7) FROM public.capacity_resource_slots WHERE NOT (slot_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, next.Namespace, p.Environment, p.Domain, p.Dimension, now.Add(-time.Duration(p.MaxEvidenceAgeSeconds)*time.Second), now.Add(5*time.Second), next.Assessment.Snapshot.Profile).Scan(&live, &fresh, &matchingProfile); err != nil {
				return model.CapacityIntent{}, err
			}
			if live != next.Assessment.Snapshot.Units || fresh != live || matchingProfile != live {
				return model.CapacityIntent{}, fmt.Errorf("%w: partial recovery inventory does not match fresh immutable native membership", ErrCapacityConflict)
			}
		}
		if next.Phase == "reconciled_failed_floor" {
			var ensured int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT (grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND state='confirmed' AND grant_record->'grant'->>'capability'=grant_record->'binding'->>'ensure_capability'`, next.Namespace, p.Environment, p.Domain, p.Dimension, next.Generation).Scan(&ensured); err != nil {
				return model.CapacityIntent{}, err
			}
			if ensured != 0 {
				return model.CapacityIntent{}, fmt.Errorf("%w: failed floor baseline cannot discard a confirmed serving creation", ErrCapacityConflict)
			}
		}
		if next.Phase == "aborted" {
			var mutations int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT (grant_record ? 'authority_kind') AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND state IN ('confirmed','compensated')`, next.Namespace, p.Environment, p.Domain, p.Dimension, next.Generation).Scan(&mutations); err != nil {
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
	if err = s.attachOriginalHostClaimTx(ctx, tx, next, data); err != nil {
		return model.CapacityIntent{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityIntent{}, err
	}
	*captured=terminal
	if s.hostOriginalClaim != nil {
		s.hostOriginalClaim.committed = true
	}
	return next, nil
}

