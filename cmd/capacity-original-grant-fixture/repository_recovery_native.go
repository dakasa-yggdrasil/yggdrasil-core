//go:build capacitytest && nativequalification

package main

// These source-owned tests use actual grant issuance/redeeming and explicit
// synthetic native readbacks on an isolated database. No Guest or provider
// operation is claimed. SQL changes age test clocks only, never grant state.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func (f repositoryScenario) freshAssessment(ctx context.Context, units int) (model.CapacityAssessment, error) {
	current, err := f.store.Observe(ctx, f.policy)
	if err != nil {
		return model.CapacityAssessment{}, err
	}
	a := current.Assessment
	now := time.Now().UTC()
	a.Snapshot.Units = units
	a.Snapshot.ObservedAt = now
	a.Evidence = append([]model.CapacityEvidence(nil), a.Evidence...)
	for i := range a.Evidence {
		a.Evidence[i].SourceSampledAt = now
		a.Evidence[i].WindowEnd = now
		a.Evidence[i].WindowStart = now.Add(-time.Minute)
	}
	return a, nil
}

func (f repositoryScenario) expireLease(ctx context.Context) error {
	result, err := f.store.DB.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("isolated lease expiry affected wrong count")
	}
	return nil
}

func repositoryPausedUnredeemed(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	g, err := f.issueGrant(ctx)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, g.GrantID); err != nil {
		return err
	}
	if err = f.expireLease(ctx); err != nil {
		return err
	}
	assessment, err := f.freshAssessment(ctx, 4)
	if err != nil {
		return err
	}
	recovery := f.store
	recovery.ExecutionEnabled = false
	recovery.ExecutorID = uuid.NewString()
	lease, err := recovery.Recover(ctx, f.policy, f.input.Generation, assessment)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:never-redeemed", Healthy: true, Inflight: &zero, MutationInflight: &zero, NoMutationVerified: true, MutationAuthorityKind: "core_mutation_grants"}
	result, err := recovery.Reconcile(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, "aborted", proof)
	if err != nil || result.Phase != "aborted" {
		return fmt.Errorf("unredeemed abort did not reconcile: %w", err)
	}
	var state string
	if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&state); err != nil || state != "expired" {
		return errors.New("unredeemed grant did not expire")
	}
	return nil
}

func (f repositoryScenario) settledProof(ctx context.Context) (model.CapacityMutationGrant, model.CapacityMutationProof, error) {
	g, err := f.issueGrant(ctx)
	if err != nil {
		return g, model.CapacityMutationProof{}, err
	}
	nonce := uuid.NewString()
	req, err := f.redeem(ctx, g, nonce)
	if err != nil {
		return g, model.CapacityMutationProof{}, err
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	settle := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: req.AttemptID, RequestSHA256: g.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: "synthetic-recovery-slot-5", ResourceCreatedAt: created, ActionID: "synthetic-native-action", NextActionIDs: []string{"synthetic-bootstrap-action"}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
		return g, model.CapacityMutationProof{}, err
	}
	proof := model.CapacityMutationProof{BindingName: f.binding.Name, Slot: g.Slot, GrantID: g.GrantID, RequestSHA256: g.RequestSHA256, ResourceID: settle.ResourceID, ResourceCreatedAt: created, ObservedCreationGrantID: g.GrantID, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:recovery-not-native", OwnerVerified: true, SpecVerified: true, ActionsTerminal: true, ActionsSuccessful: true, ActionIDs: []string{settle.ActionID, settle.NextActionIDs[0]}}
	return g, proof, nil
}

func repositoryHistoricalRecovery(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	g, proof, err := f.settledProof(ctx)
	if err != nil {
		return err
	}
	if err = f.expireLease(ctx); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, f.policy.ID); err != nil {
		return err
	}
	assessment, err := f.freshAssessment(ctx, 4)
	if err != nil {
		return err
	}
	recovery := f.store
	recovery.ExecutionEnabled = false
	recovery.ExecutorID = uuid.NewString()
	lease, err := recovery.Recover(ctx, f.policy, f.input.Generation, assessment)
	if err != nil {
		return fmt.Errorf("historical recover: %w", err)
	}
	result, err := recovery.ConfirmMutation(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, proof)
	if err != nil || result.GrantID != g.GrantID || result.State != "confirmed" {
		return fmt.Errorf("historical confirm: %w", err)
	}
	return nil
}

func (f repositoryScenario) slotIssueProof(ctx context.Context, slot int) (model.CapacityMutationIssue, model.CapacityMutationProof, error) {
	for _, candidate := range f.binding.Slots {
		if candidate.Slot != slot {
			continue
		}
		raw, err := json.Marshal(candidate.DesiredSpec)
		if err != nil {
			return model.CapacityMutationIssue{}, model.CapacityMutationProof{}, err
		}
		var resource, created string
		err = f.store.DB.QueryRowContext(ctx, `SELECT slot_record->>'resource_id',slot_record->>'resource_created_at' FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4`, f.binding.IntegrationInstanceID, f.binding.ScopeChecksum, f.binding.ProfileName, slot).Scan(&resource, &created)
		if err != nil {
			return model.CapacityMutationIssue{}, model.CapacityMutationProof{}, err
		}
		return model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: raw}, model.CapacityMutationProof{BindingName: f.binding.Name, Slot: slot, ResourceID: resource, ResourceCreatedAt: created, RequestSHA256: candidate.DesiredSpecSHA256, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:recovery-membership", OwnerVerified: true, SpecVerified: true}, nil
	}
	return model.CapacityMutationIssue{}, model.CapacityMutationProof{}, errors.New("slot not approved")
}

func (f repositoryScenario) issueForSlot(slot int) (model.CapacityMutationIssue, error) {
	for _, candidate := range f.binding.Slots {
		if candidate.Slot == slot {
			raw, err := json.Marshal(candidate.DesiredSpec)
			return model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: raw}, err
		}
	}
	return model.CapacityMutationIssue{}, errors.New("slot not approved")
}

func repositoryPartialRecovery(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	_, native, err := f.settledProof(ctx)
	if err != nil {
		return err
	}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, native); err != nil {
		return fmt.Errorf("initial confirmation: %w", err)
	}
	issue6, err := f.issueForSlot(6)
	if err != nil {
		return err
	}
	// Each original issue has a unique source-owned preregistration nonce.
	nonce := capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
	nextStore := f.store.WithOriginalGuestProvisioning(f.step, source, nonce)
	unsent, err := nextStore.IssueMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, issue6)
	if err != nil {
		return fmt.Errorf("second issue: %w", err)
	}
	if err = f.expireLease(ctx); err != nil {
		return err
	}
	assessment, err := f.freshAssessment(ctx, 5)
	if err != nil {
		return err
	}
	recovery := f.store
	recovery.ExecutionEnabled = false
	recovery.ExecutorID = uuid.NewString()
	lease, err := recovery.Recover(ctx, f.policy, f.input.Generation, assessment)
	if err != nil {
		return fmt.Errorf("partial recover: %w", err)
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:complete-partial-inventory", Healthy: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true}
	if _, err = recovery.Reconcile(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof); !errors.Is(err, repository.ErrCapacityConflict) || !strings.Contains(err.Error(), "unresolved provider mutation authority") {
		return errors.New("outstanding permission did not hold partial recovery")
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, unsent.GrantID); err != nil {
		return err
	}
	for _, scenario := range []string{"incomplete", "wrong_count", "outside_change", "no_mutation", "provider_fence"} {
		bad := proof
		switch scenario {
		case "incomplete":
			bad.MembershipComplete = false
		case "wrong_count":
			bad.Assessment.Snapshot.Units = 4
		case "outside_change":
			bad.Assessment.Snapshot.Units = 7
		case "no_mutation":
			bad.NoMutationVerified = true
		case "provider_fence":
			bad.ProviderFencingToken = lease.FencingToken
		}
		if _, err = recovery.Reconcile(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", bad); err == nil {
			return fmt.Errorf("unsafe partial proof accepted: %s", scenario)
		}
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_resource_slots SET slot_record=jsonb_set(slot_record,'{observed_at}',to_jsonb($2::text)) WHERE namespace=$1 AND slot=1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err = recovery.Reconcile(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof); !errors.Is(err, repository.ErrCapacityConflict) || !strings.Contains(err.Error(), "partial recovery inventory does not match fresh immutable native membership") {
		return errors.New("stale membership did not reach intended hold")
	}
	issue7, err := f.issueForSlot(7)
	if err != nil {
		return err
	}
	bogus := native
	bogus.Slot = 7
	bogus.GrantID = ""
	bogus.ResourceID = "synthetic-no-existing-slot"
	bogus.ObservedCreationGrantID = ""
	if err = recovery.RecordMutationSlot(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, issue7, bogus); err == nil {
		return errors.New("recovery registered an unobserved slot")
	}
	for slot := 1; slot <= 5; slot++ {
		issue, observed, e := f.slotIssueProof(ctx, slot)
		if e != nil {
			return e
		}
		if e = recovery.RecordMutationSlot(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, issue, observed); e != nil {
			return fmt.Errorf("refresh member %d: %w", slot, e)
		}
	}
	assessment, err = f.freshAssessment(ctx, 5)
	if err != nil {
		return err
	}
	proof.Assessment = assessment
	proof.ObservedAt = time.Now().UTC()
	partial, err := recovery.Reconcile(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof)
	if err != nil || partial.Phase != "reconciled_partial" || partial.Assessment.Snapshot.Units != 5 || partial.LeaseOwner != "" || partial.Decision.ExecutionPermitted {
		return fmt.Errorf("partial reconciliation: %w", err)
	}
	if _, err = recovery.RenewRecovery(ctx, f.policy, f.input.Generation, lease.FencingToken, lease.LeaseOwner); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.New("terminal partial recovery retained authority")
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{decision,clock,last_action_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	assessment, err = f.freshAssessment(ctx, 5)
	if err != nil {
		return err
	}
	next, err := f.store.Assess(ctx, f.policy, assessment)
	if err != nil || next.Generation != 2 || next.Phase != "proposed" || next.Decision.Units != 7 {
		return fmt.Errorf("next assessment after partial: %w", err)
	}
	return nil
}

func repositoryAuthorityFences(ctx context.Context, db *sql.DB, source string) error {
	for _, target := range []string{"policy", "instance", "type", "executor"} {
		f, err := newRepositoryScenario(ctx, db, source)
		if err != nil {
			return err
		}
		grant, err := f.issueGrant(ctx)
		if err != nil {
			return err
		}
		nonce := uuid.NewString()
		digest := sha256.Sum256([]byte(nonce))
		req := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: hex.EncodeToString(digest[:]), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
		id := f.policy.ID.String()
		if target == "instance" {
			id = f.binding.IntegrationInstanceID
		}
		if target == "type" {
			id = f.binding.IntegrationTypeID
		}
		if target == "executor" {
			if _, err = db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_executor_id}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, uuid.NewString()); err != nil {
				return err
			}
		} else {
			if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, id); err != nil {
				return err
			}
		}
		response, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, req)
		want := repository.ErrCapacityConflict
		if target == "policy" {
			want = repository.ErrCapacityDisabled
		}
		if target == "executor" {
			want = repository.ErrCapacityLease
		}
		if !errors.Is(err, want) || response.Mode != "read_only" {
			return fmt.Errorf("%s fence did not reach expected refusal: %w", target, err)
		}
		var state string
		if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&state); err != nil || state != "issued" {
			return errors.New("refused fence changed original grant")
		}
		if target == "executor" {
			if _, err = db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_executor_id}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, f.input.ExecutorID); err != nil {
				return err
			}
		} else {
			if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=true WHERE id=$1`, id); err != nil {
				return err
			}
		}
		response, err = f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, req)
		if err != nil || response.Mode != "write_once" {
			return fmt.Errorf("%s restored control failed: %w", target, err)
		}
	}
	return nil
}
