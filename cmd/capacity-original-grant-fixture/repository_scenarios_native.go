//go:build capacitytest && nativequalification

package main

// These independent synthetic repository scenarios preserve the legacy test
// baselines while exercising genuine IssueMutation and RedeemMutation calls in
// the source-identified executable. They never contact a provider or claim a
// Guest enrollment; all proof inputs below are explicit test fixtures.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type repositoryScenario struct {
	input   request
	policy  model.Manifest
	binding model.CapacityMutationBinding
	store   repository.CapacityStore
	issue   model.CapacityMutationIssue
	step    model.WorkflowStepSpec
}

func newRepositoryScenario(ctx context.Context, db *sql.DB, source string) (repositoryScenario, error) {
	var out repositoryScenario
	input, err := prepareSyntheticWithLimits(ctx, db, source, 2, 4, 20, 2, 120)
	if err != nil {
		return out, err
	}
	policy, err := repository.GetManifestByID(ctx, db, input.PolicyID)
	if err != nil {
		return out, err
	}
	workflow, err := repository.GetManifestByID(ctx, db, input.WorkflowID)
	if err != nil {
		return out, err
	}
	binding, step, _, err := approved(policy, workflow, input, source)
	if err != nil {
		return out, err
	}
	var selected *model.CapacityMutationSpecV1
	for _, slot := range binding.Slots {
		if slot.Slot == input.Slot {
			selected = slot.DesiredSpec
		}
	}
	if selected == nil || input.Slot != 5 {
		return out, errors.New("repository approved slot absent")
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return out, err
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, input.NonceSHA256)
	return repositoryScenario{input: input, policy: policy, binding: binding, store: store, issue: model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: raw}, step: step}, nil
}

func (f repositoryScenario) issueGrant(ctx context.Context) (model.CapacityMutationGrant, error) {
	return f.store.IssueMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, f.issue)
}

func (f repositoryScenario) redeem(ctx context.Context, grant model.CapacityMutationGrant, nonce string) (model.CapacityMutationRedeemRequest, error) {
	digest := sha256.Sum256([]byte(nonce))
	req := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: hex.EncodeToString(digest[:]), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
	response, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, req)
	if err != nil || response.Mode != "write_once" {
		return req, errors.New("repository first redemption failed")
	}
	return req, nil
}

func repositoryLostReply(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	grant, err := f.issueGrant(ctx)
	if err != nil {
		return err
	}
	nonce := uuid.NewString()
	req, err := f.redeem(ctx, grant, nonce)
	if err != nil {
		return err
	}
	replay, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, req)
	if err != nil || replay.Mode != "read_only" {
		return errors.New("same attempt replay granted another write")
	}
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: req.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "rejected_before_send", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
		return err
	}
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
		return err
	}
	// A new actual Guest preregistration has its own nonce digest.
	nextNonce := sha256.Sum256([]byte(uuid.NewString()))
	nextStore := f.store.WithOriginalGuestProvisioning(f.step, source, hex.EncodeToString(nextNonce[:]))
	next, err := nextStore.IssueMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, f.issue)
	if err != nil || next.GrantID == grant.GrantID || next.GrantID == "" {
		return errors.New("before-send rejection did not allow a distinct grant")
	}
	return nil
}

func repositoryUnresolved(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	grant, err := f.issueGrant(ctx)
	if err != nil {
		return err
	}
	req, err := f.redeem(ctx, grant, uuid.NewString())
	if err != nil {
		return err
	}
	current, err := f.store.Observe(ctx, f.policy)
	if err != nil {
		return err
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: current.Assessment, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:unresolved-no-provider-send", Healthy: true, Inflight: &zero}
	for _, phase := range []string{"prepared", "canary"} {
		if _, err = f.store.Advance(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, phase, proof); err != nil {
			return err
		}
	}
	proof.Assessment.Snapshot.Units = current.Decision.Units
	if _, err = f.store.Advance(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, "promoted", proof); !errors.Is(err, repository.ErrCapacityConflict) || !strings.Contains(err.Error(), "unresolved provider mutation authority") {
		return errors.New("unresolved authority did not trigger its specific promotion hold")
	}
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, grant.GrantID); err != nil {
		return err
	}
	replay, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, req)
	if err != nil || replay.Mode != "read_only" {
		return errors.New("expired redeemed attempt authorized another write")
	}
	var state string
	if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID).Scan(&state); err != nil || state != "redeemed" {
		return errors.New("expired redeemed state changed")
	}
	return nil
}

func repositoryNativeConfirmation(ctx context.Context, db *sql.DB, source string) error {
	f, err := newRepositoryScenario(ctx, db, source)
	if err != nil {
		return err
	}
	grant, err := f.issueGrant(ctx)
	if err != nil {
		return err
	}
	nonce := uuid.NewString()
	req, err := f.redeem(ctx, grant, nonce)
	if err != nil {
		return err
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	proof := model.CapacityMutationProof{BindingName: f.binding.Name, Slot: grant.Slot, GrantID: grant.GrantID, RequestSHA256: grant.RequestSHA256, ResourceID: "synthetic-resource", ResourceCreatedAt: created, ObservedCreationGrantID: grant.GrantID, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:no-provider-read", OwnerVerified: true, SpecVerified: true, ActionsTerminal: true, ActionsSuccessful: true, ActionIDs: []string{"synthetic-action", "synthetic-next-action"}}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, proof); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.New("native read replaced required settlement")
	}
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: req.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: proof.ResourceID, ResourceCreatedAt: created, ActionID: "synthetic-action", NextActionIDs: []string{"synthetic-next-action"}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
		return err
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+grant.GrantID).Scan(&count); err != nil || count != 0 {
		return errors.New("settlement emitted a premature event")
	}
	incomplete := proof
	incomplete.ActionIDs = []string{"synthetic-action"}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, incomplete); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.New("incomplete action history accepted")
	}
	wrong := proof
	wrong.ResourceID = "synthetic-replacement"
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, wrong); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.New("replacement identity accepted")
	}
	for _, wrongID := range []string{"", uuid.NewString()} {
		wrong = proof
		wrong.ObservedCreationGrantID = wrongID
		if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, wrong); !errors.Is(err, repository.ErrCapacityConflict) {
			return errors.New("wrong creation grant accepted")
		}
	}
	result, err := f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, proof)
	if err != nil || result.State != "confirmed" {
		return errors.New("native confirmation failed")
	}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.input.Generation, f.input.Fence, f.input.LeaseOwner, proof); err != nil {
		return errors.New("native confirmation replay failed")
	}
	var typ, aggregate, resource, instance string
	if err = db.QueryRowContext(ctx, `SELECT type,aggregate_type,payload->>'resource_id',payload->>'instance_id' FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+grant.GrantID).Scan(&typ, &aggregate, &resource, &instance); err != nil || typ != "native-qemu.server.ensured" || aggregate != "native-qemu_server" || resource != proof.ResourceID || instance != f.binding.IntegrationInstanceID {
		return errors.New("canonical event mismatch")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+grant.GrantID).Scan(&count); err != nil || count != 1 {
		return errors.New("duplicate canonical event")
	}
	return nil
}
