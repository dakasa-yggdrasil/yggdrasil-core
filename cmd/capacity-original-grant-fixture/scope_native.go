//go:build capacitytest && nativequalification

package main

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

// syntheticSettlementScope exercises actual issue/redeem and callback storage
// using invented data on the verified isolated database. No provider is called.
func syntheticSettlementScope(ctx context.Context, db *sql.DB, source string, repositoryScenario bool) error {
	var input request
	var err error
	if repositoryScenario {
		input, err = prepareSyntheticWithLimits(ctx, db, source, 2, 4, 20, 2, 120)
	} else {
		input, err = prepareSynthetic(ctx, db, source)
	}
	if err != nil {
		return err
	}
	policy, err := repository.GetManifestByID(ctx, db, input.PolicyID)
	if err != nil {
		return err
	}
	workflow, err := repository.GetManifestByID(ctx, db, input.WorkflowID)
	if err != nil {
		return err
	}
	binding, step, _, err := approved(policy, workflow, input, source)
	if err != nil {
		return err
	}
	var selected *model.CapacityMutationSpecV1
	for _, slot := range binding.Slots {
		if slot.Slot == input.Slot {
			selected = slot.DesiredSpec
		}
	}
	if selected == nil {
		return errors.New("synthetic slot missing")
	}
	spec, err := json.Marshal(selected)
	if err != nil {
		return err
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, input.NonceSHA256)
	grant, err := store.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: spec})
	if err != nil {
		return err
	}
	nonce := uuid.NewString()
	digest := sha256.Sum256([]byte(nonce))
	redeem := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: hex.EncodeToString(digest[:]), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
	permission, err := store.RedeemMutation(ctx, binding.AdapterPrincipalID, redeem)
	if err != nil || permission.Mode != "write_once" {
		return errors.New("synthetic original redemption failed")
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: redeem.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: "synthetic-resource-scope", ResourceCreatedAt: created, ActionID: "synthetic-action-scope", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err = store.SettleMutation(ctx, "foreign-principal", nonce, settle); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return errors.New("foreign settlement principal accepted")
	}
	if _, err = store.SettleMutation(ctx, binding.AdapterPrincipalID, uuid.NewString(), settle); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return errors.New("wrong settlement nonce accepted")
	}
	paused := store
	paused.ExecutionEnabled = false
	if _, err = paused.SettleMutation(ctx, binding.AdapterPrincipalID, nonce, settle); err != nil {
		return errors.New("paused process lost settlement receipt")
	}
	receipt, err := paused.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
	if err != nil || receipt.ResourceID != settle.ResourceID || receipt.ActionID != settle.ActionID || !receipt.TransportCompleted {
		return errors.New("settlement receipt differs")
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	for _, private := range []string{nonce, redeem.SettlementTokenSHA256, input.LeaseOwner, input.ExecutorID} {
		if strings.Contains(string(wire), private) {
			return errors.New("settlement receipt exposed private authority")
		}
	}
	if _, err = paused.MutationReceipt(ctx, "foreign-principal", grant.GrantID); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return errors.New("foreign principal observed private receipt")
	}
	settle.ActionID = "synthetic-different-action"
	if _, err = paused.SettleMutation(ctx, binding.AdapterPrincipalID, nonce, settle); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.New("conflicting settlement replaced original")
	}
	return nil
}
