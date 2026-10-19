//go:build linux && nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestPG17AfterCreate(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) error {
	rows, err := guestPG17MutationAfterCreate(ctx, store, policy, p, binding, input, grant, pre, proof)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	if err = PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "mutation-create", rows); err != nil {
		return err
	}
	if originalGuestNativeRealm.Request.NativeCase == "positive_original_lifecycle" && input.Slot == 2 {
		httpResult, httpErr := AssertPG17HTTPReturns(ctx, store, policy, grant, pre)
		if httpErr != nil {
			return httpErr
		}
		return PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "http-callback", []PG17AssertionResult{httpResult})
	}
	return nil
}

func guestPG17AfterConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, proof model.CapacityMutationProof) error {
	rows, err := guestPG17MutationAfterConfirm(ctx, store, policy, p, binding, input, grant, proof)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "mutation-confirm", rows)
}

func guestPG17AfterTerminal(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	rows, err := guestPG17MutationAfterTerminal(ctx, store, policy, p, binding, input, grant, pre, output)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "mutation-terminal", rows)
}

func guestPG17AfterHistorical(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	rows, err := guestPG17MutationAfterHistorical(ctx, store, policy, p, binding, input, grant, pre, output)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "mutation-historical", rows)
}

func guestPG17BeforeConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, workflow model.ManifestReference, input guestOriginalStepInput, grant model.CapacityMutationGrant) error {
	if originalGuestNativeRealm == nil || originalGuestNativeRealm.Request.NativeCase != "positive_original_lifecycle" || input.Slot != 2 {
		return nil
	}
	pg17OriginalReadBrokerMu.Lock()
	broker := pg17OriginalReadBroker
	pg17OriginalReadBrokerMu.Unlock()
	if broker == nil {
		return errOriginalGuestStep
	}
	originalInput := map[string]any{"policy": map[string]any{"namespace": policy.Metadata.Namespace, "name": policy.Metadata.Name}, "binding_name": input.BindingName, "generation": input.Generation, "fencing_token": input.FencingToken, "lease_owner": input.LeaseOwner, "grant_id": grant.GrantID}
	result, err := AssertPG17NativeWorkflow(ctx, broker, store, policy, workflow, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.confirm_native_mutation", Status: "failed"}, originalInput, grant)
	if err != nil {
		return err
	}
	return PG17RetainAssertions(ctx, originalGuestNativeRealm, policy, store.WorkflowID.String(), input.Slot, "native-workflow", []PG17AssertionResult{result})
}
