//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test-only signed fixture: the ambiguous transport stays uncertain and no
// provider response, source-owned witness, or physical Guest is claimed.
func TestUnanchoredUncertainCreateCannotConfirmPostgres(t *testing.T) {
	f := syntheticFailedFloorSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	parent, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[3])
	if err != nil {
		t.Fatal(err)
	}
	nonce := uuid.NewString()
	redemption := mutationRedeem(parent, nonce)
	if _, err = f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redemption); err != nil {
		t.Fatal(err)
	}
	settlement := mutationSettlement(redemption, f.created)
	settlement.Outcome, settlement.ResourceID, settlement.ResourceCreatedAt, settlement.ActionID = "uncertain", "", "", ""
	settlement.NextActionIDs, settlement.AuxiliaryResources, settlement.AuxiliaryInventoryComplete = nil, nil, false
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settlement); err != nil {
		t.Fatal(err)
	}
	proof := f.proof(t, 3)
	proof.GrantID, proof.ObservedCreationGrantID = parent.GrantID, parent.GrantID
	proof.ResourceID, proof.ResourceCreatedAt = "123", time.Now().UTC().Format(time.RFC3339Nano)
	proof.ObservedAt = time.Now().UTC()
	proof.ActionsTerminal, proof.ActionsSuccessful = true, true
	proof.ActionIDs = []string{"unrelated-action"}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrCapacityConflict) {
		t.Fatalf("unanchored uncertain create confirmed or wrong refusal: %v", err)
	}
	receipt, err := f.store.MutationReceipt(ctx, f.binding.AdapterPrincipalID, parent.GrantID)
	if err != nil || receipt.Grant.State != "settled" || receipt.Outcome != "uncertain" || receipt.ResourceID != "" || receipt.ActionID != "" {
		t.Fatal("uncertain original changed", err)
	}
	var count int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=3 AND resource_id<>''`, f.policy.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
		t.Fatal("unanchored proof changed membership", err)
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+parent.GrantID, f.policy.Metadata.Namespace).Scan(&count); err != nil || count != 0 {
		t.Fatal("unanchored proof emitted event", err)
	}
}
