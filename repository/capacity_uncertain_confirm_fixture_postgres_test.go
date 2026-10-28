//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test-only signed fixture: the ambiguous transport stays uncertain and no
// provider response, source-owned witness, or physical Guest is claimed.
func TestRecoveryFixtureUnanchoredUncertainCreateCannotConfirmPostgres(t *testing.T) {
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
	forged := f.store
	forged.hostOriginalOrdinary = &hostOriginalOrdinaryFactory{}
	if _, err = forged.ConfirmMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrHostFactoryHold) {
		t.Fatal("unverified host source bypassed guard", err)
	}
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

// This synthetic accepted response is separate from the unknown-response case.
func TestRecoveryFixtureAcceptedCreateStillConfirmsPostgres(t *testing.T) {
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
	instant := time.Now().UTC().Format(time.RFC3339Nano)
	settlement.ResourceID, settlement.ResourceCreatedAt, settlement.ObservedAt = "123", instant, instant
	settlement.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: f.binding.OriginalProviderSourceCommit, GrantID: parent.GrantID, AttemptID: redemption.AttemptID, RequestSHA256: parent.RequestSHA256, ResourceID: settlement.ResourceID, ResourceCreatedAt: instant, ActionID: settlement.ActionID, NextActionIDs: settlement.NextActionIDs, CalledAt: instant, ReturnedAt: instant, ContextDeadline: parent.ExpiresAt.UTC().Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 100}
	if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settlement); err != nil {
		t.Fatal(err)
	}
	proof := f.proof(t, 3)
	proof.GrantID, proof.ObservedCreationGrantID = parent.GrantID, parent.GrantID
	proof.ResourceID, proof.ResourceCreatedAt = settlement.ResourceID, settlement.ResourceCreatedAt
	proof.ObservedAt = time.Now().UTC()
	proof.ActionsTerminal, proof.ActionsSuccessful = true, true
	proof.ActionIDs = append([]string{settlement.ActionID}, settlement.NextActionIDs...)
	confirmed, err := f.store.ConfirmMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, proof)
	if err != nil || confirmed.State != "confirmed" {
		t.Fatal("accepted create did not confirm", err)
	}
}

// Fixture-only historical row checks exact replay; it is not an issued or
// confirmed production authority and cannot be selected in a normal build.
func TestRecoveryFixtureHistoricalConfirmedReplayPostgres(t *testing.T) {
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
	proof.ActionIDs = []string{"historical-action"}
	var raw []byte
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, parent.GrantID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record capacityMutationRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Grant.State = "confirmed"
	record.Proof = &proof
	raw, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state='confirmed',grant_record=$2::jsonb WHERE id=$1`, parent.GrantID, string(raw)); err != nil {
		t.Fatal(err)
	}
	replay, err := f.store.ConfirmMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, proof)
	if err != nil || replay.State != "confirmed" || replay.GrantID != parent.GrantID {
		t.Fatal("exact historical replay refused", err)
	}
	changed := proof
	changed.ActionIDs = []string{"different-action"}
	if _, err = f.store.ConfirmMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, changed); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("changed historical proof admitted", err)
	}
}
