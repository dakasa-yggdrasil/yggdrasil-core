//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// The ONLY transport in this integration test is declared signed fixture data.
// The real store, source graph, PG locks/FKs/triggers and grant callbacks run in
// CI. This supplies no provider execution, actual Guest or clean-cycle credit.
func cleanupNativeInventory(t *testing.T, f *FailedExpansionCleanupRecoveryFixture, a FailedUnwitnessedExpansionCleanup, target bool) model.CapacityVMFleetInventory {
	t.Helper()
	inv := capacity.RecoveryFixtureInventory(t, f.Spec, f.private.reg, time.Now().UTC())
	if target {
		m := inv.Members[0]
		m.Slot = 2
		m.Protected = false
		m.DesiredSpec = *f.Spec.MutationBindings[0].Slots[1].DesiredSpec
		m.RequestSHA256 = f.Spec.MutationBindings[0].Slots[1].DesiredSpecSHA256
		m.Server.ID = a.ResourceID
		m.Server.CreatedAt = a.ResourceCreatedAt
		m.Server.Name = m.DesiredSpec.NativeName
		m.Server.Labels = map[string]string{}
		for k, v := range inv.Members[0].Server.Labels {
			m.Server.Labels[k] = v
		}
		m.Server.Labels["yggdrasil.io/slot"] = "2"
		m.Server.Labels["yggdrasil.io/intent"] = a.GrantID
		inv.Members = append(inv.Members, m)
		inv.MissingSlots = []int{3, 4, 5, 6, 7, 8}
	}
	return inv
}
func cleanupNativeHTTP(t *testing.T, value any, at time.Time) capacity.GuestOriginalHTTPReturn {
	raw := failedServingWire(t, value)
	sha := capacity.BusinessCreationSHA256(raw)
	return capacity.GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Millisecond), DoReturnedAt: at.Add(51 * time.Millisecond), ReadReturnedAt: at.Add(52 * time.Millisecond), CloseReturnedAt: at.Add(53 * time.Millisecond), DriverReturnedAt: at.Add(54 * time.Millisecond), Status: 200, Body: raw, ReceivedBodyBytes: len(raw), ResponseSHA256: sha, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(raw), RetainedPrefixSHA256: sha}
}
func cleanupNativeCanaries(t *testing.T, f *FailedExpansionCleanupRecoveryFixture, store CapacityStore, current model.CapacityIntent, usage string) {
	t.Helper()
	waitCtx, stopWait := context.WithTimeout(context.Background(), 7*time.Second)
	delay, err := store.FailedExpansionPublicationDelay(waitCtx, f.Policy, f.private.pre.PreregistrationID)
	if err != nil || delay > 6*time.Second {
		stopWait()
		t.Fatal("actual bounded PG publication gap", delay, err)
	}
	if delay > 0 {
		timer := time.NewTimer(delay + time.Millisecond)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			stopWait()
			t.Fatal("original PG gap wait", waitCtx.Err())
		case <-timer.C:
		}
	}
	stopWait()
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	key := failedServingKey('c')
	e := f.private.receipt.Enrollment
	members, err := store.GuestNotifyFloorMembers(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, 2)
	if err != nil || len(members) != 1 || members[0].Slot != 1 {
		t.Fatal("actual onlyS1 floor selection with desiredN2 retained", members, err)
	}
	probe := func(c model.CapacityGuestNotifyCanaryChallenge, pub *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		c = capacity.RecoveryFixtureCanaryNonce(t, c, e)
		at := time.Now().UTC()
		nonceReturn := cleanupNativeHTTP(t, c.GuestNonce, at)
		if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, nonceReturn); err != nil {
			t.Fatal(err)
		}
		if err := store.ReserveGuestNotifyCanarySend(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c); err != nil {
			t.Fatal(err)
		}
		response, facts := capacity.RecoveryFixtureCanaryResponse(t, f.Spec, c, e, pub)
		returned := cleanupNativeHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		time.Sleep(max(0, time.Until(returned.DriverReturnedAt)) + time.Millisecond)
		if _, err := store.RecordGuestNotifyCanaryReturn(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, returned); err != nil {
			t.Fatal("real source-owned survivor return", err)
		}
		return facts
	}
	pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, key)
	if err != nil {
		t.Fatal(err)
	}
	facts := probe(pub, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, pub.ChallengeID, key)
	if err != nil {
		t.Fatal(err)
	}
	probe(read, facts)
}
func cleanupNativeReturn(t *testing.T, c FailedExpansionRead) FailedExpansionReadReturn {
	at := time.Now().UTC()
	return FailedExpansionReadReturn{Schema: "failed_unwitnessed_expansion_native_return_v1", Read: c, ReadWire: failedServingWire(t, c), StartedAtCore: at, ReturnedAtCore: at}
}
func cleanupNativeInventoryReturn(t *testing.T, f *FailedExpansionCleanupRecoveryFixture, a FailedUnwitnessedExpansionCleanup, c FailedExpansionRead) FailedExpansionReadReturn {
	r := cleanupNativeReturn(t, c)
	r.Status = "dry_run"
	plan, err := failedExpansionDestroyPlan(f.Spec, a)
	if err != nil {
		t.Fatal(err)
	}
	inventory := cleanupNativeInventory(t, f, a, true)
	server := inventory.Members[1].Server
	var desired model.CapacityMutationSpecV1
	if json.Unmarshal(plan.CanonicalSpec, &desired) != nil {
		t.Fatal("canonical exact destroy projection")
	}
	r.Plan = &model.CapacityVMFleetPlan{DesiredSpec: desired, RequestSHA256: plan.RequestSHA256, Server: &server, ObservedAt: r.ReturnedAtCore.Format(time.RFC3339Nano)}
	return r
}
func cleanupNativeAbsenceReturn(t *testing.T, c FailedExpansionRead, receipt model.CapacityMutationReceipt, pending bool) FailedExpansionReadReturn {
	r := cleanupNativeReturn(t, c)
	r.Status = "observed"
	r.Receipt = &receipt
	r.ReceiptWire = failedServingWire(t, receipt)
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	o := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: receipt.ResourceID, CreatedAt: receipt.ResourceCreatedAt}, DestroyGrantID: receipt.Grant.GrantID, DestroyGrantState: receipt.Grant.State, OriginalOutcome: receipt.Outcome, OriginalTransportCompleted: receipt.TransportCompleted, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: stamp, NextActions: []model.CapacityVMActionObservation{}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: stamp, ObservedAt: stamp, AWSRetirementLifecycle: &model.CapacityAWSRetirementLifecycle{Schema: "aws_original_terminate_and_native_absence_v1", RequestID: receipt.ActionID, EC2State: "terminated", ObservedAt: at}}
	for _, aux := range receipt.AuxiliaryResources {
		o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: aux.Kind, ID: aux.ID, Absent: true, ObservedAt: stamp})
	}
	if pending {
		o.BillableResourcesAbsent = false
		o.RetirementComplete = false
		o.HoldReasons = []string{"aws_network_interface_still_present"}
		for n := range o.AuxiliaryResources {
			if o.AuxiliaryResources[n].Kind == "aws_network_interface" {
				o.AuxiliaryResources[n].Absent = false
			}
		}
	}
	r.Observation = &o
	r.ObserverSourceCommit = RetirementReadonlyAWSObserverSource()
	r.OriginalObserverReturn = failedServingWire(t, GuestRetirementReadonlyReturn{Schema: GuestRetirementReadonlyReturnSchema, ObserverSourceCommit: r.ObserverSourceCommit, OriginalAdapterSourceCommit: enrolledFailedAWSCreator, ReadID: c.ReadID, ReadSHA256: capacity.GuestRetirementSHA(c), OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), Observation: o})
	r.ReturnedAtCore = at
	return r
}
func cleanupNativeSettle(t *testing.T, f *FailedExpansionCleanupRecoveryFixture, ctx context.Context, store CapacityStore, grant model.CapacityMutationGrant) model.CapacityMutationReceipt {
	t.Helper()
	callback := CapacityStore{DB: f.DB, ExecutionEnabled: true}
	b := f.Spec.MutationBindings[0]
	nonce := uuid.NewString()
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256, ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce))}
	permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, request)
	if err != nil || permit.Mode != "write_once" || permit.CompensationOf != "" {
		t.Fatal("real normal destroy single redemption", permit, err)
	}
	again, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, request)
	if err == nil && again.Mode == "write_once" {
		t.Fatal("second native write permit")
	}
	at := time.Now().UTC()
	stamp := at.Format(time.RFC3339Nano)
	action := uuid.NewString()
	body := []byte("DECLARED-SDK-HTTP200-no-production-execution")
	settled := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: request.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: action, NextActionIDs: []string{}, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-00000000000000456", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-00000000000000456", RequiresAbsence: true}}, AuxiliaryInventoryComplete: true, ObservedAt: stamp, OriginalProviderDestroyReturn: &model.CapacityOriginalProviderDestroyReturn{Schema: "aws_original_terminate_instances_return_v1", Provider: "aws", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: grant.GrantID, AttemptID: request.AttemptID, RequestSHA256: grant.RequestSHA256, ResourceID: grant.ExpectedResourceID, ResourceCreatedAt: grant.ExpectedResourceCreatedAt, ActionID: action, NextActionIDs: []string{}, CalledAt: stamp, ReturnedAt: stamp, ContextDeadline: at.Add(5 * time.Second).Format(time.RFC3339Nano), ResponseStatus: 200, ResponseBodySHA256: capacity.BusinessCreationSHA256(body), ResponseBytes: int64(len(body))}}
	if _, err = callback.SettleMutation(ctx, b.AdapterPrincipalID, nonce, settled); err != nil {
		t.Fatal("real sealed child AUX2 settlement", err)
	}
	receipt, found, err := store.FailedExpansionDestroyReceipt(ctx, f.Policy)
	if err != nil || !found || receipt.Grant.State != "settled" {
		t.Fatal("child receipt custody", err)
	}
	return receipt
}

func TestFailedUnwitnessedExpansionCleanupPostgresWholeLifecycle(t *testing.T) {
	for _, firstRead := range []string{"pending", "complete_before_canary"} {
		t.Run(firstRead, func(t *testing.T) {
			f := NewFailedExpansionCleanupRecoveryFixture(t)
			ctx, stop := context.WithTimeout(context.Background(), 60*time.Second)
			defer stop()
			original := failedCleanupTestOriginal(t, f.DB, f.GrantID)
			admission, err := f.AdmissionSourceStore.RequestFailedUnwitnessedExpansionCleanup(ctx, f.GrantID, f.JobID, "collaborator:"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			initialLedger := failedCleanupTestLedger(t, f.DB, admission)
			_, current, a, handled, err := f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy)
			if err != nil || !handled {
				t.Fatal("genuine scheduler claim", err)
			}
			store, _, handled, err := f.RetirementStore().BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
			if err != nil || !handled {
				t.Fatal(err)
			}
			if current.Decision.Units != 2 || current.BaselineSnapshot.Units != 1 {
				t.Fatal("failed desiredN2 or realN1 rewritten")
			}
			inv := cleanupNativeInventory(t, f, a, true)
			if err = store.RefreshFailedExpansionSurvivors(ctx, f.Policy, inv); err != nil {
				t.Fatal("exact survivor-only native refresh", err)
			}
			for _, usage := range []string{"initial_useful_membership", "steady_useful_membership"} {
				if _, err = store.IssueGuestNotifyCanaryPublication(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, f.private.pre.PreregistrationID, usage, failedServingKey('c')); !errors.Is(err, ErrCapacityConflict) {
					t.Fatal("cleanup acquired unrelated canary authority", usage, err)
				}
			}
			cleanupNativeCanaries(t, f, store, current, "before_retirement_floor")
			read, err := store.PrepareFailedExpansionRead(ctx, f.Policy, "inventory")
			if err != nil {
				t.Fatal(err)
			}
			if _, pending, err := store.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeInventoryReturn(t, f, a, read)); err != nil || pending {
				t.Fatal("declared canonical c34 owned-attached dry_run", err)
			}
			grant, err := store.IssueFailedExpansionDestroy(ctx, f.Policy)
			if err != nil || grant.CompensationOf != "" || grant.GrantID != a.ChildGrantID || grant.GrantID == a.GrantID {
				t.Fatal("one private-linked NORMAL destroy", grant, err)
			}
			if _, err = store.IssueFailedExpansionDestroy(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("second child issue", err)
			}
			if !reflect.DeepEqual(original, failedCleanupTestOriginal(t, f.DB, f.GrantID)) {
				t.Fatal("original SDK/settlement altered before cleanup")
			}
			if _, err = store.PrepareFailedExpansionRead(ctx, f.Policy, "absence"); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("unknown issued child invented settled absence", err)
			}
			if err = store.MarkFailedExpansionPossibleSend(ctx, f.Policy); err != nil {
				t.Fatal(err)
			}
			if err = store.MarkFailedExpansionPossibleSend(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("possible-send replay", err)
			}
			receipt := cleanupNativeSettle(t, f, ctx, store, grant)
			finish, _, _, err := f.FinishStore().BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
			if err != nil {
				t.Fatal(err)
			}
			read, err = finish.PrepareFailedExpansionRead(ctx, f.Policy, "absence")
			if err != nil {
				t.Fatal(err)
			}
			if proof, pending, err := finish.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeAbsenceReturn(t, read, receipt, firstRead == "pending")); err != nil || pending != (firstRead == "pending") || proof.ResourceAbsent != (firstRead != "pending") {
				t.Fatal("paid ENI Pending may only read, never complete", pending, err)
			}
			if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("pending paid resource completed", err)
			}
			// Close this declared failed read-only owner using the real dispatch
			// finalizer, then wait its ORIGINAL finite lease. No clock is rewritten.
			var owningJobID uuid.UUID
			if err = f.DB.QueryRow(`SELECT id FROM public.capacity_dispatch_jobs WHERE run_id=$1`, f.store.OriginalRunID).Scan(&owningJobID); err != nil {
				t.Fatal(err)
			}
			tx, err := f.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			job, err := readCapacityDispatchJob(ctx, tx, owningJobID, false)
			_ = tx.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			returned := time.Now().UTC()
			response := model.RunWorkflowResponse{Workflow: model.ManifestReference{ID: f.Workflow.ID, Kind: "workflow", Namespace: f.Workflow.Metadata.Namespace, Name: f.Workflow.Metadata.Name, Version: f.Workflow.Version}, Status: "failed", StartedAt: *job.StartedAt, FinishedAt: returned}
			if err = FinishCapacityDispatch(ctx, f.DB, job, response, returned, errors.New("DECLARED-only original read ended Pending")); err != nil {
				t.Fatal("real failed owner ACK", err)
			}
			if _, _, _, _, err = f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityLease) {
				t.Fatal("new owner reminted before natural expiry", err)
			}
			time.Sleep(max(0, time.Until(*current.LeaseExpiresAt)) + 5*time.Millisecond)
			f.startSuccessorDispatch()
			_, continued, same, selected, err := f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy)
			if err != nil || !selected || same.ID != a.ID || continued.FencingToken != current.FencingToken+1 || continued.Generation != current.Generation || continued.LeaseOwner == current.LeaseOwner {
				t.Fatal("real new read-only owner", err)
			}
			current = continued
			finish, _, _, err = f.FinishStore().BindFailedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = finish.IssueFailedExpansionDestroy(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("new owner reissued destroy", err)
			}
			if err = finish.MarkFailedExpansionPossibleSend(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("new owner replayed possible send", err)
			}
			if err = finish.RefreshFailedExpansionSurvivors(ctx, f.Policy, cleanupNativeInventory(t, f, a, false)); err != nil {
				t.Fatal("accepted Pending VM may already be absent; only survivor freshness", err)
			}
			cleanupNativeCanaries(t, f, finish, current, "before_retirement_floor")
			read, err = finish.PrepareFailedExpansionRead(ctx, f.Policy, "absence")
			if err != nil {
				t.Fatal(err)
			}
			if proof, pending, err := finish.RecordFailedExpansionRead(ctx, f.Policy, cleanupNativeAbsenceReturn(t, read, receipt, false)); err != nil || pending || !proof.ResourceAbsent || len(proof.AuxiliaryAbsent) != 2 {
				t.Fatal("same sealed child full VM/AUX2 absence", err)
			}
			if _, err = finish.CompleteFailedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("old before-floor canary replaced real post-absence floor", err)
			}
			if err = finish.RefreshFailedExpansionSurvivors(ctx, f.Policy, cleanupNativeInventory(t, f, a, false)); err != nil {
				t.Fatal("postabsence exact survivingN1 inventory", err)
			}
			cleanupNativeCanaries(t, f, finish, current, "after_retirement_floor")
			terminal, err := finish.CompleteFailedExpansionCleanup(ctx, f.Policy)
			if err != nil || terminal.Phase != "hold" || terminal.Decision.Units != 1 || terminal.LeaseExpiresAt != nil || terminal.LeaseOwner != "" || terminal.Decision.ExecutionPermitted {
				t.Fatal("truthful unleased failed-expansion closure", terminal, err)
			}
			var state string
			var sdk []byte
			if err = f.DB.QueryRow(`SELECT state,(grant_record#>'{settlement,original_provider_create_return}')::text FROM public.capacity_mutation_grants WHERE id=$1`, a.GrantID).Scan(&state, &sdk); err != nil || state != "cleanup_closed" || !bytes.Equal(sdk, original.sdk) {
				t.Fatal("new terminal state falsified accepted CREATE bytes", state, err)
			}
			var witnesses, retirements, children int
			if err = f.DB.QueryRow(`SELECT(SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_mutation_grants WHERE failed_unwitnessed_expansion_cleanup_id=$2)`, a.PreregistrationID, a.ID).Scan(&witnesses, &retirements, &children); err != nil || witnesses != 0 || retirements != 0 || children != 1 {
				t.Fatal("cleanup manufactured Guest authority or duplicate child", err)
			}
			stored, events, err := store.ReadFailedUnwitnessedExpansionCleanup(ctx, a.GrantID)
			if err != nil || !reflect.DeepEqual(stored, admission) || events[len(events)-1].Stage != "terminal" {
				t.Fatal("append-only actual terminal ledger", err)
			}
			ledger := failedCleanupTestLedger(t, f.DB, a)
			for _, old := range initialLedger {
				found := false
				for _, current := range ledger {
					found = found || bytes.Equal(old, current)
				}
				if !found {
					t.Fatal("old admission/event wire changed")
				}
			}
			if _, _, _, selected, err := f.PlanStore().TryClaimFailedExpansionCleanup(ctx, f.Policy); err != nil || !selected {
				t.Fatal("same failed policy not latched", err)
			}
			// A genuinely later compatible policy is a normal new decision, not a reset
			// or replay of this consumed admission. Its Source planner must regain control.
			newer := f.Policy
			newer.ID = uuid.New()
			newer.Version++
			newer.Checksum = capacity.BusinessCreationSHA256([]byte("DECLARED-new-compatible-policy"))
			f.private.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,true)`, newer.ID, newer.Metadata.Namespace, newer.Metadata.Name, newer.Version, newer.Checksum, string(newer.Spec))
			if _, _, _, selected, err := f.PlanStore().TryClaimFailedExpansionCleanup(ctx, newer); err != nil || selected {
				t.Fatal("new compatible policy stuck behind old consumed cleanup", err)
			}
		})
	}

}
