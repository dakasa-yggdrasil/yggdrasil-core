//go:build recoveryfixture && !nativequalification

package message

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Prepare a DECLARED provider settlement through the existing real PostgreSQL
// APIs, then admit a historical successor that adopts that settled DELETE.
// This owns exactly one Issue/Redeem/Settle; no native provider is called.
func inventoryReadonlySettledForwardFixture(t *testing.T, f *repository.GuestRetirementForwardRecoveryFixture, ctx context.Context) model.CapacityMutationReceipt {
	t.Helper()
	parent, err := f.RetirementStore().AdmitGuestRetirementForwardLive(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal("real forward admission", err, f.AdmissionDiagnostics())
	}
	finish := f.FinishStore()
	read, err := finish.PrepareGuestRetirementForwardRead(ctx, f.Request.Intent.RequestID, "off", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = finish.RecordGuestRetirementForwardRead(ctx, f.NativeOffReturn(read, "")); err != nil {
		t.Fatal("declared original OFF", err)
	}
	f.Canaries("after_retirement_floor")
	if err = finish.RefreshGuestRetirementForwardInventory(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, f.Inventory(true)); err != nil {
		t.Fatal(err)
	}
	f.Intent, err = finish.AdvanceGuestRetirementForwardDrained(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID)
	if err != nil {
		t.Fatal("real drain", err)
	}
	b := f.Spec.MutationBindings[0]
	spec := *b.Slots[f.Pre.Slot-1].DesiredSpec
	spec.Capability, spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = b.DestroyCapability, f.Request.Intent.Tuple.ResourceID, f.Request.Intent.Tuple.CreatedAt
	wire, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := finish.IssueMutation(ctx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire})
	if err != nil {
		t.Fatal("one real destroy issue", err)
	}
	callback := repository.CapacityStore{DB: f.DB, ExecutionEnabled: true}
	nonce := uuid.NewString()
	redeem := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256, AttemptID: uuid.NewString(), SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), ExpectedResourceID: grant.ExpectedResourceID, ExpectedResourceCreatedAt: grant.ExpectedResourceCreatedAt, CompensationOf: grant.CompensationOf}
	permit, err := callback.RedeemMutation(ctx, b.AdapterPrincipalID, redeem)
	if err != nil || permit.Mode != "write_once" {
		t.Fatal("one real redemption", err)
	}
	if _, err = callback.SettleMutation(ctx, b.AdapterPrincipalID, nonce, f.DestroySettlement(grant, redeem.AttemptID)); err != nil {
		t.Fatal("declared accepted original settlement", err)
	}
	receipt, found, err := finish.GuestRetirementForwardDestroyReceipt(ctx, f.Request.Intent.RequestID)
	if err != nil || !found || receipt.Grant.State != "settled" {
		t.Fatal("real settled custody", err)
	}
	// Settlement does not rewrite the live admission into adopted-destroy
	// authority. Close its real failed dispatch/ACK and observe natural expiry
	// before requesting and claiming a distinct historical admission.
	f.FinishFailedRun("finish-original-retirement")
	originals, oldIntent := f.PreservedOriginals(), f.Intent
	var parentBefore string
	if err = f.DB.QueryRowContext(ctx, `SELECT encode(original_wire,'hex') FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='admitted'`, parent.ID).Scan(&parentBefore); err != nil {
		t.Fatal(err)
	}
	barrier := f.WaitHistoricalBarrier()
	child, err := f.Store.RequestGuestRetirementForwardHistorical(ctx, f.HistoricalRequest(), "declared-readonly-inventory-fixture", barrier, func(context.Context) error { return nil })
	if err != nil || child.Mode != "historical" || child.ID == parent.ID || child.ParentAdmissionID != parent.ID || child.RootAdmissionID != parent.ID || child.DestroyGrantID != receipt.Grant.GrantID {
		t.Fatal("historical admission must adopt the same settled original DELETE", child, err)
	}
	f.StartSuccessorDispatch()
	next, preregistrationID, requestID, handled, err := f.PlanStore().TryClaimGuestRetirementForward(ctx, f.Policy)
	if err != nil || !handled || preregistrationID != f.Pre.PreregistrationID || requestID != f.Request.Intent.RequestID || next.RetirementForward == nil || next.RetirementForward.ID != child.ID || next.FencingToken != oldIntent.FencingToken+1 || next.LeaseOwner == oldIntent.LeaseOwner || next.LeaseExpiresAt == nil || !next.LeaseExpiresAt.After(time.Now()) {
		t.Fatal("historical successor must acquire a fresh fenced owner", next, handled, err)
	}
	f.Intent = next
	var parentAfter string
	var ownReads int
	if err = f.DB.QueryRowContext(ctx, `SELECT encode(original_wire,'hex') FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='admitted'`, parent.ID).Scan(&parentAfter); err != nil || parentAfter != parentBefore || !reflect.DeepEqual(originals, f.PreservedOriginals()) {
		t.Fatal("historical adoption rewrote the parent or immutable original evidence", err)
	}
	if err = f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1`, child.ID).Scan(&ownReads); err != nil || ownReads != 0 {
		t.Fatal("historical inventory owner must begin before any own absence read", ownReads, err)
	}
	return receipt
}

// The independently described HTTP reader supplies DECLARED inventory facts;
// actual lease validation, complete inventory proof and membership refresh run
// on the existing isolated PG16/17 fixture. This is not production SDK evidence.
func TestInventoryReadonlySettledForwardRefreshPostgres(t *testing.T) {
	if !inventoryReadonlySourceReady(inventoryReadonlyAWSObserverSource) {
		t.Fatal("actual published inventory compiler source must be bound before CI")
	}
	f := repository.NewGuestRetirementForwardRecoveryFixture(t, "aws", 3, 4)
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	receipt := inventoryReadonlySettledForwardFixture(t, f, ctx)
	before := f.PreservedOriginals()
	var grantBefore string
	if err := f.DB.QueryRowContext(ctx, `SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, receipt.Grant.GrantID).Scan(&grantBefore); err != nil {
		t.Fatal(err)
	}
	var readCount int
	if err := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forward_reads`).Scan(&readCount); err != nil {
		t.Fatal(err)
	}
	o := inventoryReadonlyDeclaredSupplier(t)
	b := f.Spec.MutationBindings[0]
	o.instance.ID, o.typ.ID = uuid.MustParse(b.IntegrationInstanceID), uuid.MustParse(b.IntegrationTypeID)
	o.instance.Checksum, o.typ.Checksum = b.IntegrationChecksum, b.IntegrationTypeChecksum
	for _, fault := range []string{"incomplete", "foreign_native_tuple", "changed_admission", "wrong_owner", "exact_survivors"} {
		t.Run(fault, func(t *testing.T) {
			inventory := f.Inventory(false)
			switch fault {
			case "incomplete":
				inventory.Complete = false
			case "foreign_native_tuple":
				inventory.Members[0].Server.ID = "i-fffffffffffffffff"
			case "changed_admission":
				inventory.AdmissionChecksum = capacity.BusinessCreationSHA256([]byte("foreign admission"))
			}
			installInventoryReadonlyHTTP(t, func(path string, raw []byte) any {
				if path == "/rpc/describe" {
					return expectedInventoryReadonlyDescription(inventoryReadonlyAWSObserverSource)
				}
				if path != "/rpc/execute" {
					t.Error("unexpected reader endpoint")
					return nil
				}
				in := inventoryReadonlyDecodeTestRequest(t, raw)
				return model.AdapterExecuteIntegrationResponse{Operation: inventoryReadonlyOperation, Capability: inventoryReadonlyOperation, Status: "observed", Output: inventoryReadonlyDeclaredReturn(in, inventoryReadonlyAWSObserverSource, inventory)}
			})
			read, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			finish := f.FinishStore()
			guardCalls := 0
			observed, err := readInventoryReadonly(read, o, b.ProfileName, inventoryReadonlyAWSObserverSource, func(guardCtx context.Context) error {
				guardCalls++
				owner := f.Intent.LeaseOwner
				if fault == "wrong_owner" {
					owner = uuid.NewString()
				}
				return finish.ValidateNativeObservationLease(guardCtx, f.Policy, f.Intent.Generation, f.Intent.FencingToken, owner)
			})
			if err == nil {
				err = finish.RefreshGuestRetirementForwardInventory(read, f.Policy, f.Intent.Generation, f.Intent.FencingToken, f.Intent.LeaseOwner, f.Request.Intent.RequestID, observed)
			}
			if (err == nil) != (fault == "exact_survivors") || fault == "exact_survivors" && guardCalls != 2 {
				t.Fatal("read-only provenance weakened native membership or lease guards", fault, err)
			}
			var grantAfter string
			var readsAfter, deletes int
			if err := f.DB.QueryRowContext(ctx, `SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, receipt.Grant.GrantID).Scan(&grantAfter); err != nil || grantAfter != grantBefore {
				t.Fatal("inventory changed original destroy settlement", err)
			}
			if err := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forward_reads`).Scan(&readsAfter); err != nil || readsAfter != readCount {
				t.Fatal("inventory fabricated an absence read", err)
			}
			if err := f.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,capability}'=$1`, b.DestroyCapability).Scan(&deletes); err != nil || deletes != 1 {
				t.Fatal("inventory issued another destroy", deletes, err)
			}
			if !reflect.DeepEqual(before, f.PreservedOriginals()) {
				t.Fatal("inventory rewrote immutable original Guest/SDK/workflow evidence")
			}
		})
	}
}
