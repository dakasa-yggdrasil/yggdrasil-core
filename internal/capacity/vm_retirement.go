package capacity

import (
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const VMObserveRetirement = "observe_server_retirement"

// VMRetirementProof consumes only authenticated provider readback of the exact
// ORIGINAL accepted destroy. It proves native action/resource absence, never
// Guest writer quiescence or permission to send another DELETE. The store must
// independently join the original Guest evidence before freeing a slot.
func VMRetirementProof(p model.CapacityPolicySpec, b model.CapacityMutationBinding, original model.CapacityMutationReceipt, observed model.CapacityVMRetirementObservation, now time.Time, receiptRef string) (model.CapacityMutationProof, error) {
	var out model.CapacityMutationProof
	if AWSOriginalMutationPair(b) {
		return awsVMRetirementProof(p, b, original, observed, now, receiptRef)
	}
	if observed.AWSRetirementLifecycle != nil {
		return out, fmt.Errorf("AWS retirement lifecycle requires its exact source-pinned AWS binding")
	}
	g := original.Grant
	refuse := fmt.Errorf("exact original native retirement readback required")
	if (g.State != "settled" && g.State != "confirmed") || g.Capability != b.DestroyCapability || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.GrantID == "" || g.RequestSHA256 == "" || g.ExpectedResourceID == "" || g.ExpectedResourceCreatedAt == "" || original.Outcome != "accepted" || !original.TransportCompleted || observed.DestroyGrantID != g.GrantID || observed.DestroyGrantState != g.State || observed.CompensationOf != g.CompensationOf || observed.ID != g.ExpectedResourceID || observed.CreatedAt != g.ExpectedResourceCreatedAt || observed.OriginalOutcome != original.Outcome || observed.OriginalTransportCompleted != original.TransportCompleted || !observed.ServerAbsent || !observed.ServerAbsenceComplete || observed.ServerStatus != "" || !observed.AuxiliaryInventoryComplete || !original.AuxiliaryInventoryComplete || !observed.BillableResourcesAbsent || !observed.RetirementComplete || observed.HoldReasons == nil || len(observed.HoldReasons) != 0 || observed.InvoiceReconciled || observed.WriterQuiescenceEvidence || observed.ProviderFencingEvidence || receiptRef == "" || len(receiptRef) > 2048 {
		return out, refuse
	}
	if _, err := vmApprovedSlot(b, g.Slot); err != nil || (g.Slot <= b.ProtectedSlots && g.CompensationOf == "") {
		return out, refuse
	}
	start, e1 := vmTime(observed.ObservationStartedAt, p, now)
	server, e2 := vmTime(observed.ServerObservedAt, p, now)
	end, e3 := vmTime(observed.ObservedAt, p, now)
	created, e4 := time.Parse(time.RFC3339Nano, observed.CreatedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != observed.CreatedAt || start.After(server) || server.After(end) || end.After(now) || created.After(start) || end.Sub(start) > 60*time.Second {
		return out, refuse
	}
	if original.ResourceID != "" && (original.ResourceID != observed.ID || original.ResourceCreatedAt != observed.CreatedAt) {
		return out, refuse
	}
	main := observed.DeleteAction
	if original.ActionID == "" || !main.Known || !main.Observed || main.ID != original.ActionID || main.Status != "success" || main.Command != "delete_server" || main.ErrorCode != "" || observed.NextActions == nil || len(observed.NextActions) != len(original.NextActionIDs) || len(observed.NextActions) > 32 {
		return out, refuse
	}
	// The closed main-action DTO has no separate observation timestamp. Use
	// only the ORIGINAL whole readback's returned-at upper bound for freshness;
	// never invent the time of that GET. Successors retain their actual stamps.
	collection := model.CapacityVMActionCollection{ResourceID: observed.ID, ResourceCreatedAt: observed.CreatedAt, Complete: true, ObservedAt: observed.ObservedAt, Actions: []model.CapacityVMActionObservation{{ID: main.ID, Status: main.Status, Command: main.Command, ResourceID: observed.ID, StartedAt: main.StartedAt, FinishedAt: main.FinishedAt, ErrorCode: main.ErrorCode, ObservedAt: observed.ObservedAt}}}
	for n, action := range observed.NextActions {
		if action.ID != original.NextActionIDs[n] {
			return out, refuse
		}
		collection.Actions = append(collection.Actions, action)
	}
	ids, err := VMActionProof(p, collection, observed.ID, now, true)
	if err != nil {
		return out, refuse
	}
	if observed.AuxiliaryResources == nil || len(observed.AuxiliaryResources) != len(original.AuxiliaryResources) || len(observed.AuxiliaryResources) > 16 {
		return out, refuse
	}
	owned := map[string]model.CapacityMutationAuxiliaryResource{}
	for _, aux := range original.AuxiliaryResources {
		key := aux.Kind + "/" + aux.ID
		if aux.Kind == "" || aux.ID == "" || len(aux.Kind) > 64 || len(aux.ID) > 128 || strings.ContainsAny(key, "\x00\r\n") || owned[key].ID != "" {
			return out, refuse
		}
		owned[key] = aux
	}
	absent := []model.CapacityMutationAuxiliaryResource{}
	seen := map[string]bool{}
	for n, aux := range observed.AuxiliaryResources {
		key := aux.Kind + "/" + aux.ID
		if owned[key].ID == "" || seen[key] || !aux.Absent || original.AuxiliaryResources[n].Kind != aux.Kind || original.AuxiliaryResources[n].ID != aux.ID {
			return out, refuse
		}
		at, err := vmTime(aux.ObservedAt, p, now)
		if err != nil || at.Before(start) || at.After(end) {
			return out, refuse
		}
		seen[key] = true
		absent = append(absent, model.CapacityMutationAuxiliaryResource{Kind: aux.Kind, ID: aux.ID, RequiresAbsence: true})
	}
	if !vmRetirementExposureBound(p, original, observed, created, start, end) {
		return out, refuse
	}
	out = model.CapacityMutationProof{GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, ResourceID: observed.ID, ResourceCreatedAt: observed.CreatedAt, RequestSHA256: g.RequestSHA256, ObservedAt: end, ReceiptRef: receiptRef, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: ids, ActionsTerminal: true, ActionsSuccessful: true, AuxiliaryAbsent: absent, CompensationIdentityVerified: g.CompensationOf != ""}
	return out, nil
}

func vmRetirementExposureBound(p model.CapacityPolicySpec, original model.CapacityMutationReceipt, observed model.CapacityVMRetirementObservation, created, start, end time.Time) bool {
	x := observed.BillingExposure
	if x == nil || x.Basis != "profile_admission_ceiling_not_invoice" || x.Currency != p.Currency || x.WindowStart != observed.CreatedAt || len(x.Resources) != len(observed.AuxiliaryResources)+1 || len(x.Resources) > 17 || x.ExcludedCosts == nil || len(x.ExcludedCosts) == 0 || len(x.ExcludedCosts) > 32 || x.StartedHoursUpperBound < 1 || x.CalendarMonthsUpperBound < 1 || x.GrossHourlyCeilingMicros < 0 || x.GrossMonthlyCeilingMicros < 0 || x.HourlyCeilingTotalMicros < 0 || x.MonthlyCapCeilingTotalMicros < 0 || x.GrossCeilingMicrosUpperBound < 0 {
		return false
	}
	windowEnd, err := time.Parse(time.RFC3339Nano, x.WindowEndUpperBound)
	if err != nil || windowEnd.UTC().Format(time.RFC3339Nano) != x.WindowEndUpperBound || windowEnd.Before(created) || windowEnd.After(end) {
		return false
	}
	resources := map[string]string{"server/" + observed.ID: "native_server_created_at"}
	for _, aux := range original.AuxiliaryResources {
		resources[aux.Kind+"/"+aux.ID] = "server_creation_proxy_not_native_ip_creation"
	}
	seen := map[string]bool{}
	var latest time.Time
	latestSource := ""
	for n, window := range x.Resources {
		key := window.Kind + "/" + window.ID
		if resources[key] == "" || seen[key] || window.WindowStart != observed.CreatedAt || window.WindowStartSource != resources[key] || window.StartedHoursUpperBound < 1 {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, window.WindowEndUpperBound)
		if err != nil || at.UTC().Format(time.RFC3339Nano) != window.WindowEndUpperBound || at.Before(created) || at.After(windowEnd) {
			return false
		}
		if window.Kind == "server" {
			if n != 0 || window.WindowEndSource != "native_delete_action_finished" || window.WindowEndUpperBound != observed.DeleteAction.FinishedAt {
				return false
			}
		} else {
			if n == 0 || window.WindowEndSource != "first_complete_absence_observation" || at.Before(start) || window.Kind != observed.AuxiliaryResources[n-1].Kind || window.ID != observed.AuxiliaryResources[n-1].ID || window.WindowEndUpperBound != observed.AuxiliaryResources[n-1].ObservedAt {
				return false
			}
		}
		if latest.IsZero() || at.After(latest) {
			latest, latestSource = at, window.WindowEndSource
		}
		seen[key] = true
	}
	return latest.Equal(windowEnd) && x.WindowEndSource == latestSource
}
