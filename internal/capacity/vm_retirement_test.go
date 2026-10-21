package capacity

import (
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func vmRetirementFixture() (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityMutationReceipt, model.CapacityVMRetirementObservation, time.Time) {
	p, b, inventory, now := vmObservationFixture()
	p.Currency = "EUR"
	created := inventory.Members[1].Server.CreatedAt
	mainStart, mainEnd := now.Add(-10*time.Second).Format(time.RFC3339Nano), now.Add(-4*time.Second).Format(time.RFC3339Nano)
	absence := now.Add(-time.Second).Format(time.RFC3339Nano)
	r := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "original-destroy", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.DestroyCapability, RequestSHA256: strings.Repeat("e", 64), ExpectedResourceID: "2", ExpectedResourceCreatedAt: created, State: "settled"}, AttemptID: "original-attempt", Outcome: "accepted", TransportCompleted: true, ResourceID: "2", ResourceCreatedAt: created, ActionID: "14", NextActionIDs: []string{}, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "20", RequiresAbsence: true}}, AuxiliaryInventoryComplete: true}
	o := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: "2", CreatedAt: created}, DestroyGrantID: r.Grant.GrantID, DestroyGrantState: "settled", OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: now.Add(-1500 * time.Millisecond).Format(time.RFC3339Nano), DeleteAction: model.CapacityVMRetirementAction{Known: true, Observed: true, ID: "14", Status: "success", Command: "delete_server", StartedAt: mainStart, FinishedAt: mainEnd}, NextActions: []model.CapacityVMActionObservation{}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "20", Absent: true, ObservedAt: absence}}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: now.Add(-2 * time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
	o.BillingExposure = &model.CapacityVMBillingExposure{Basis: "profile_admission_ceiling_not_invoice", Currency: "EUR", WindowStart: created, WindowEndUpperBound: absence, WindowEndSource: "first_complete_absence_observation", Resources: []model.CapacityVMBillableResourceWindow{{Kind: "server", ID: "2", WindowStart: created, WindowStartSource: "native_server_created_at", WindowEndUpperBound: mainEnd, WindowEndSource: "native_delete_action_finished", StartedHoursUpperBound: 2}, {Kind: "primary_ip", ID: "20", WindowStart: created, WindowStartSource: "server_creation_proxy_not_native_ip_creation", WindowEndUpperBound: absence, WindowEndSource: "first_complete_absence_observation", StartedHoursUpperBound: 2}}, StartedHoursUpperBound: 2, CalendarMonthsUpperBound: 1, GrossHourlyCeilingMicros: 1000, GrossMonthlyCeilingMicros: 2000, HourlyCeilingTotalMicros: 2000, MonthlyCapCeilingTotalMicros: 2000, GrossCeilingMicrosUpperBound: 2000, IncludesPrimaryIPv4: true, ExcludedCosts: []string{"not an invoice"}}
	return p, b, r, o, now
}

func TestVMRetirementKeepsOriginalUncertaintyAndQuiescenceSeparate(t *testing.T) {
	for _, mode := range []string{"accepted-original-known-resources", "uncertain-original-even-all-absent", "lost-original-transport", "unknown-main-action", "foreign-main-action", "running-main-action", "error-main-action", "foreign-resource", "foreign-created-at", "foreign-grant", "foreign-grant-state", "foreign-binding", "protected-ordinary-slot", "unknown-auxiliary-inventory", "missing-owned-auxiliary", "foreign-auxiliary", "present-auxiliary", "duplicate-auxiliary", "unexpected-successor", "incomplete-server-absence", "server-still-present", "retained-hold-reason", "fake-provider-quiescence", "fake-provider-fencing", "fake-invoice", "stale-read", "reversed-read-window", "missing-exposure", "foreign-exposure-resource", "foreign-exposure-end", "invoice-exposure-basis", "foreign-exposure-currency", "negative-exposure-ceiling"} {
		t.Run(mode, func(t *testing.T) {
			p, b, r, o, now := vmRetirementFixture()
			switch mode {
			case "uncertain-original-even-all-absent":
				r.Outcome, o.OriginalOutcome = "uncertain", "uncertain"
			case "lost-original-transport":
				r.TransportCompleted, o.OriginalTransportCompleted = false, false
			case "unknown-main-action":
				r.ActionID, o.DeleteAction.ID = "", ""
			case "foreign-main-action":
				o.DeleteAction.ID = "foreign"
			case "running-main-action":
				o.DeleteAction.Status = "running"
			case "error-main-action":
				o.DeleteAction.Status = "error"
			case "foreign-resource":
				o.ID = "foreign"
			case "foreign-created-at":
				o.CreatedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
			case "foreign-grant":
				o.DestroyGrantID = "foreign"
			case "foreign-grant-state":
				o.DestroyGrantState = "issued"
			case "foreign-binding":
				r.Grant.BindingName = "foreign"
			case "protected-ordinary-slot":
				r.Grant.Slot = 1
			case "unknown-auxiliary-inventory":
				r.AuxiliaryInventoryComplete = false
			case "missing-owned-auxiliary":
				o.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{}
			case "foreign-auxiliary":
				o.AuxiliaryResources[0].ID = "foreign"
			case "present-auxiliary":
				o.AuxiliaryResources[0].Absent = false
			case "duplicate-auxiliary":
				o.AuxiliaryResources = append(o.AuxiliaryResources, o.AuxiliaryResources[0])
			case "unexpected-successor":
				o.NextActions = []model.CapacityVMActionObservation{{ID: "foreign"}}
			case "incomplete-server-absence":
				o.ServerAbsenceComplete = false
			case "server-still-present":
				o.ServerAbsent, o.ServerStatus = false, "off"
			case "retained-hold-reason":
				o.HoldReasons = []string{"original_delete_transport_uncertain"}
			case "fake-provider-quiescence":
				o.WriterQuiescenceEvidence = true
			case "fake-provider-fencing":
				o.ProviderFencingEvidence = true
			case "fake-invoice":
				o.InvoiceReconciled = true
			case "stale-read":
				o.ObservationStartedAt = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
			case "reversed-read-window":
				o.ServerObservedAt = now.Add(-3 * time.Second).Format(time.RFC3339Nano)
			case "missing-exposure":
				o.BillingExposure = nil
			case "foreign-exposure-resource":
				o.BillingExposure.Resources[0].ID = "foreign"
			case "foreign-exposure-end":
				o.BillingExposure.Resources[1].WindowEndUpperBound = now.Format(time.RFC3339Nano)
			case "invoice-exposure-basis":
				o.BillingExposure.Basis = "invoice"
			case "foreign-exposure-currency":
				o.BillingExposure.Currency = "BRL"
			case "negative-exposure-ceiling":
				o.BillingExposure.GrossCeilingMicrosUpperBound = -1
			}
			proof, err := VMRetirementProof(p, b, r, o, now, "receipt:original-provider-read")
			if (err == nil) != (mode == "accepted-original-known-resources") {
				t.Fatal("unknown/foreign native observation gained retirement proof", mode, err)
			}
			if err == nil && (!proof.ResourceAbsent || len(proof.ActionIDs) != 1 || len(proof.AuxiliaryAbsent) != 1 || proof.ObservedCreationGrantID != "") {
				t.Fatal("native retirement substituted product/creation evidence")
			}
		})
	}
}
