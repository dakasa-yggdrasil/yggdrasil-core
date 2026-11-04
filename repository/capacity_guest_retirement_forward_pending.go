package repository

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Exact existing provider pending shapes are retained here as classification,
// never absence or permission to repeat a mutation.
func guestForwardAWSAbsencePending(o model.CapacityVMRetirementObservation, r model.CapacityMutationReceipt) bool {
	l := o.AWSRetirementLifecycle
	if r.Grant.State != "settled" || r.Outcome != "accepted" || !r.TransportCompleted || !r.AuxiliaryInventoryComplete || len(r.AuxiliaryResources) != 2 || o.DestroyGrantID != r.Grant.GrantID || o.DestroyGrantState != r.Grant.State || o.ID != r.ResourceID || o.CreatedAt != r.ResourceCreatedAt || o.OriginalOutcome != "accepted" || !o.OriginalTransportCompleted || !o.AuxiliaryInventoryComplete || len(o.AuxiliaryResources) != 2 || o.RetirementComplete || len(o.HoldReasons) < 1 || len(o.HoldReasons) > 3 || o.WriterQuiescenceEvidence || o.ProviderFencingEvidence || o.InvoiceReconciled || o.BillingExposure != nil || o.DeleteAction != (model.CapacityVMRetirementAction{}) || o.NextActions == nil || len(o.NextActions) != 0 || l == nil || l.Schema != "aws_original_terminate_and_native_absence_v1" || l.RequestID != r.ActionID {
		return false
	}
	switch l.EC2State {
	case "pending", "running", "stopping", "stopped", "shutting-down", "terminated", "not_found":
	default:
		return false
	}
	absent := l.EC2State == "terminated" || l.EC2State == "not_found"
	if o.ServerAbsent != absent || o.ServerAbsenceComplete != absent || o.BillableResourcesAbsent || (absent && o.ServerStatus != "") || (!absent && o.ServerStatus != l.EC2State) {
		return false
	}
	seen := map[string]bool{}
	for _, hold := range o.HoldReasons {
		if seen[hold] || (hold != "instance_not_terminated" && hold != "aws_ebs_volume_still_present" && hold != "aws_network_interface_still_present") {
			return false
		}
		seen[hold] = true
	}
	if seen["instance_not_terminated"] == absent {
		return false
	}
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID || seen[a.Kind+"_still_present"] == a.Absent {
			return false
		}
	}
	return true
}

func guestForwardHetznerAbsencePending(o model.CapacityVMRetirementObservation, r model.CapacityMutationReceipt) bool {
	if r.Grant.State != "settled" || r.Grant.CompensationOf != "" || r.Outcome != "accepted" || !r.TransportCompleted || !r.AuxiliaryInventoryComplete || len(r.AuxiliaryResources) < 1 || len(r.AuxiliaryResources) > 2 || o.AWSRetirementLifecycle != nil || o.DestroyGrantID != r.Grant.GrantID || o.DestroyGrantState != r.Grant.State || o.CompensationOf != "" || o.ID != r.ResourceID || o.CreatedAt != r.ResourceCreatedAt || o.OriginalOutcome != "accepted" || !o.OriginalTransportCompleted || !o.ServerAbsenceComplete || !o.AuxiliaryInventoryComplete || len(o.AuxiliaryResources) != len(r.AuxiliaryResources) || o.RetirementComplete || len(o.HoldReasons) < 1 || len(o.HoldReasons) > 3 || o.WriterQuiescenceEvidence || o.ProviderFencingEvidence || o.InvoiceReconciled || o.BillingExposure != nil || o.DeleteAction.ID != r.ActionID || !o.DeleteAction.Known || !o.DeleteAction.Observed || o.DeleteAction.Command != "delete_server" || o.DeleteAction.ErrorCode != "" || (o.DeleteAction.Status != "running" && o.DeleteAction.Status != "success") || o.NextActions == nil || len(o.NextActions) != len(r.NextActionIDs) {
		return false
	}
	seen := map[string]bool{}
	for _, hold := range o.HoldReasons {
		if seen[hold] || (hold != "native_server_present" && hold != "original_delete_actions_not_successful" && hold != "native_billable_resources_present") {
			return false
		}
		seen[hold] = true
	}
	allAbsent := o.ServerAbsent
	if o.ServerAbsent && o.ServerStatus != "" || !o.ServerAbsent && o.ServerStatus == "" {
		return false
	}
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID {
			return false
		}
		allAbsent = allAbsent && a.Absent
	}
	allActions := o.DeleteAction.Status == "success"
	for n, a := range o.NextActions {
		if a.ID != r.NextActionIDs[n] || a.ResourceID != r.ResourceID || a.ErrorCode != "" || (a.Status != "running" && a.Status != "success") {
			return false
		}
		allActions = allActions && a.Status == "success"
	}
	return seen["native_server_present"] != o.ServerAbsent && seen["original_delete_actions_not_successful"] != allActions && seen["native_billable_resources_present"] != allAbsent && o.BillableResourcesAbsent == allAbsent
}
