package capacity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const GuestNotifyReconcileMode = "original_guest_notify_reconcile_v1"
const PlanOriginalGuestOperation = "capacity.plan_original_guest"
const CompleteOriginalGuestOperation = "capacity.complete_original_guest"
const OriginalGuestMemberCoverageName = "original-guest-member-coverage"
const OriginalGuestCoverageMinimumSamples = 5
const OriginalGuestCoverageMinimumWindow = 30 * time.Second

var ErrOriginalGuestReportingIncomplete = errors.New("original Guest reporting window incomplete")

// Observe only: an already-confirmed membership change may need the actual
// metric window to mature. This loop does not publish, create, retire, claim,
// renew or replay anything. Its source caller retains the SAME original context.
func AwaitOriginalGuestReporting(ctx context.Context, read func(context.Context) error) error {
	for {
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		err := read(ctx)
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		if !errors.Is(err, ErrOriginalGuestReportingIncomplete) {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Source identity below describes an operator-owned VM profile, not a native
// VM UID, an atomic provider snapshot, readiness or a business receipt.
func GuestReconcileSnapshot(policy model.Manifest, p model.CapacityPolicySpec, inv model.CapacityVMFleetInventory, now time.Time) (model.CapacitySnapshot, error) {
	var empty model.CapacitySnapshot
	if ValidateGuestNotifyReconcileBinding(p) != nil || p.GuestNotifyReconcileBinding == nil || policy.ID.String() == "00000000-0000-0000-0000-000000000000" || !ValidDigest(policy.Checksum) {
		return empty, fmt.Errorf("original Guest inventory scope unavailable")
	}
	b := p.MutationBindings[0]
	proofs, err := VMInventoryProofs(p, b, inv, "", 0, now, "original-guest-inventory:"+policy.ID.String())
	if err != nil || len(proofs) != len(inv.Members) {
		return empty, fmt.Errorf("original Guest inventory incomplete")
	}
	observed, err := time.Parse(time.RFC3339Nano, inv.ObservedAt)
	if err != nil {
		return empty, err
	}
	// Sort before fingerprinting: provider response order is not a resource
	// replacement. Native tuples remain independent and are checked in SQL.
	tuples := make([]struct {
		Slot          int
		ID, CreatedAt string
	}, 0, len(proofs))
	for _, member := range inv.Members {
		if member.Server.Labels["yggdrasil.io/owner"] != p.Owner {
			return empty, fmt.Errorf("original Guest native owner differs")
		}
	}
	for _, proof := range proofs {
		tuples = append(tuples, struct {
			Slot          int
			ID, CreatedAt string
		}{proof.Slot, proof.ResourceID, proof.ResourceCreatedAt})
	}
	sort.Slice(tuples, func(i, j int) bool { return tuples[i].Slot < tuples[j].Slot })
	return model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, Owner: p.Owner, Profile: b.ProfileName, Units: len(proofs), ObservedAt: observed,
		ResourceUID:     "original-vm-profile:" + b.IntegrationInstanceID + ":" + b.ScopeChecksum,
		WorkloadUID:     "original-guest-profile:" + p.GuestRetirementBinding.ProfileManifestSHA256,
		ResourceVersion: GuestRetirementSHA(tuples), WorkloadResourceVersion: inv.AdmissionChecksum}, nil
}

func ValidateGuestNotifyReconcileBinding(p model.CapacityPolicySpec) error {
	r := p.GuestNotifyReconcileBinding
	if r == nil {
		return nil
	}
	refuse := func() error { return fmt.Errorf("fixed original Guest reconciliation binding required") }
	if r.Mode != GuestNotifyReconcileMode || r.MemberCoverage == nil || p.AssessmentBinding != nil || p.HPAExecutionBinding != nil || p.GuestBootstrapBinding != nil || p.VMNodeMembershipBinding != nil || p.ExecutorPowerBinding != nil || p.NativeNotifyWindowBinding != nil || p.Environment != "production" || p.Domain != "notify" || p.Floor != 1 || p.Ceiling != 8 || p.Step != 1 || len(p.Profiles) != 1 || len(p.MutationBindings) != 1 || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.EvidenceClass != "owned_provisioner_original" || p.GuestNotifyCanaryBinding == nil || len(r.Signals) == 0 || len(r.Signals) != len(p.Signals) || len(r.Signals) > 8 {
		return refuse()
	}
	profile, binding := p.Profiles[0], p.MutationBindings[0]
	if profile.Provider != "aws" && profile.Provider != "hetzner" || profile.MinUnits != 1 || profile.MaxUnits != 8 || profile.Name != binding.ProfileName || binding.Name != "notify-"+profile.Provider+"-elastic" || p.Workflow.Namespace != "dakasa-production" || p.TargetIdentity != "dakasa-production/"+binding.Name || p.Dimension != "original_notify_"+profile.Provider+"_vm_members" || binding.MaxSlots != 8 || len(binding.Slots) != 8 || p.GuestRetirementBinding.MutationBindingName != binding.Name || len(p.GuestRetirementBinding.Members) != 8 || ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil || ValidateGuestNotifyCanaryBinding(p) != nil {
		return refuse()
	}
	seen, targets := map[string]bool{}, map[string]bool{}
	for _, b := range r.Signals {
		matched := false
		for _, signal := range p.Signals {
			matched = matched || signal.Name == b.Name
		}
		key := b.Adapter.IntegrationInstanceID + "/" + b.BindingName
		if !matched || seen[b.Name] || targets[key] || !validObservationAdapter(b.Adapter) || !ValidDigest(b.BindingSHA256) || b.BindingName == "" || len(b.BindingName) > 128 || strings.TrimSpace(b.BindingName) != b.BindingName || strings.ContainsAny(b.BindingName, "\x00\r\n\t") {
			return refuse()
		}
		seen[b.Name] = true
		targets[key] = true
	}
	c := r.MemberCoverage
	if c.Name != OriginalGuestMemberCoverageName || seen[c.Name] || targets[c.Adapter.IntegrationInstanceID+"/"+c.BindingName] || !validObservationAdapter(c.Adapter) || !ValidDigest(c.BindingSHA256) || c.BindingName == "" || len(c.BindingName) > 128 || strings.TrimSpace(c.BindingName) != c.BindingName || strings.ContainsAny(c.BindingName, "\x00\r\n\t") {
		return refuse()
	}
	return ValidateAdministrativeCostAssumption(p)
}

// A separate quality gate, never a demand signal or a useful-member count.
// Cardinality must cover the SAME complete native inventory for the entire
// observed metric window; a partial low aggregate cannot authorize retirement.
func GuestReconcileMemberCoverage(p model.CapacityPolicySpec, raw model.CapacityMetricRangeObservation, nativeMembers int, now time.Time) error {
	refuse := fmt.Errorf("complete original Guest reporting membership required")
	if p.GuestNotifyReconcileBinding == nil || ValidateGuestNotifyReconcileBinding(p) != nil || nativeMembers < 0 || nativeMembers > 8 {
		return refuse
	}
	b := *p.GuestNotifyReconcileBinding.MemberCoverage
	projection := p
	projection.Signals = []model.CapacitySignalRule{{Name: OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/" + p.Profiles[0].Provider + "/reporting-members", Unit: "members"}}
	e, err := BoundMetricEvidence(projection, b, raw, now)
	if err != nil {
		return err
	}
	// Native inventory, not this null response, proves that the fleet is empty.
	if nativeMembers == 0 && e.DataState == "missing" && !raw.OK && !e.Matched && e.Value == nil && e.RangeMin == nil && e.RangeMax == nil && e.Samples == 0 && !e.CoverageComplete {
		return nil
	}
	want := float64(nativeMembers)
	if !raw.OK || !e.RequireData || !e.Matched || e.DataState != "present" || e.Value == nil || e.RangeMin == nil || e.RangeMax == nil || !finite(*e.Value) || *e.Value != want || *e.RangeMin != want || *e.RangeMax != want || e.Samples < OriginalGuestCoverageMinimumSamples || !e.CoverageComplete || e.MaxGapSeconds < 0 || e.MaxGapSeconds > p.MaxSampleGapSeconds || !Fresh(e.SourceSampledAt, now, p.MaxEvidenceAgeSeconds) || !Fresh(e.WindowEnd, now, p.MaxEvidenceAgeSeconds) || e.WindowStart.IsZero() || e.WindowStart.After(e.WindowEnd) || e.WindowEnd.Sub(e.WindowStart) < OriginalGuestCoverageMinimumWindow || e.SourceSampledAt.Before(e.WindowStart) || e.SourceSampledAt.After(e.WindowEnd.Add(5*time.Second)) {
		return ErrOriginalGuestReportingIncomplete
	}
	return nil
}

// The generic workflow runner executes these actual visible source steps.
// No hidden child, externally supplied assessment/lease or callback registry
// replaces the existing original provisioning, canary or retirement opcode.
func OriginalGuestReconcileGraph(policy model.Manifest, p model.CapacityPolicySpec) ([]model.WorkflowStepSpec, error) {
	if p.GuestNotifyReconcileBinding == nil || ValidateGuestNotifyReconcileBinding(p) != nil {
		return nil, fmt.Errorf("original Guest graph unavailable")
	}
	ref := map[string]any{"namespace": policy.Metadata.Namespace, "name": policy.Metadata.Name}
	step := func(id, operation string, input map[string]any, condition string, deps []string, timeout int) model.WorkflowStepSpec {
		return model.WorkflowStepSpec{ID: id, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: operation}, With: input, Condition: condition, DependsOn: deps, TimeoutSeconds: timeout, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}}
	}
	value := func(name string) string { return "{{ steps.plan-original-guest.metadata." + name + " }}" }
	common := func() map[string]any {
		return map[string]any{"policy": ref, "binding_name": p.MutationBindings[0].Name, "slot": value("slot"), "generation": value("generation"), "fencing_token": value("fencing_token"), "lease_owner": value("lease_owner")}
	}
	provisionID := p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID
	retire := common()
	retire["preregistration_id"] = value("preregistration_id")
	finish := common()
	finish["preregistration_id"] = value("preregistration_id")
	finish["request_id"] = "{{ steps.retire-original-guest.metadata.request_id }}"
	complete := func(mode string) map[string]any {
		out := common()
		out["mode"] = mode
		if mode == "retire" {
			out["request_id"] = "{{ steps.retire-original-guest.metadata.request_id }}"
		}
		return out
	}
	return []model.WorkflowStepSpec{
		step("plan-original-guest", PlanOriginalGuestOperation, map[string]any{"policy": ref}, "", nil, 90),
		step(provisionID, ProvisionOriginalGuestOperation, common(), "{{ steps.plan-original-guest.metadata.mode }} == provision", []string{"plan-original-guest"}, 600),
		step("complete-original-provision", CompleteOriginalGuestOperation, complete("provision"), "{{ steps.plan-original-guest.metadata.mode }} == provision", []string{provisionID}, 90),
		step("retire-original-guest", RetireOriginalGuestOperation, retire, "{{ steps.plan-original-guest.metadata.mode }} == retire", []string{"plan-original-guest"}, 180),
		step("finish-original-retirement", "capacity.finish_original_guest_retirement", finish, "{{ steps.plan-original-guest.metadata.mode }} == retire", []string{"retire-original-guest"}, 90),
		step("complete-original-retirement", CompleteOriginalGuestOperation, complete("retire"), "{{ steps.plan-original-guest.metadata.mode }} == retire", []string{"finish-original-retirement"}, 90),
		step("refresh-original-membership", CompleteOriginalGuestOperation, map[string]any{"policy": ref, "mode": "refresh"}, "{{ steps.plan-original-guest.metadata.mode }} == refresh", []string{"plan-original-guest"}, 90),
	}, nil
}

func ValidateOriginalGuestReconcileGraph(spec model.WorkflowManifestSpec, policy model.Manifest, p model.CapacityPolicySpec) error {
	want, err := OriginalGuestReconcileGraph(policy, p)
	if err != nil || spec.Authorization == nil || spec.Trigger.Mode != "schedule" || spec.Trigger.Enabled == nil || !*spec.Trigger.Enabled || spec.Trigger.Schedule == nil || spec.DispatchMode != "async" || len(spec.InputSchema.Required) != 1 || spec.InputSchema.Required[0] != "policy" || spec.InputSchema.AdditionalProperties == nil || *spec.InputSchema.AdditionalProperties || len(spec.InputSchema.Properties) != 1 || spec.InputSchema.Properties["policy"].Type != "object" || len(spec.Defaults) != 0 || !reflect.DeepEqual(spec.Steps, want) {
		return fmt.Errorf("exact source-owned original Guest scheduled graph required")
	}
	return nil
}
