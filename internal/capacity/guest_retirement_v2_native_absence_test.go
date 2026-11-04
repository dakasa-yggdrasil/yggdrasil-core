package capacity

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
)

// These are pure decoder operands, not signed enrollment/provider/SQL authority.
func nativeAbsenceContentFixture(provider string) (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityMutationReceipt, model.CapacityVMRetirementObservation) {
	p, b, r, o, _ := vmRetirementFixture()
	if provider == "aws" {
		var g model.CapacityMutationGrant
		var s model.CapacityMutationSettleRequest
		p, b, g, s, o, _, _ = awsDestroyFixture()
		r = model.CapacityMutationReceipt{Grant: g, AttemptID: s.AttemptID, Outcome: s.Outcome, TransportCompleted: s.TransportCompleted, ResourceID: s.ResourceID, ResourceCreatedAt: s.ResourceCreatedAt, ActionID: s.ActionID, NextActionIDs: s.NextActionIDs, AuxiliaryResources: s.AuxiliaryResources, AuxiliaryInventoryComplete: s.AuxiliaryInventoryComplete}
	}
	b.OriginalProviderSourceCommit = strings.Repeat("a", 40)
	p.MutationBindings = []model.CapacityMutationBinding{b}
	p.Profiles = []model.CapacityProfile{{Name: b.ProfileName, Provider: provider}}
	return p, b, r, o
}
func TestGuestRetirementV2NativeAbsenceContentPreservesOriginalReceipt(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, mode := range []string{"exact", "uncertain", "lost_transport", "unknown_original_action", "wrong_grant", "wrong_tuple", "wrong_instance_binding", "missing_source", "unconfigured", "protected", "missing_aux_inventory", "missing_aux", "retained_aux", "duplicate_aux", "retained_server", "writer_claim", "fencing_claim", "invoice_claim", "foreign_lifecycle"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				p, b, r, o := nativeAbsenceContentFixture(provider)
				switch mode {
				case "uncertain":
					r.Outcome = "uncertain"
					o.OriginalOutcome = "uncertain"
				case "lost_transport":
					r.TransportCompleted = false
					o.OriginalTransportCompleted = false
				case "unknown_original_action":
					r.ActionID = ""
				case "wrong_grant":
					o.DestroyGrantID = "other"
				case "wrong_tuple":
					o.ID = "other"
				case "wrong_instance_binding":
					r.Grant.IntegrationInstanceID = "other"
				case "missing_source":
					b.OriginalProviderSourceCommit = ""
					p.MutationBindings[0] = b
				case "unconfigured":
					p.MutationBindings = nil
				case "protected":
					r.Grant.Slot = 1
				case "missing_aux_inventory":
					r.AuxiliaryInventoryComplete = false
				case "missing_aux":
					o.AuxiliaryResources = nil
				case "retained_aux":
					o.AuxiliaryResources[0].Absent = false
				case "duplicate_aux":
					o.AuxiliaryResources = append(o.AuxiliaryResources, o.AuxiliaryResources[0])
				case "retained_server":
					o.ServerAbsent = false
					o.ServerStatus = "off"
				case "writer_claim":
					o.WriterQuiescenceEvidence = true
				case "fencing_claim":
					o.ProviderFencingEvidence = true
				case "invoice_claim":
					o.InvoiceReconciled = true
				case "foreign_lifecycle":
					if provider == "hetzner" {
						o.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{}
					} else {
						o.AWSRetirementLifecycle.RequestID = "foreign"
					}
				}
				proof, err := GuestRetirementV2NativeAbsenceContent(p, b, r, o, "content-only-original-native")
				if (err == nil) != (mode == "exact") {
					t.Fatalf("content=%v mode=%s", err, mode)
				}
				if err == nil && (!proof.ResourceAbsent || len(proof.AuxiliaryAbsent) != len(r.AuxiliaryResources)) {
					t.Fatal("complete auxiliary lifetime lost")
				}
			})
		}
	}
}
func TestGuestRetirementV2NativeAbsenceDoesNotUseCoreWallClock(t *testing.T) {
	for _, offset := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			p, b, r, o := nativeAbsenceContentFixture("aws")
			shift := func(raw string) string {
				at, err := time.Parse(time.RFC3339Nano, raw)
				if err != nil {
					t.Fatal(err)
				}
				return at.Add(offset).UTC().Format(time.RFC3339Nano)
			}
			o.ObservationStartedAt = shift(o.ObservationStartedAt)
			o.ServerObservedAt = shift(o.ServerObservedAt)
			o.ObservedAt = shift(o.ObservedAt)
			o.AWSRetirementLifecycle.ObservedAt = o.AWSRetirementLifecycle.ObservedAt.Add(offset)
			for n := range o.AuxiliaryResources {
				o.AuxiliaryResources[n].ObservedAt = shift(o.AuxiliaryResources[n].ObservedAt)
			}
			proof, err := GuestRetirementV2NativeAbsenceContent(p, b, r, o, "content-only-native-clock")
			if err != nil {
				t.Fatal(err)
			}
			at, _ := time.Parse(time.RFC3339Nano, o.ObservedAt)
			if !proof.ObservedAt.Equal(at) {
				t.Fatal("native stamp rewritten")
			}
		})
	}
}
