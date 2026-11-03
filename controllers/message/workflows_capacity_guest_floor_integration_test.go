package message

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Exercises the actual collector, snapshot validation, coverage contract and
// planner with declared fixture responses. No adapter/provider is called.
func TestOriginalGuestFloorCollectionAndStrictAdmission(t *testing.T) {
	raw, err := os.ReadFile("../../internal/capacity/testdata/original-notify-aws-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p.ExecutionEnabled = true
	if p.GuestNotifyReconcileBinding != nil && p.GuestNotifyReconcileBinding.AdministrativeCostAssumption != nil {
		p.GuestNotifyReconcileBinding.AdministrativeCostAssumption.ExpiresAt = now.Add(time.Hour)
	} else {
		for i := range p.Profiles {
			p.Profiles[i].QuoteValidUntil = now.Add(time.Hour)
			p.Profiles[i].ValidationValidUntil = now.Add(time.Hour)
		}
	}
	if err = capacity.ValidateGuestNotifyReconcileBinding(p); err != nil {
		t.Fatal(err)
	}
	b := p.MutationBindings[0]
	spec := b.Slots[0].DesiredSpec
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: spec.ProfileChecksum, AdmissionChecksum: spec.AdmissionChecksum, ProfileName: b.ProfileName, ProtectedSlots: b.ProtectedSlots, MaxSlots: b.MaxSlots, Members: []model.CapacityVMFleetInventoryMember{}, MissingSlots: []int{1, 2, 3, 4, 5, 6, 7, 8}, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
	cov := p.GuestNotifyReconcileBinding.MemberCoverage
	missing := model.CapacityMetricRangeObservation{Operation: capacity.ObserveMetricRange, Binding: cov.BindingName, BindingSHA256: cov.BindingSHA256, EvaluatedAt: now, Reason: "no_data", CapacityEvidence: model.CapacityEvidence{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/aws/reporting-members", Unit: "members", RequireData: true, DataState: "missing"}}
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "fixture"}, Checksum: strings.Repeat("4", 64)}
	cases := []struct {
		name                      string
		badInventory, badCoverage bool
		wantErr                   bool
	}{{"empty_complete", false, false, false}, {"incomplete_inventory", true, false, true}, {"foreign_coverage", false, true, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := inv
			if tc.badInventory {
				i.Complete = false
			}
			c := missing
			if tc.badCoverage {
				c.SourceIdentity = "foreign"
			}
			calls := []string{}
			read := func(_ model.CapacityObservationAdapterBinding, operation string, _ map[string]any, out any) error {
				calls = append(calls, operation)
				switch v := out.(type) {
				case *model.CapacityVMFleetInventory:
					*v = i
					return nil
				case *model.CapacityMetricRangeObservation:
					*v = c
					return nil
				default:
					return errors.New("unexpected response")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, assessment, _, err := collectOriginalGuestAssessmentFromReads(ctx, policy, p, read)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected collection result: %v", err)
			}
			if !tc.wantErr {
				if len(calls) != 2 || calls[0] != capacity.VMObserveInventory || calls[1] != capacity.ObserveMetricRange || len(assessment.Evidence) != 0 {
					t.Fatal("collector did not use inventory then coverage only", calls)
				}
				decision, e := capacity.Assess(p, assessment, model.CapacityClockState{}, now)
				if e != nil || decision.Reason != "protected_floor_recovery" || decision.Units != 1 {
					t.Fatalf("floor recovery not proposed: %+v %v", decision, e)
				}
				assessment.Snapshot.Units = 1
				if e = capacity.ValidateAssessment(p, assessment, now); e == nil {
					t.Fatal("missing demand became readiness")
				}
				decision, e = capacity.Assess(p, assessment, model.CapacityClockState{}, now)
				if e != nil || decision.Action != "hold" || decision.ExecutionPermitted {
					t.Fatalf("missing demand enabled ordinary scaling: %+v %v", decision, e)
				}
			}
		})
	}
}
