//go:build linux && nativequalification

package main

import (
	"testing"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestFailedFloorWorkflowModes(t *testing.T) {
	for _, nativeCase := range []string{"canonical_failed_floor_recovery", "source_live_failed_floor_recovery"} {
		t.Run(nativeCase, func(t *testing.T) {
			f := fixture{request: q.SourceRequest{NativeCase: nativeCase}, profile: model.CapacityGuestProtectedProfileManifest{OriginalProvisioningStepID: "original_create"}}
			spec := f.workflowSpec(model.Manifest{})
			steps := make(map[string]model.WorkflowStepSpec)
			for _, step := range spec.Steps {
				steps[step.ID] = step
			}
			create, createOK := steps["original_create"]
			qualify, qualifyOK := steps["original_echo_qualified"]
			if !createOK || !qualifyOK || len(qualify.DependsOn) != 1 || qualify.DependsOn[0] != create.ID {
				t.Fatal("original create and dependent echo qualification are required")
			}
			for _, tc := range []struct {
				mode        string
				wantQualify bool
			}{{failedFloorInitialMode, true}, {failedFloorNextMode, false}} {
				ctx := manifest.WorkflowExecutionContext{Inputs: map[string]any{"mode": tc.mode}}
				for _, check := range []struct {
					step model.WorkflowStepSpec
					want bool
				}{{create, true}, {qualify, tc.wantQualify}} {
					got, err := manifest.EvaluateWorkflowStepCondition(check.step.Condition, ctx)
					if err != nil || got != check.want {
						t.Fatalf("mode %q step %q: got %t, want %t, err %v", tc.mode, check.step.ID, got, check.want, err)
					}
				}
			}
		})
	}
}
