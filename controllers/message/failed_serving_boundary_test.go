//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestFailedServingSourceClosedReadOperations(t *testing.T) {
	ctx := context.Background()
	if _, err := RequestFailedServingGuestQuarantine(ctx, nil, nil, model.CapacityFailedServingGuestDisposalRequest{}, "collaborator:invalid"); err == nil {
		t.Fatal("unowned quarantine caller admitted")
	}
	if _, err := ObserveFailedServingGuestNativeOff(ctx, nil, nil, "pre", "admission", "collaborator:invalid"); err == nil {
		t.Fatal("unowned OFF caller admitted")
	}
	if _, err := CompleteFailedServingGuestAbsence(ctx, nil, nil, "pre", "admission", "collaborator:invalid"); err == nil {
		t.Fatal("unowned absence caller admitted")
	}
	for _, operation := range []string{"ensure_server", "destroy_server", "ensure_ec2_instance", "terminate_ec2_instance", "poweroff", "delete", "observe_server_retirement", ""} {
		if err := failedServingNativeRead(ctx, nil, nil, model.CapacityOriginalCreateDispositionCandidate{}, operation, nil, new(any)); err == nil {
			t.Fatal("new lane admitted a mutating/unlisted capability", operation)
		}
	}
	for _, tc := range []struct{ provider, operation string }{{"aws", capacity.VMObserveServer}, {"hetzner", "observe_ec2_instance"}, {"lab", capacity.VMObserveInventory}} {
		raw, _ := json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "exact", Provider: tc.provider}}})
		c := model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: model.Manifest{Spec: raw}, Binding: model.CapacityMutationBinding{ProfileName: "exact"}}
		if err := failedServingNativeRead(ctx, nil, nil, c, tc.operation, nil, new(any)); err == nil {
			t.Fatal("cross-provider operation admitted")
		}
	}
}
