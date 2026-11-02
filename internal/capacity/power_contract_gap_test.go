package capacity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestExecutorLegacyPowerNeverEntersVMCreationDestructionLedger(t *testing.T) {
	p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{{Name: "fleet"}}}
	for _, op := range []string{"start_ec2_instance", "stop_ec2_instance"} {
		raw, _ := json.Marshal(model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: op})
		if _, err := PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: "fleet", DesiredSpec: raw}); !errors.Is(err, ErrPowerLifecycleUnqualified) {
			t.Fatal("power aliased into VM authority", op, err)
		}
	}
}
