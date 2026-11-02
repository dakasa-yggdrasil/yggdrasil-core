package message

import (
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalGuestDemandAllowsOnlyMissingFloorRecovery(t *testing.T) {
	p := model.CapacityPolicySpec{Floor: 1, GuestNotifyReconcileBinding: &model.CapacityGuestNotifyReconcileBinding{Signals: []model.CapacityMetricSignalBinding{{BindingName: "real-demand"}}}}
	calls := 0
	read := func(model.CapacityMetricSignalBinding) (model.CapacityMetricRangeObservation, error) {
		calls++
		return model.CapacityMetricRangeObservation{}, errors.New("real telemetry unavailable")
	}
	evidence, err := collectOriginalGuestDemand(p, model.CapacitySnapshot{Units: 0}, read)
	if err != nil || len(evidence) != 0 || calls != 0 {
		t.Fatal("empty verified inventory must permit floor repair without inventing demand", err, calls)
	}
	if _, err = collectOriginalGuestDemand(p, model.CapacitySnapshot{Units: 1}, read); err == nil || calls != 1 {
		t.Fatal("existing member must still require real demand", err, calls)
	}
}
