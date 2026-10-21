package capacity

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestExecutorActivityBindingPreservesFloorAndBounds(t *testing.T) {
	p, _ := fixture(time.Now().UTC())
	b := model.CapacityExecutorActivityBinding{Mode: "executor_activity_v1", LeaseTTLSeconds: 90, IdleAfterSeconds: 600, MaxObservationAgeSeconds: 30, MaxTasks: 10000}
	p.ExecutorActivityBinding = &b
	if err := ValidatePolicy(p); err != nil {
		t.Fatal(err)
	}
	p.Floor = 0
	if ValidatePolicy(p) == nil {
		t.Fatal("activity binding lowered protected floor")
	}
	p.Floor = 2
	for _, mutate := range []func(*model.CapacityExecutorActivityBinding){
		func(b *model.CapacityExecutorActivityBinding) { b.Mode = "automatic" },
		func(b *model.CapacityExecutorActivityBinding) { b.LeaseTTLSeconds = 0 },
		func(b *model.CapacityExecutorActivityBinding) { b.MaxObservationAgeSeconds = 301 },
		func(b *model.CapacityExecutorActivityBinding) { b.MaxTasks = 100001 },
		func(b *model.CapacityExecutorActivityBinding) { b.IdleAfterSeconds = 0 },
	} {
		changed := b
		mutate(&changed)
		p.ExecutorActivityBinding = &changed
		if ValidatePolicy(p) == nil {
			t.Fatal("unsafe activity binding accepted")
		}
	}
}
