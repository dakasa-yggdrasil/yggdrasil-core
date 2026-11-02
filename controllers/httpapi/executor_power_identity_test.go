package httpapi

import (
	"context"
	"testing"
)

func TestExecutorPowerOperatorIngressOnlyAuthenticatedHuman(t *testing.T) {
	ctx := context.Background()
	id := "11111111-1111-4111-8111-111111111111"
	if executorPowerOperatorContext(ctx, id, "", false, false) == ctx {
		t.Fatal("authenticated human not carried")
	}
	for _, tc := range []struct {
		id, machine        string
		hasMachine, legacy bool
	}{{}, {"forged", "", false, false}, {id, "service", false, false}, {id, "", true, false}, {id, "", false, true}, {"00000000-0000-0000-0000-000000000000", "", false, false}} {
		if executorPowerOperatorContext(ctx, tc.id, tc.machine, tc.hasMachine, tc.legacy) != ctx {
			t.Fatal("nonhuman or migration actor admitted")
		}
	}
}
