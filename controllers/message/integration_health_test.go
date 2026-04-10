package message

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestIntegrationInstanceOverallStatus(t *testing.T) {
	tests := []struct {
		name          string
		declared      string
		checkKind     string
		runtimeStates []model.IntegrationRuntimeState
		want          string
	}{
		{
			name:      "disabled instance wins",
			declared:  "disabled",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			runtimeStates: []model.IntegrationRuntimeState{{
				Status: model.IntegrationRuntimeStatusHealthy,
			}},
			want: "disabled",
		},
		{
			name:      "draft instance wins",
			declared:  "draft",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			want:      "draft",
		},
		{
			name:      "active without runtime state is unknown",
			declared:  "active",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			want:      model.IntegrationInstanceHealthStatusUnknown,
		},
		{
			name:      "active mirrors single runtime state",
			declared:  "active",
			checkKind: model.IntegrationRuntimeCheckKindDescribeHandshake,
			runtimeStates: []model.IntegrationRuntimeState{{
				Status: model.IntegrationRuntimeStatusContractMismatch,
			}},
			want: model.IntegrationRuntimeStatusContractMismatch,
		},
		{
			name:      "overall stays unknown until both checks exist when healthy",
			declared:  "active",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			runtimeStates: []model.IntegrationRuntimeState{{
				CheckKind: model.IntegrationRuntimeCheckKindTransportConnectivity,
				Status:    model.IntegrationRuntimeStatusHealthy,
			}},
			want: model.IntegrationInstanceHealthStatusUnknown,
		},
		{
			name:      "overall returns unhealthy as soon as one check fails",
			declared:  "active",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			runtimeStates: []model.IntegrationRuntimeState{
				{
					CheckKind: model.IntegrationRuntimeCheckKindTransportConnectivity,
					Status:    model.IntegrationRuntimeStatusHealthy,
				},
				{
					CheckKind: model.IntegrationRuntimeCheckKindDescribeHandshake,
					Status:    model.IntegrationRuntimeStatusContractMismatch,
				},
			},
			want: model.IntegrationRuntimeStatusContractMismatch,
		},
		{
			name:      "overall is healthy when both checks are healthy",
			declared:  "active",
			checkKind: model.IntegrationRuntimeCheckKindOverall,
			runtimeStates: []model.IntegrationRuntimeState{
				{
					CheckKind: model.IntegrationRuntimeCheckKindTransportConnectivity,
					Status:    model.IntegrationRuntimeStatusHealthy,
				},
				{
					CheckKind: model.IntegrationRuntimeCheckKindDescribeHandshake,
					Status:    model.IntegrationRuntimeStatusHealthy,
				},
			},
			want: model.IntegrationRuntimeStatusHealthy,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := integrationInstanceOverallStatus(tc.declared, tc.checkKind, tc.runtimeStates); got != tc.want {
				t.Fatalf("integrationInstanceOverallStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestShouldFastFailIntegrationRuntimeState(t *testing.T) {
	now := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		state model.IntegrationRuntimeState
		want  bool
	}{
		{
			name: "healthy does not fast fail",
			state: model.IntegrationRuntimeState{
				Status:        model.IntegrationRuntimeStatusHealthy,
				LastCheckedAt: now.Add(-10 * time.Second),
			},
			want: false,
		},
		{
			name: "recent unreachable fast fails",
			state: model.IntegrationRuntimeState{
				Status:        model.IntegrationRuntimeStatusUnreachable,
				LastCheckedAt: now.Add(-10 * time.Second),
			},
			want: true,
		},
		{
			name: "stale unreachable does not fast fail",
			state: model.IntegrationRuntimeState{
				Status:        model.IntegrationRuntimeStatusUnreachable,
				LastCheckedAt: now.Add(-(integrationRuntimeFastFailWindow + time.Second)),
			},
			want: false,
		},
		{
			name: "recent contract mismatch fast fails",
			state: model.IntegrationRuntimeState{
				Status:        model.IntegrationRuntimeStatusContractMismatch,
				LastCheckedAt: now.Add(-time.Second),
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFastFailIntegrationRuntimeState(tc.state, now); got != tc.want {
				t.Fatalf("shouldFastFailIntegrationRuntimeState() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldFastFailIntegrationRuntimeStates(t *testing.T) {
	now := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	states := []model.IntegrationRuntimeState{
		{
			CheckKind:     model.IntegrationRuntimeCheckKindTransportConnectivity,
			Status:        model.IntegrationRuntimeStatusHealthy,
			LastCheckedAt: now.Add(-time.Second),
		},
		{
			CheckKind:     model.IntegrationRuntimeCheckKindDescribeHandshake,
			Status:        model.IntegrationRuntimeStatusUnreachable,
			LastCheckedAt: now.Add(-time.Second),
		},
	}

	if !shouldFastFailIntegrationRuntimeStates(states, now) {
		t.Fatal("expected overall runtime state list to fast fail when one recent check is unhealthy")
	}
}
