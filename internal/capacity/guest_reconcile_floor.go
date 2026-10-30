package capacity

import (
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidateOriginalGuestFloorBootstrap checks content only, not authority. The
// repository must also hold the current original lease, compiled source graph,
// native tuple/ledger and raw useful-canary joins in the SAME transaction.
// A first endpoint cannot supply Demand300 within its original completion
// budget. Complete Coverage30 may certify the protected floor without changing
// that missing demand; expansion and retirement keep ValidateAssessment.
func ValidateOriginalGuestFloorBootstrap(p model.CapacityPolicySpec, intent model.CapacityIntent, current model.CapacityAssessment, reporting model.CapacityMetricRangeObservation, now time.Time) error {
	refuse := fmt.Errorf("original zero-to-one protected floor required")
	if p.GuestNotifyReconcileBinding == nil || ValidateGuestNotifyReconcileBinding(p) != nil || ValidateSnapshot(p, current, now) != nil || intent.RecoveryOnly || intent.FloorDegraded || intent.Generation < 1 || intent.FencingToken < 1 || intent.LeaseOwner == "" || intent.LeaseExecutorID == "" || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.After(now) || intent.Decision.Reason != "protected_floor_recovery" || intent.Decision.Action != "expand" || !intent.Decision.ExecutionPermitted || intent.Decision.Units != 1 || current.Snapshot.Units != 1 || intent.Decision.Profile != current.Snapshot.Profile {
		return refuse
	}
	if intent.Phase != "preparing" && intent.Phase != "prepared" && intent.Phase != "canary" {
		return refuse
	}
	// Controller cadence age is not permission to reuse an old Coverage30
	// source response after waiting for a SQL lock during this completion.
	if !Fresh(reporting.SourceSampledAt, now, 15) || !Fresh(reporting.WindowEnd, now, 15) || !Fresh(reporting.EvaluatedAt, now, 15) {
		return refuse
	}
	baseline := intent.BaselineSnapshot
	if baseline.Units != 0 || baseline.ObservedAt.IsZero() || baseline.ResourceVersion == "" || baseline.WorkloadResourceVersion == "" || baseline.Profile != current.Snapshot.Profile {
		return refuse
	}
	for _, snapshot := range []model.CapacitySnapshot{baseline, intent.Assessment.Snapshot} {
		if snapshot.TargetIdentity != current.Snapshot.TargetIdentity || snapshot.Owner != current.Snapshot.Owner || snapshot.ResourceUID != current.Snapshot.ResourceUID || snapshot.WorkloadUID != current.Snapshot.WorkloadUID {
			return refuse
		}
	}
	return GuestReconcileMemberCoverage(p, reporting, 1, now)
}
