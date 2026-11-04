package message

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Only the plan operation may defer an incomplete reporting-membership proof
// (and only to try an already requested failed-installed disposal claim).
// Every other operation and every other refusal stays strict.
func TestOriginalGuestReconcilePlanCoverageDefersOnlyIncompleteReportingInPlan(t *testing.T) {
	incomplete := capacity.ErrOriginalGuestReportingIncomplete
	wrapped := fmt.Errorf("collect: %w", incomplete)
	if !originalGuestPlanCoverageMayDefer(capacity.PlanOriginalGuestOperation, incomplete) || !originalGuestPlanCoverageMayDefer(capacity.PlanOriginalGuestOperation, wrapped) {
		t.Fatal("plan step cannot reach a requested disposal claim without Guest reporting")
	}
	for _, c := range []struct {
		operation string
		err       error
	}{
		{capacity.CompleteOriginalGuestOperation, incomplete},
		{"", incomplete},
		{capacity.PlanOriginalGuestOperation, nil},
		{capacity.PlanOriginalGuestOperation, errOriginalGuestStep},
		{capacity.PlanOriginalGuestOperation, errors.New("complete original Guest reporting membership required")},
		{capacity.PlanOriginalGuestOperation, repository.ErrCapacityConflict},
	} {
		if originalGuestPlanCoverageMayDefer(c.operation, c.err) {
			t.Fatal("coverage exception widened beyond the plan step's incomplete reporting", c.operation, c.err)
		}
	}
}
