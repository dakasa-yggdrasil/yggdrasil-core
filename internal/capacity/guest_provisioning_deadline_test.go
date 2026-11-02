package capacity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestGuestOriginalProvisioningBudgetPrecedesCreateAndNeverDefaults(t *testing.T) {
	for _, name := range []string{"explicit_original_budget", "shorter_original_context_wins", "no_original_context_deadline", "canceled_original_context", "zero_budget", "negative_budget", "unbounded_budget", "missing_step_id", "foreign_step_id", "foreign_operation", "foreign_kind", "implicit_timeout", "shorter_step_timeout", "unbounded_step_timeout", "repeating_original", "foreach_original"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			profile := model.CapacityGuestProtectedProfileManifest{OriginalProvisioningBudgetSeconds: 20, OriginalProvisioningStepID: "original-provisioning"}
			step := model.WorkflowStepSpec{ID: profile.OriginalProvisioningStepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: ProvisionOriginalGuestOperation}, TimeoutSeconds: 40}
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(30*time.Second))
			defer cancel()
			want := now.Add(20 * time.Second)
			switch name {
			case "shorter_original_context_wins":
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), now.Add(10*time.Second))
				defer cancel()
				want = now.Add(10 * time.Second)
			case "no_original_context_deadline":
				ctx = context.Background()
			case "canceled_original_context":
				cancel()
			case "zero_budget":
				profile.OriginalProvisioningBudgetSeconds = 0
			case "negative_budget":
				profile.OriginalProvisioningBudgetSeconds = -1
			case "unbounded_budget":
				profile.OriginalProvisioningBudgetSeconds = 86401
			case "missing_step_id":
				profile.OriginalProvisioningStepID = ""
			case "foreign_step_id":
				step.ID = "foreign"
			case "foreign_operation":
				step.Use.Operation = "capacity.grant_mutation"
			case "foreign_kind":
				step.Use.Kind = "integration"
			case "implicit_timeout":
				step.TimeoutSeconds = 0
			case "shorter_step_timeout":
				step.TimeoutSeconds = 10
			case "unbounded_step_timeout":
				step.TimeoutSeconds = 86401
			case "repeating_original":
				step.Retry.MaxAttempts = 2
			case "foreach_original":
				step.ForEach = &model.WorkflowForEachSpec{}
			}
			deadline, err := GuestOriginalProvisioningDeadline(ctx, profile, step, now)
			valid := name == "explicit_original_budget" || name == "shorter_original_context_wins"
			if (err == nil) != valid || valid && !deadline.Equal(want) || !valid && !deadline.IsZero() {
				t.Fatal("missing/foreign/defaulted source budget or renewed original context acquired provisioning authority")
			}
		})
	}
}

func TestGuestOriginalProvisioningStoredBudgetCannotRenewAfterCreate(t *testing.T) {
	for _, name := range []string{"immutable_original_budget", "stored_shorter_context", "deadline_renewed", "deadline_reduced_without_original_context", "profile_changed_after_create", "workflow_changed_after_create", "missing_context", "missing_reservation", "missing_nonce", "foreign_original_request", "foreign_original_policy", "foreign_original_workflow", "foreign_source", "zero_original_fence", "zero_original_generation", "missing_original_executor"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Add(-time.Hour)
			profile := model.CapacityGuestProtectedProfileManifest{OriginalProvisioningBudgetSeconds: 20, OriginalProvisioningStepID: "original-provisioning"}
			r := model.CapacityGuestOriginalProvisioningPreregistration{Schema: "original_guest_provisioning_preregistration_v1", PreregistrationID: uuid.NewString(), OriginalCreateGrantID: uuid.NewString(), OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: strings.Repeat("b", 64), ProfileManifestSHA256: GuestRetirementSHA(profile), PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("c", 64), WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("d", 64), OriginalWorkflowStepID: profile.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 40, OriginalWorkflowContextDeadline: now.Add(30 * time.Second), CoreSourceCommit: strings.Repeat("e", 40), Generation: 1, Fence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), Slot: 2, OriginalDeadline: now.Add(20 * time.Second), ReservedAt: now}
			switch name {
			case "stored_shorter_context":
				r.OriginalWorkflowContextDeadline = now.Add(10 * time.Second)
				r.OriginalDeadline = r.OriginalWorkflowContextDeadline
			case "deadline_renewed":
				r.OriginalDeadline = time.Now().Add(time.Minute)
			case "deadline_reduced_without_original_context":
				r.OriginalDeadline = r.OriginalDeadline.Add(-time.Second)
			case "profile_changed_after_create":
				profile.OriginalProvisioningBudgetSeconds = 30
			case "workflow_changed_after_create":
				r.OriginalWorkflowStepID = "replacement"
			case "missing_context":
				r.OriginalWorkflowContextDeadline = time.Time{}
			case "missing_reservation":
				r.ReservedAt = time.Time{}
			case "missing_nonce":
				r.NonceSHA256 = ""
			case "foreign_original_request":
				r.OriginalCreateRequestSHA256 = "foreign"
			case "foreign_original_policy":
				r.PolicyChecksum = "foreign"
			case "foreign_original_workflow":
				r.WorkflowChecksum = "foreign"
			case "foreign_source":
				r.CoreSourceCommit = "foreign"
			case "zero_original_fence":
				r.Fence = 0
			case "zero_original_generation":
				r.Generation = 0
			case "missing_original_executor":
				r.ExecutorID = ""
			}
			if GuestOriginalProvisioningDeadlineMatches(r, profile) != (name == "immutable_original_budget" || name == "stored_shorter_context") {
				t.Fatal("historical source budget was renewed/adopted or original expiry erased its immutable readback")
			}
		})
	}
}

func TestGuestOriginalRetirementFirstDeadline(t *testing.T) {
	for _, name := range []string{"actor_thirty_seconds_precedes_long_source_and_lease", "shorter_original_context_is_literal", "shorter_current_lease_is_literal", "no_context_deadline", "canceled_original_context", "expired_current_lease", "missing_original_issued_at"} {
		t.Run(name, func(t *testing.T) {
			issued := time.Now().UTC()
			ctx, cancel := context.WithDeadline(t.Context(), issued.Add(600*time.Second))
			defer cancel()
			lease, want := issued.Add(300*time.Second), issued.Add(30*time.Second)
			switch name {
			case "shorter_original_context_is_literal":
				cancel()
				want = issued.Add(7*time.Second + 19*time.Nanosecond)
				ctx, cancel = context.WithDeadline(t.Context(), want)
				defer cancel()
			case "shorter_current_lease_is_literal":
				lease = issued.Add(11*time.Second + 29*time.Nanosecond)
				want = lease
			case "no_context_deadline":
				ctx = context.Background()
			case "canceled_original_context":
				cancel()
			case "expired_current_lease":
				lease = issued
			case "missing_original_issued_at":
				issued = time.Time{}
			}
			actual, err := GuestOriginalRetirementDeadline(ctx, issued, lease)
			valid := name == "actor_thirty_seconds_precedes_long_source_and_lease" || name == "shorter_original_context_is_literal" || name == "shorter_current_lease_is_literal"
			if (err == nil) != valid || (valid && !actual.Equal(want)) || (!valid && !actual.IsZero()) {
				t.Fatal("original actor/context/lease bound renewed, rounded or inferred", err)
			}
		})
	}
}
